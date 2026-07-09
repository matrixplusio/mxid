package app

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/conditionalaccess"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/geoip"
)

// loginHistoryAdapter reads recent successful logins from mxid_login_record so
// the conditional-access signal computer can derive new-country / impossible-
// travel signals.
type loginHistoryAdapter struct{ db *gorm.DB }

func (l loginHistoryAdapter) RecentSuccessful(ctx context.Context, userID int64, limit int) ([]conditionalaccess.LoginEvent, error) {
	var rows []struct {
		IP        *string   `gorm:"column:ip"`
		CreatedAt time.Time `gorm:"column:created_at"`
	}
	err := l.db.WithContext(ctx).
		Table("mxid_login_record").
		Select("ip, created_at").
		Where("user_id = ? AND success = ?", userID, true).
		Order("created_at DESC").
		Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	events := make([]conditionalaccess.LoginEvent, 0, len(rows))
	for _, r := range rows {
		ip := ""
		if r.IP != nil {
			ip = *r.IP
		}
		events = append(events, conditionalaccess.LoginEvent{IP: ip, At: r.CreatedAt})
	}
	return events, nil
}

// caRiskLogger records the A3 fallback — a risky login allowed through because
// the user has no second factor to challenge. Publishes a login.risk event the
// audit pipeline persists (so it's queryable in the console), and logs at WARN
// for live operability.
type caRiskLogger struct {
	logger *zap.Logger
	bus    *event.Bus
}

func (l caRiskLogger) Risk(ctx context.Context, userID, tenantID int64, ip string, reasons []string) {
	l.logger.Warn("conditional-access risk: login allowed without a second factor",
		zap.Int64("user_id", userID),
		zap.Int64("tenant_id", tenantID),
		zap.String("ip", ip),
		zap.Strings("reasons", reasons))
	if l.bus != nil {
		l.bus.Publish(ctx, event.Event{
			Type: event.LoginRisk,
			Payload: map[string]any{
				"user_id":   userID,
				"tenant_id": tenantID,
				"ip":        ip,
				"reasons":   reasons,
			},
		})
	}
}

// buildConditionalAccess wires the adaptive-authentication service from app
// dependencies. The returned service is inert until the tenant's
// security.conditional_access policy is enabled.
func buildConditionalAccess(a *bootstrap.App, settings *setting.Service, geo geoip.Resolver) *conditionalaccess.Service {
	deviceSvc := conditionalaccess.NewDeviceService(conditionalaccess.NewGormDeviceRepo(a.DB), a.IDGen)
	computer := conditionalaccess.NewSignalComputer(geo, loginHistoryAdapter{db: a.DB}, deviceSvc)

	cfg := func(ctx context.Context, tenantID int64) conditionalaccess.RuntimeConfig {
		c, err := settings.ConditionalAccess(ctx, tenantID)
		if err != nil {
			c = setting.DefaultConditionalAccess()
		}
		return conditionalaccess.RuntimeConfig{
			Policy: conditionalaccess.Policy{
				Enabled:            c.Enabled,
				OnNewCountry:       c.OnNewCountry,
				OnImpossibleTravel: c.OnImpossibleTravel,
				OnNewDevice:        c.OnNewDevice,
			},
			TravelWindow: time.Duration(c.ImpossibleTravelWindowMinutes) * time.Minute,
		}
	}

	return conditionalaccess.NewService(cfg, computer, deviceSvc, caRiskLogger{logger: a.Logger, bus: a.EventBus})
}
