package dashboard

import (
	"context"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"gorm.io/gorm"
)

// Service builds the dashboard Overview by aggregating the audit log and a
// handful of entity tables. It is a read-only reporting module: it reads
// across domain tables directly (by table name) rather than going through
// each domain repo, which is the conventional trade-off for analytics code —
// it keeps the hot aggregation path in one place without a fan-out of
// cross-domain service calls.
type Service struct {
	db *gorm.DB
	// sessionCounter returns the count of live sessions. Injected from main
	// (backed by the redis session manager) because session state lives in
	// redis, not the DB. nil → ActiveSessions reported as 0.
	sessionCounter func(ctx context.Context) int64
}

// NewService creates a dashboard service over the given DB handle.
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// SetSessionCounter wires the live-session count source.
func (s *Service) SetSessionCounter(fn func(ctx context.Context) int64) {
	s.sessionCounter = fn
}

// Overview aggregates every dashboard metric for one tenant over the given
// range window (in days). A single call issues several small grouped queries
// — cheap against the indexed audit log, and the page caches the result.
func (s *Service) Overview(ctx context.Context, tenantID int64, rangeDays int) (*Overview, error) {
	if rangeDays <= 0 {
		rangeDays = 7
	}
	now := time.Now()
	rangeStart := now.AddDate(0, 0, -rangeDays)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	ov := &Overview{RangeDays: rangeDays, GeneratedAt: now}

	if err := s.fillCounts(ctx, tenantID, rangeStart, &ov.Counts); err != nil {
		return nil, err
	}
	if err := s.fillAuth(ctx, tenantID, rangeStart, todayStart, now, &ov.Auth); err != nil {
		return nil, err
	}
	trend, err := s.loginTrend(ctx, tenantID, rangeDays)
	if err != nil {
		return nil, err
	}
	ov.LoginTrend = trend

	if ov.AuthMethods, err = s.distribution(ctx, tenantID, rangeStart,
		"COALESCE(detail->>'auth_type','unknown')", event.LoginSuccess, 8); err != nil {
		return nil, err
	}
	if ov.GeoTop, err = s.distribution(ctx, tenantID, rangeStart,
		"COALESCE(geo_country,'unknown')", event.LoginSuccess, 8); err != nil {
		return nil, err
	}
	if ov.TopApps, err = s.topApps(ctx, tenantID, rangeStart); err != nil {
		return nil, err
	}
	if err := s.fillSecurity(ctx, tenantID, rangeStart, &ov.Security); err != nil {
		return nil, err
	}
	return ov, nil
}

func (s *Service) fillCounts(ctx context.Context, tenantID int64, rangeStart time.Time, c *Counts) error {
	db := s.db.WithContext(ctx)

	if err := db.Table("mxid_user").Where("tenant_id = ?", tenantID).Count(&c.Users).Error; err != nil {
		return err
	}
	if err := db.Table("mxid_user").Where("tenant_id = ? AND status = ?", tenantID, statusActive).Count(&c.UsersActive).Error; err != nil {
		return err
	}
	if err := db.Table("mxid_user").Where("tenant_id = ? AND created_at >= ?", tenantID, rangeStart).Count(&c.NewUsers).Error; err != nil {
		return err
	}
	// Apps: tenant-owned OR shared (tenant_id IS NULL is visible everywhere).
	if err := db.Table("mxid_app").Where("tenant_id = ? OR tenant_id IS NULL", tenantID).Count(&c.Apps).Error; err != nil {
		return err
	}
	if err := db.Table("mxid_app").
		Select("protocol AS name, count(*) AS value").
		Where("tenant_id = ? OR tenant_id IS NULL", tenantID).
		Group("protocol").Order("value DESC").
		Scan(&c.AppsByProtocol).Error; err != nil {
		return err
	}
	if err := db.Table("mxid_organization").Where("tenant_id = ?", tenantID).Count(&c.Orgs).Error; err != nil {
		return err
	}
	if err := db.Table("mxid_user_group").Where("tenant_id = ?", tenantID).Count(&c.Groups).Error; err != nil {
		return err
	}
	if err := db.Table("mxid_external_idp").Where("tenant_id = ?", tenantID).Count(&c.IdentitySources).Error; err != nil {
		return err
	}
	// MFA-enrolled = distinct users in this tenant with a verified factor.
	if err := db.Table("mxid_user_mfa AS m").
		Joins("JOIN mxid_user u ON u.id = m.user_id").
		Where("u.tenant_id = ? AND m.verified = true", tenantID).
		Distinct("m.user_id").Count(&c.MFAEnrolled).Error; err != nil {
		return err
	}
	if c.UsersActive > 0 {
		c.MFACoverage = float64(c.MFAEnrolled) / float64(c.UsersActive)
	}
	if s.sessionCounter != nil {
		c.ActiveSessions = s.sessionCounter(ctx)
	}
	return nil
}

func (s *Service) fillAuth(ctx context.Context, tenantID int64, rangeStart, todayStart, now time.Time, a *AuthHealth) error {
	db := s.db.WithContext(ctx)
	tbl := func() *gorm.DB { return db.Table("mxid_audit_log").Where("tenant_id = ?", tenantID) }

	if err := tbl().Where("event_type = ? AND created_at >= ?", event.LoginSuccess, todayStart).Count(&a.TodayLogins).Error; err != nil {
		return err
	}
	if err := tbl().Where("event_type = ? AND created_at >= ?", event.LoginSuccess, rangeStart).Count(&a.LoginSuccess).Error; err != nil {
		return err
	}
	if err := tbl().Where("event_type = ? AND created_at >= ?", event.LoginFailed, rangeStart).Count(&a.LoginFailed).Error; err != nil {
		return err
	}
	if total := a.LoginSuccess + a.LoginFailed; total > 0 {
		a.SuccessRate = float64(a.LoginSuccess) / float64(total)
	}
	// Distinct active users (successful login) across the three standard windows.
	a.DAU = s.distinctActors(ctx, tenantID, todayStart)
	a.WAU = s.distinctActors(ctx, tenantID, now.AddDate(0, 0, -7))
	a.MAU = s.distinctActors(ctx, tenantID, now.AddDate(0, 0, -30))
	return nil
}

func (s *Service) distinctActors(ctx context.Context, tenantID int64, since time.Time) int64 {
	var n int64
	s.db.WithContext(ctx).Table("mxid_audit_log").
		Where("tenant_id = ? AND event_type = ? AND created_at >= ? AND actor_id IS NOT NULL",
			tenantID, event.LoginSuccess, since).
		Distinct("actor_id").Count(&n)
	return n
}

func (s *Service) loginTrend(ctx context.Context, tenantID int64, rangeDays int) ([]TrendPoint, error) {
	type row struct {
		Date    string `gorm:"column:date"`
		Success int64  `gorm:"column:success"`
		Failed  int64  `gorm:"column:failed"`
	}
	var rows []row
	since := time.Now().AddDate(0, 0, -int(rangeDays))
	err := s.db.WithContext(ctx).Table("mxid_audit_log").
		Select(`to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS date,
			count(*) FILTER (WHERE event_type = ?) AS success,
			count(*) FILTER (WHERE event_type = ?) AS failed`,
			event.LoginSuccess, event.LoginFailed).
		Where("tenant_id = ? AND event_type IN ? AND created_at >= ?",
			tenantID, []string{event.LoginSuccess, event.LoginFailed}, since).
		Group("date").Order("date").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	// Fill gaps so the line is continuous across the whole window.
	byDate := make(map[string]row, len(rows))
	for _, r := range rows {
		byDate[r.Date] = r
	}
	out := make([]TrendPoint, 0, rangeDays)
	for i := int(rangeDays) - 1; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		r := byDate[d]
		out = append(out, TrendPoint{Date: d, Success: r.Success, Failed: r.Failed})
	}
	return out, nil
}

// distribution groups successful logins by an arbitrary SQL expression
// (auth_type, geo_country, …) into the top-N label/count pairs.
func (s *Service) distribution(ctx context.Context, tenantID int64, rangeStart time.Time, expr, eventType string, limit int) ([]NameValue, error) {
	var out []NameValue
	err := s.db.WithContext(ctx).Table("mxid_audit_log").
		Select(expr+" AS name, count(*) AS value").
		Where("tenant_id = ? AND event_type = ? AND created_at >= ?", tenantID, eventType, rangeStart).
		Group("name").Order("value DESC").Limit(limit).Scan(&out).Error
	return out, err
}

func (s *Service) topApps(ctx context.Context, tenantID int64, rangeStart time.Time) ([]NameValue, error) {
	type row struct {
		ResourceID int64 `gorm:"column:resource_id"`
		Value      int64 `gorm:"column:value"`
	}
	var rows []row
	err := s.db.WithContext(ctx).Table("mxid_audit_log").
		Select("resource_id, count(*) AS value").
		Where("tenant_id = ? AND event_type = ? AND created_at >= ? AND resource_id IS NOT NULL",
			tenantID, event.AppLaunched, rangeStart).
		Group("resource_id").Order("value DESC").Limit(8).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []NameValue{}, nil
	}
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ResourceID
	}
	// Resolve app names in one query; fall back to the id for deleted apps.
	type nameRow struct {
		ID   int64  `gorm:"column:id"`
		Name string `gorm:"column:name"`
	}
	var names []nameRow
	if err := s.db.WithContext(ctx).Table("mxid_app").Select("id, name").Where("id IN ?", ids).Scan(&names).Error; err != nil {
		return nil, err
	}
	nameByID := make(map[int64]string, len(names))
	for _, n := range names {
		nameByID[n.ID] = n.Name
	}
	out := make([]NameValue, 0, len(rows))
	for _, r := range rows {
		label := nameByID[r.ResourceID]
		if label == "" {
			label = "#" + itoa(r.ResourceID)
		}
		out = append(out, NameValue{Name: label, Value: r.Value})
	}
	return out, nil
}

// AuditExportRow is a flat projection of an audit row for CSV export.
type AuditExportRow struct {
	CreatedAt    time.Time `gorm:"column:created_at"`
	EventType    string    `gorm:"column:event_type"`
	EventStatus  int       `gorm:"column:event_status"`
	ActorName    *string   `gorm:"column:actor_name"`
	ResourceType *string   `gorm:"column:resource_type"`
	ResourceID   *int64    `gorm:"column:resource_id"`
	IP           *string   `gorm:"column:ip"`
	GeoCountry   *string   `gorm:"column:geo_country"`
}

// ExportAudit returns the tenant's audit rows since `since`, newest first,
// capped to keep a single CSV download bounded.
func (s *Service) ExportAudit(ctx context.Context, tenantID int64, since time.Time) ([]AuditExportRow, error) {
	var rows []AuditExportRow
	err := s.db.WithContext(ctx).Table("mxid_audit_log").
		Select("created_at, event_type, event_status, actor_name, resource_type, resource_id, ip, geo_country").
		Where("tenant_id = ? AND created_at >= ?", tenantID, since).
		Order("created_at DESC").Limit(50000).Scan(&rows).Error
	return rows, err
}

func (s *Service) fillSecurity(ctx context.Context, tenantID int64, rangeStart time.Time, p *SecurityPanel) error {
	db := s.db.WithContext(ctx)
	count := func(eventType string, dst *int64) error {
		return db.Table("mxid_audit_log").
			Where("tenant_id = ? AND event_type = ? AND created_at >= ?", tenantID, eventType, rangeStart).
			Count(dst).Error
	}
	if err := count(event.LoginRisk, &p.RiskEvents); err != nil {
		return err
	}
	if err := count(event.UserLocked, &p.LockedUsers); err != nil {
		return err
	}
	if err := count(event.OIDCTokenReuse, &p.TokenReuse); err != nil {
		return err
	}
	if err := count(event.UserSuperAdminGrant, &p.SuperAdminGrants); err != nil {
		return err
	}
	if err := count(event.UserPIIView, &p.PIIViews); err != nil {
		return err
	}

	secTypes := []string{event.LoginRisk, event.UserLocked, event.OIDCTokenReuse, event.UserSuperAdminGrant, event.UserPIIView}
	type row struct {
		CreatedAt time.Time `gorm:"column:created_at"`
		EventType string    `gorm:"column:event_type"`
		ActorName *string   `gorm:"column:actor_name"`
		IP        *string   `gorm:"column:ip"`
	}
	var rows []row
	if err := db.Table("mxid_audit_log").
		Select("created_at, event_type, actor_name, ip").
		Where("tenant_id = ? AND event_type IN ? AND created_at >= ?", tenantID, secTypes, rangeStart).
		Order("created_at DESC").Limit(10).Scan(&rows).Error; err != nil {
		return err
	}
	p.Recent = make([]SecurityEvent, 0, len(rows))
	for _, r := range rows {
		p.Recent = append(p.Recent, SecurityEvent{
			Time:      r.CreatedAt,
			EventType: r.EventType,
			Actor:     deref(r.ActorName),
			IP:        deref(r.IP),
		})
	}
	return nil
}
