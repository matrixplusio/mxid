package audit

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// gormRepository implements Repository using GORM.
type gormRepository struct {
	db *gorm.DB
}

// NewGormRepository creates a new GORM-based audit repository.
func NewGormRepository(db *gorm.DB) Repository {
	return &gormRepository{db: db}
}

// Create inserts a new audit log entry.
func (r *gormRepository) Create(ctx context.Context, log *AuditLog) error {
	if err := r.db.WithContext(ctx).Create(log).Error; err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}
	return nil
}

// PurgeOlderThan deletes audit log rows older than cutoff. Returns the row
// count. Cron-driven; safe to run on a hot table because the WHERE matches
// the primary key index range tail.
func (r *gormRepository) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("created_at < ?", cutoff).
		Delete(&AuditLog{})
	if res.Error != nil {
		return 0, fmt.Errorf("purge audit logs: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// List returns a paginated list of audit logs with filters.
func (r *gormRepository) List(ctx context.Context, params ListParams) ([]*AuditLog, int64, error) {
	var logs []*AuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&AuditLog{}).Where("tenant_id = ?", params.TenantID)

	query = query.Scopes(
		eventTypeScope(params.EventType),
		eventTypesScope(params.EventTypes),
		actorIDScope(params.ActorID),
		resourceTypeScope(params.ResourceType),
		timeRangeScope(params.StartTime, params.EndTime),
		hideAPIScope(params.HideAPI),
	)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	offset := (params.Page - 1) * params.PageSize
	if err := query.Offset(offset).Limit(params.PageSize).Order("created_at DESC").Find(&logs).Error; err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}

	return logs, total, nil
}

// GetStats returns aggregate statistics for a given time range.
func (r *gormRepository) GetStats(ctx context.Context, tenantID int64, start, end time.Time) (*AuditStatsResponse, error) {
	stats := &AuditStatsResponse{}

	base := r.db.WithContext(ctx).Model(&AuditLog{}).
		Where("tenant_id = ? AND created_at >= ? AND created_at <= ?", tenantID, start, end)

	// Total events
	if err := base.Count(&stats.TotalEvents).Error; err != nil {
		return nil, fmt.Errorf("count total events: %w", err)
	}

	// Login count (successful)
	if err := r.db.WithContext(ctx).Model(&AuditLog{}).
		Where("tenant_id = ? AND created_at >= ? AND created_at <= ? AND event_type = ? AND event_status = ?",
			tenantID, start, end, "login.success", EventStatusSuccess).
		Count(&stats.LoginCount).Error; err != nil {
		return nil, fmt.Errorf("count logins: %w", err)
	}

	// Failed login count
	if err := r.db.WithContext(ctx).Model(&AuditLog{}).
		Where("tenant_id = ? AND created_at >= ? AND created_at <= ? AND event_type = ?",
			tenantID, start, end, "login.failed").
		Count(&stats.FailedLoginCount).Error; err != nil {
		return nil, fmt.Errorf("count failed logins: %w", err)
	}

	// Active users (distinct actor_id with successful login today)
	var activeCount int64
	err := r.db.WithContext(ctx).Model(&AuditLog{}).
		Where("tenant_id = ? AND created_at >= ? AND created_at <= ? AND event_type = ? AND actor_id IS NOT NULL",
			tenantID, start, end, "login.success").
		Distinct("actor_id").
		Count(&activeCount).Error
	if err != nil {
		return nil, fmt.Errorf("count active users: %w", err)
	}
	stats.ActiveUsers = activeCount

	return stats, nil
}

// eventTypeScope filters by event type.
func eventTypeScope(eventType string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if eventType == "" {
			return db
		}
		return db.Where("event_type = ?", eventType)
	}
}

// eventTypesScope filters by a set of event types using SQL IN.
func eventTypesScope(types []string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if len(types) == 0 {
			return db
		}
		return db.Where("event_type IN ?", types)
	}
}

// hideAPIScope excludes the generic api.* catch-all rows when enabled. Uses a
// prefix match so only the safety-net middleware rows (api.put/api.post/…) are
// dropped, leaving every domain event intact.
func hideAPIScope(hide bool) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if !hide {
			return db
		}
		return db.Where("event_type NOT LIKE ?", "api.%")
	}
}

// actorIDScope filters by actor ID.
func actorIDScope(actorID *int64) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if actorID == nil {
			return db
		}
		return db.Where("actor_id = ?", *actorID)
	}
}

// resourceTypeScope filters by resource type.
func resourceTypeScope(resourceType string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if resourceType == "" {
			return db
		}
		return db.Where("resource_type = ?", resourceType)
	}
}

// timeRangeScope filters by a time range.
func timeRangeScope(start, end *time.Time) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if start != nil {
			db = db.Where("created_at >= ?", *start)
		}
		if end != nil {
			db = db.Where("created_at <= ?", *end)
		}
		return db
	}
}
