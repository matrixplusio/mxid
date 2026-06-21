package audit

import (
	"context"
	"time"
)

// ListParams holds the parsed filter criteria for listing audit logs.
//
// EventType filters by exact match; EventTypes (mutually exclusive with
// EventType in practice — if both set, EventTypes wins) filters by SQL IN.
// EventTypes lets the /security/login-history endpoint pull the union of
// login.success / login.failed / logout in a single query.
type ListParams struct {
	TenantID     int64
	Page         int
	PageSize     int
	EventType    string
	EventTypes   []string
	ActorID      *int64
	ResourceType string
	StartTime    *time.Time
	EndTime      *time.Time
	// HideAPI excludes the generic api.* catch-all rows (the safety-net entries
	// RecordAPIRequest writes for every non-GET request). They duplicate the
	// richer domain events for any route that emits one, so the console hides
	// them by default and only shows them when investigating a route that emits
	// no domain event.
	HideAPI bool
}

// Repository defines the data access interface for audit logs.
type Repository interface {
	// Create inserts a new audit log entry.
	Create(ctx context.Context, log *AuditLog) error

	// List returns a paginated, filtered list of audit logs.
	List(ctx context.Context, params ListParams) ([]*AuditLog, int64, error)

	// GetStats returns aggregate statistics for a time range.
	GetStats(ctx context.Context, tenantID int64, start, end time.Time) (*AuditStatsResponse, error)

	// PurgeOlderThan deletes audit log rows whose created_at is strictly
	// before the given cutoff. Returns the rows deleted. Called from the
	// retention cron; safe to invoke repeatedly (idempotent).
	PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}
