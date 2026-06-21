package audit

import "time"

// AuditLogResponse is the API representation of an audit log entry.
//
// All int64 ID fields are JSON-serialized as strings (Twitter/Discord
// snowflake convention) to preserve precision past 2^53.
type AuditLogResponse struct {
	ID           int64          `json:"id,string"`
	TenantID     int64          `json:"tenant_id,string"`
	ActorID      *int64         `json:"actor_id,string,omitempty"`
	ActorName    *string        `json:"actor_name"`
	ActorType    string         `json:"actor_type"`
	EventType    string         `json:"event_type"`
	EventStatus  int            `json:"event_status"`
	ResourceType *string        `json:"resource_type"`
	ResourceID   *int64         `json:"resource_id,string,omitempty"`
	ResourceName *string        `json:"resource_name"`
	Detail       map[string]any `json:"detail"`
	IP           *string        `json:"ip"`
	UserAgent    *string        `json:"user_agent"`
	GeoCity      *string        `json:"geo_city"`
	GeoCountry   *string        `json:"geo_country"`
	SessionID    *string        `json:"session_id"`
	CreatedAt    time.Time      `json:"created_at"`
}

// ListAuditRequest holds query parameters for listing audit logs.
type ListAuditRequest struct {
	Page         int    `form:"page"`
	PageSize     int    `form:"page_size"`
	EventType    string `form:"event_type"`
	ActorID      *int64 `form:"actor_id"`
	ResourceType string `form:"resource_type"`
	StartTime    string `form:"start_time"`
	EndTime      string `form:"end_time"`
	// HideAPI drops the generic api.* catch-all rows from the result. Default
	// false to preserve the full trail for API clients; the console sets it.
	HideAPI bool `form:"hide_api"`
}

// AuditStatsResponse contains aggregate statistics for audit logs.
type AuditStatsResponse struct {
	TotalEvents      int64 `json:"total_events"`
	LoginCount       int64 `json:"login_count"`
	FailedLoginCount int64 `json:"failed_login_count"`
	ActiveUsers      int64 `json:"active_users"`
}
