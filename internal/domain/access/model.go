package access

import (
	"slices"
	"time"
)

// Target kinds — which role system the grant lands in.
const (
	TargetConsole = "console" // role_id -> mxid_role, binding -> mxid_role_binding
	TargetApp     = "app"     // role_id -> mxid_app_role, binding -> mxid_app_role_binding
)

// Request lifecycle states.
const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusRejected  = "rejected"
	StatusCancelled = "cancelled"
	StatusExpired   = "expired"
	StatusRevoked   = "revoked"
)

// Binding row status (mxid_role_binding / mxid_app_role_binding .status).
const (
	BindingActive  = 1
	BindingExpired = 2
	BindingRevoked = 3
)

// Approver subject types.
const (
	ApproverRole  = "role"
	ApproverGroup = "group"
	ApproverUser  = "user"
	ApproverAuto  = "auto"
)

// IntSlice persists a JSONB int array (allowed_durations).
// GORM's built-in json serializer handles marshalling to/from the JSONB column.
// (No repo precedent for []int JSONB; json.RawMessage is used for opaque blobs
// and datatypes.JSON for arbitrary maps — neither fits a typed int slice, so
// serializer:json is the idiomatic GORM choice here.)
type IntSlice []int

// Eligibility: who may request which role, for how long, approved by whom.
type Eligibility struct {
	ID                   int64     `gorm:"column:id;primaryKey" json:"id,string"`
	TenantID             int64     `gorm:"column:tenant_id;not null;default:0" json:"tenant_id,string"`
	TargetKind           string    `gorm:"column:target_kind;size:16;not null" json:"target_kind"`
	RoleID               int64     `gorm:"column:role_id;not null" json:"role_id,string"`
	ScopeType            *string   `gorm:"column:scope_type;size:16" json:"scope_type,omitempty"`
	ScopeID              *int64    `gorm:"column:scope_id" json:"scope_id,omitempty,string"`
	AppID                *int64    `gorm:"column:app_id" json:"app_id,omitempty,string"`
	RequesterSubjectType string    `gorm:"column:requester_subject_type;size:16;not null" json:"requester_subject_type"`
	RequesterSubjectID   int64     `gorm:"column:requester_subject_id;not null;default:0" json:"requester_subject_id,string"`
	AllowedDurations     IntSlice  `gorm:"column:allowed_durations;serializer:json" json:"allowed_durations"`
	MaxDurationSeconds   int       `gorm:"column:max_duration_seconds;not null" json:"max_duration_seconds"`
	ApproverSubjectType  string    `gorm:"column:approver_subject_type;size:16;not null;default:role" json:"approver_subject_type"`
	ApproverSubjectID    int64     `gorm:"column:approver_subject_id;not null;default:0" json:"approver_subject_id,string"`
	// NOTE: no gorm "default:..." tag on these two booleans. GORM's Create()
	// treats a Go zero value (false) on a field that carries a "default" tag
	// as "not set" and omits the column from the INSERT, letting the DB's
	// column default (TRUE, per migration 000045) apply instead — silently
	// turning an explicit false into true. The desired default is already
	// computed in the service layer (boolOrDefault) before the struct reaches
	// the repository, so the struct tag's default is redundant and actively
	// harmful here. The DB column keeps its own DEFAULT TRUE for any INSERT
	// that bypasses the service (e.g. raw SQL / migrations backfill).
	RequireJustification bool      `gorm:"column:require_justification;not null" json:"require_justification"`
	RequireStepUp        bool      `gorm:"column:require_stepup;not null" json:"require_stepup"`
	Status               int       `gorm:"column:status;not null;default:1" json:"status"`
	CreatedAt            time.Time `gorm:"column:created_at;not null" json:"created_at"`
	CreatedBy            *int64    `gorm:"column:created_by" json:"created_by,omitempty,string"`
	UpdatedAt            time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (Eligibility) TableName() string { return "mxid_access_eligibility" }
func (Eligibility) TenantScoped()     {}

// DurationAllowed reports whether seconds is in the configured set.
func (e *Eligibility) DurationAllowed(seconds int) bool {
	return slices.Contains(e.AllowedDurations, seconds)
}

// ClampDuration caps seconds at MaxDurationSeconds.
func (e *Eligibility) ClampDuration(seconds int) int {
	if e.MaxDurationSeconds > 0 && seconds > e.MaxDurationSeconds {
		return e.MaxDurationSeconds
	}
	return seconds
}

// Request: one elevation ask + its lifecycle.
type Request struct {
	ID               int64      `gorm:"column:id;primaryKey" json:"id,string"`
	TenantID         int64      `gorm:"column:tenant_id;not null;default:0" json:"tenant_id,string"`
	RequesterID      int64      `gorm:"column:requester_id;not null" json:"requester_id,string"`
	EligibilityID    int64      `gorm:"column:eligibility_id;not null" json:"eligibility_id,string"`
	TargetKind       string     `gorm:"column:target_kind;size:16;not null" json:"target_kind"`
	RoleID           int64      `gorm:"column:role_id;not null" json:"role_id,string"`
	ScopeType        *string    `gorm:"column:scope_type;size:16" json:"scope_type,omitempty"`
	ScopeID          *int64     `gorm:"column:scope_id" json:"scope_id,omitempty,string"`
	AppID            *int64     `gorm:"column:app_id" json:"app_id,omitempty,string"`
	RequestedSeconds int        `gorm:"column:requested_seconds;not null" json:"requested_seconds"`
	Justification    string     `gorm:"column:justification" json:"justification"`
	Status           string     `gorm:"column:status;size:16;not null;default:pending" json:"status"`
	ApproverID       *int64     `gorm:"column:approver_id" json:"approver_id,omitempty,string"`
	DecidedAt        *time.Time `gorm:"column:decided_at" json:"decided_at,omitempty"`
	DecisionReason   string     `gorm:"column:decision_reason" json:"decision_reason"`
	ActivatedAt      *time.Time `gorm:"column:activated_at" json:"activated_at,omitempty"`
	ExpiresAt        *time.Time `gorm:"column:expires_at" json:"expires_at,omitempty"`
	BindingID        *int64     `gorm:"column:binding_id" json:"binding_id,omitempty,string"`
	CreatedAt        time.Time  `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"column:updated_at;not null" json:"updated_at"`

	// RequesterName is the requester's display_name (falling back to
	// username), populated only by ListRequestsByStatus (console approvals
	// list) via a lookup against mxid_user. It is not a real column — fully
	// ignored by GORM (gorm:"-") so every other Request query path (CreateRequest,
	// GetRequest, ListRequestsByRequester, ListDueGrants, ...) is unaffected.
	RequesterName string `gorm:"-" json:"requester_name,omitempty"`
}

func (Request) TableName() string { return "mxid_access_request" }
func (Request) TenantScoped()     {}

// ---- DTOs ----

type CreateEligibilityRequest struct {
	TargetKind           string  `json:"target_kind" binding:"required"`
	RoleID               int64   `json:"role_id,string" binding:"required"`
	ScopeType            *string `json:"scope_type"`
	ScopeID              *int64  `json:"scope_id,string"`
	AppID                *int64  `json:"app_id,string"`
	RequesterSubjectType string  `json:"requester_subject_type" binding:"required"`
	RequesterSubjectID   int64   `json:"requester_subject_id,string"`
	AllowedDurations     []int   `json:"allowed_durations" binding:"required"`
	MaxDurationSeconds   int     `json:"max_duration_seconds" binding:"required"`
	ApproverSubjectType  string  `json:"approver_subject_type"`
	ApproverSubjectID    int64   `json:"approver_subject_id,string"`
	RequireJustification *bool   `json:"require_justification"`
	RequireStepUp        *bool   `json:"require_stepup"`
}

type CreateAccessRequest struct {
	EligibilityID    int64  `json:"eligibility_id,string" binding:"required"`
	RequestedSeconds int    `json:"requested_seconds" binding:"required"`
	Justification    string `json:"justification"`
}

type DecisionRequest struct {
	Reason string `json:"reason"`
}
