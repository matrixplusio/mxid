// Package approle implements the IdP-side app role mapping layer.
//
// Industry-grade IAMs (Okta, Keycloak, Auth0) centralize SP role
// assignment instead of pushing JMESPath per-SP config. This module
// gives MXID the same model:
//
//   - Admin defines roles per app (Admin / Editor / Viewer / custom)
//   - Admin binds users/groups/orgs/system-roles → app roles
//   - At /token time MXID emits `app_roles: ["admin"]` claim
//   - SP reads claim verbatim (no JMESPath needed)
//
// Default role: if no binding matches, the app_role with is_default=true
// is emitted. Lets admin say "everyone defaults to Viewer" without
// having to add a public binding row.
//
// Multiple matches: token's app_roles[] is the union of all matched
// role codes (sorted by app_role.sort_order asc).
package approle

import "time"

// Subject types — same vocabulary as appaccess.
const (
	SubjectUser  = "user"
	SubjectGroup = "group"
	SubjectOrg   = "org"
	SubjectRole  = "role"
)

// AppRole is one role within an app OR app-group. CHECK constraint
// guarantees exactly one of AppID / AppGroupID is set.
type AppRole struct {
	ID          int64     `gorm:"column:id;primaryKey" json:"id,string"`
	AppID       *int64    `gorm:"column:app_id" json:"app_id,omitempty,string"`
	AppGroupID  *int64    `gorm:"column:app_group_id" json:"app_group_id,omitempty,string"`
	TenantID    int64     `gorm:"column:tenant_id;not null;default:0" json:"tenant_id,string"`
	Code        string    `gorm:"column:code;size:64;not null" json:"code"`
	Name        string    `gorm:"column:name;size:128;not null" json:"name"`
	Description *string   `gorm:"column:description" json:"description,omitempty"`
	IsDefault   bool      `gorm:"column:is_default;not null;default:false" json:"is_default"`
	SortOrder   int       `gorm:"column:sort_order;not null;default:0" json:"sort_order"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
	CreatedBy   *int64    `gorm:"column:created_by" json:"created_by,string,omitempty"`
}

func (AppRole) TableName() string { return "mxid_app_role" }

// TenantScoped marks mxid_app_role for automatic tenant isolation.
func (AppRole) TenantScoped() {}

// Binding glues a subject (user/group/org/system-role) to an app_role.
// Same exactly-one-of (app_id, app_group_id) invariant as AppRole.
type Binding struct {
	ID          int64      `gorm:"column:id;primaryKey" json:"id,string"`
	AppID       *int64     `gorm:"column:app_id" json:"app_id,omitempty,string"`
	AppGroupID  *int64     `gorm:"column:app_group_id" json:"app_group_id,omitempty,string"`
	TenantID    int64      `gorm:"column:tenant_id;not null;default:0" json:"tenant_id,string"`
	AppRoleID   int64      `gorm:"column:app_role_id;not null" json:"app_role_id,string"`
	SubjectType string     `gorm:"column:subject_type;size:16;not null" json:"subject_type"`
	SubjectID   int64      `gorm:"column:subject_id;not null" json:"subject_id,string"`
	// Time-bound JIT fields (added by migration 000045). NULL ExpiresAt = permanent.
	// Status: 1=active, 2=expired, 3=revoked. Default 1 (permanent bindings unaffected).
	GrantID     *int64     `gorm:"column:grant_id" json:"grant_id,omitempty,string"`
	ExpiresAt   *time.Time `gorm:"column:expires_at" json:"expires_at,omitempty"`
	Status      int16      `gorm:"column:status;not null;default:1" json:"status"`
	CreatedAt   time.Time  `gorm:"column:created_at;not null" json:"created_at"`
	CreatedBy   *int64     `gorm:"column:created_by" json:"created_by,string,omitempty"`
}

func (Binding) TableName() string { return "mxid_app_role_binding" }

// TenantScoped marks mxid_app_role_binding for automatic tenant isolation.
func (Binding) TenantScoped() {}

// BindingView enriches Binding with display name+code of the subject
// AND the bound role, for console rendering without N+1 lookups.
type BindingView struct {
	*Binding
	RoleCode    string `json:"role_code"`
	RoleName    string `json:"role_name"`
	SubjectName string `json:"subject_name,omitempty"`
	SubjectCode string `json:"subject_code,omitempty"`
}
