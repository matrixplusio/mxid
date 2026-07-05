package permission

import (
	"time"

	"gorm.io/gorm"
)

// Role type constants.
const (
	RoleTypeSystem = 1
	RoleTypeCustom = 2
)

// Role represents the mxid_role table.
type Role struct {
	ID          int64          `gorm:"column:id;primaryKey" json:"id"`
	TenantID    int64          `gorm:"column:tenant_id;not null" json:"tenant_id"`
	Name        string         `gorm:"column:name;not null;size:128" json:"name"`
	Code        string         `gorm:"column:code;not null;size:64" json:"code"`
	Type        int            `gorm:"column:type;not null;default:1" json:"type"`
	Description *string        `gorm:"column:description" json:"description"`
	CreatedAt   time.Time      `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"column:updated_at;not null" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the table name for Role.
func (Role) TableName() string {
	return "mxid_role"
}

// AuditResource implements audit.Audited.
func (Role) AuditResource() string {
	return "role"
}

// TenantScoped marks mxid_role for automatic tenant isolation.
func (Role) TenantScoped() {}

// Scope type constants for role bindings. Empty / NULL ScopeType means
// the binding is global (admin-wide). Org bindings apply to the full ltree
// subtree of the scope_id.
const (
	ScopeTypeGlobal = ""
	ScopeTypeOrg    = "org"
	ScopeTypeGroup  = "group"
)

// Subject type constants for role bindings — the kind of principal a binding
// grants the role to. Mirror the DTO oneof validation (user|group|org).
const (
	SubjectTypeUser  = "user"
	SubjectTypeGroup = "group"
	SubjectTypeOrg   = "org"
)

// RoleBinding represents the mxid_role_binding table.
//
// A binding pairs a role with a subject (user / group / org) and optionally
// constrains the role's effective area to a scope_id (an org or a group).
// Same (role, subject) can be bound multiple times with different scopes
// — the resulting permission set is the union.
type RoleBinding struct {
	ID          int64     `gorm:"column:id;primaryKey" json:"id,string"`
	RoleID      int64     `gorm:"column:role_id;not null" json:"role_id,string"`
	SubjectType string    `gorm:"column:subject_type;not null;size:16" json:"subject_type"`
	SubjectID   int64     `gorm:"column:subject_id;not null" json:"subject_id,string"`
	ScopeType   *string   `gorm:"column:scope_type;size:16" json:"scope_type,omitempty"`
	ScopeID     *int64    `gorm:"column:scope_id" json:"scope_id,string,omitempty"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the table name for RoleBinding.
func (RoleBinding) TableName() string {
	return "mxid_role_binding"
}

// AuditResource implements audit.Audited.
func (RoleBinding) AuditResource() string {
	return "role_binding"
}

// Permission represents the mxid_permission table.
type Permission struct {
	ID          int64     `gorm:"column:id;primaryKey" json:"id,string"`
	TenantID    int64     `gorm:"column:tenant_id;not null" json:"tenant_id,string"`
	Name        string    `gorm:"column:name;not null;size:128" json:"name"`
	Code        string    `gorm:"column:code;not null;size:128" json:"code"`
	Resource    string    `gorm:"column:resource;not null;size:128" json:"resource"`
	Action      string    `gorm:"column:action;not null;size:32" json:"action"`
	Description *string   `gorm:"column:description" json:"description"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the table name for Permission.
func (Permission) TableName() string {
	return "mxid_permission"
}

// AuditResource implements audit.Audited.
func (Permission) AuditResource() string {
	return "permission"
}

// TenantScoped marks mxid_permission for automatic tenant isolation. Despite
// the name this row IS tenant-scoped (has a tenant_id column), not a global
// catalog.
func (Permission) TenantScoped() {}

// RolePermission represents the mxid_role_permission table.
type RolePermission struct {
	ID           int64     `gorm:"column:id;primaryKey" json:"id"`
	RoleID       int64     `gorm:"column:role_id;not null" json:"role_id"`
	PermissionID int64     `gorm:"column:permission_id;not null" json:"permission_id"`
	CreatedAt    time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the table name for RolePermission.
func (RolePermission) TableName() string {
	return "mxid_role_permission"
}
