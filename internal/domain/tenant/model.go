// Package tenant manages multi-tenant root entities. Each tenant is an
// isolated logical organisation: its own users, orgs, groups, roles, IdPs,
// audit log, etc. Apps default to tenant-scoped but can be shared across
// tenants (see internal/domain/app — app.Scope/SubjectStrategy).
//
// Cross-tenant access is reserved to platform-level super_admin (binding
// without tenant scope). Tenant admins are bound to a single tenant via
// the role_binding.scope_type='tenant' mechanism (future) or implicit
// session.tenant_id today.
package tenant

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Tenant status constants.
const (
	StatusEnabled  = 1
	StatusDisabled = 2
)

// Tenant represents the mxid_tenant table. Already exists in migration 001;
// this is the Go-side model for the CRUD surface.
type Tenant struct {
	ID        int64          `gorm:"column:id;primaryKey" json:"id,string"`
	Name      string         `gorm:"column:name;size:128;not null" json:"name"`
	Code      string         `gorm:"column:code;size:64;not null;uniqueIndex" json:"code"`
	Status    int            `gorm:"column:status;not null;default:1" json:"status"`
	Config    datatypes.JSON `gorm:"column:config;type:jsonb;default:'{}'" json:"config"`
	CreatedAt time.Time      `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the postgres table name.
func (Tenant) TableName() string { return "mxid_tenant" }

// AuditResource implements audit.Audited.
func (Tenant) AuditResource() string { return "tenant" }
