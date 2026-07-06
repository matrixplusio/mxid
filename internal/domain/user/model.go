package user

import (
	"time"

	"gorm.io/gorm"
)

// User status constants.
const (
	StatusActive   = 1
	StatusLocked   = 2
	StatusDisabled = 3
	StatusPending  = 4
)

// Gender constants.
const (
	GenderUnknown = 0
	GenderMale    = 1
	GenderFemale  = 2
)

// MFA type constants.
const (
	MFATypeTotp     = "totp"
	MFATypeSMS      = "sms"
	MFATypeEmail    = "email"
	MFATypeWebauthn = "webauthn"
)

// User represents the mxid_user table.
type User struct {
	ID                int64          `gorm:"column:id;primaryKey" json:"id"`
	TenantID          int64          `gorm:"column:tenant_id;not null" json:"tenant_id"`
	Username          string         `gorm:"column:username;not null;size:128" json:"username"`
	Email             *string        `gorm:"column:email;size:256" json:"email"`
	EmailVerified     bool           `gorm:"column:email_verified;not null;default:false" json:"email_verified"`
	EmailVerifiedAt   *time.Time     `gorm:"column:email_verified_at" json:"email_verified_at"`
	Phone             *string        `gorm:"column:phone;size:32" json:"phone"`
	DisplayName       *string        `gorm:"column:display_name;size:128" json:"display_name"`
	Avatar            *string        `gorm:"column:avatar;type:text" json:"avatar"`
	PasswordHash      string         `gorm:"column:password_hash;size:256" json:"-"`
	Status            int            `gorm:"column:status;not null;default:1" json:"status"`
	LastLoginAt       *time.Time     `gorm:"column:last_login_at" json:"last_login_at"`
	LastLoginIP       *string        `gorm:"column:last_login_ip;size:64" json:"last_login_ip"`
	PasswordChangedAt *time.Time     `gorm:"column:password_changed_at" json:"password_changed_at"`
	MustChangePwd     bool           `gorm:"column:must_change_pwd;not null;default:false" json:"must_change_pwd"`
	// IsSuperAdmin grants the holder every permission, bypassing the RBAC
	// scope check entirely. Previously this state was encoded as "holds a
	// binding to role_id == 1", which depended on seed-data invariants
	// that don't survive a DB restore / cross-environment import. The
	// column is the authoritative source from migration 000033 onwards.
	// Mutations MUST emit a user.super_admin.{grant,revoke} audit event
	// and invalidate the authz cache for this user.
	IsSuperAdmin      bool           `gorm:"column:is_super_admin;not null;default:false" json:"is_super_admin"`
	// IsBuiltin marks a platform-seeded break-glass account (the bootstrap
	// admin). Such accounts must authenticate locally only — console
	// external-IdP login refuses them so the emergency path never depends on
	// an IdP being reachable. See migration 000038.
	IsBuiltin         bool           `gorm:"column:is_builtin;not null;default:false" json:"is_builtin"`
	CreatedAt         time.Time      `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt         time.Time      `gorm:"column:updated_at;not null" json:"updated_at"`
	CreatedBy         *int64         `gorm:"column:created_by" json:"created_by"`
	UpdatedBy         *int64         `gorm:"column:updated_by" json:"updated_by"`
	DeletedAt         gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the table name for User.
func (User) TableName() string {
	return "mxid_user"
}

// AuditResource implements audit.Audited.
func (User) AuditResource() string {
	return "user"
}

// TenantScoped marks mxid_user for automatic tenant isolation (see pkg/tenantscope).
func (User) TenantScoped() {}

// UserDetail represents the mxid_user_detail table.
type UserDetail struct {
	ID         int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID     int64     `gorm:"column:user_id;not null" json:"user_id"`
	Gender     *int      `gorm:"column:gender" json:"gender"`
	Birthday   *string   `gorm:"column:birthday" json:"birthday"`
	Address    *string   `gorm:"column:address;size:512" json:"address"`
	EmployeeNo *string   `gorm:"column:employee_no;size:64" json:"employee_no"`
	JobTitle   *string   `gorm:"column:job_title;size:128" json:"job_title"`
	Department *string   `gorm:"column:department;size:256" json:"department"`
	Extra      *string   `gorm:"column:extra;type:jsonb;default:'{}'" json:"extra"`
	CreatedAt  time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

// TableName returns the table name for UserDetail.
func (UserDetail) TableName() string {
	return "mxid_user_detail"
}

// UserPasswordHistory represents the mxid_user_password_history table.
type UserPasswordHistory struct {
	ID           int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID       int64     `gorm:"column:user_id;not null" json:"user_id"`
	PasswordHash string    `gorm:"column:password_hash;not null;size:256" json:"-"`
	CreatedAt    time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName returns the table name for UserPasswordHistory.
func (UserPasswordHistory) TableName() string {
	return "mxid_user_password_history"
}

// UserIdentity represents the mxid_user_identity table.
type UserIdentity struct {
	ID           int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID       int64     `gorm:"column:user_id;not null" json:"user_id"`
	TenantID     int64     `gorm:"column:tenant_id;not null" json:"tenant_id"`
	ProviderType string    `gorm:"column:provider_type;not null;size:32" json:"provider_type"`
	ProviderID   string    `gorm:"column:provider_id;not null;size:128" json:"provider_id"`
	ExternalID   string    `gorm:"column:external_id;not null;size:256" json:"external_id"`
	ExternalName *string   `gorm:"column:external_name;size:256" json:"external_name"`
	Extra        *string   `gorm:"column:extra;type:jsonb;default:'{}'" json:"extra"`
	CreatedAt    time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt    time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

// TableName returns the table name for UserIdentity.
func (UserIdentity) TableName() string {
	return "mxid_user_identity"
}

// TenantScoped marks mxid_user_identity for automatic tenant isolation.
func (UserIdentity) TenantScoped() {}

// UserMFA represents the mxid_user_mfa table.
type UserMFA struct {
	ID        int64     `gorm:"column:id;primaryKey" json:"id"`
	UserID    int64     `gorm:"column:user_id;not null" json:"user_id"`
	Type      string    `gorm:"column:type;not null;size:16" json:"type"`
	Secret    *string   `gorm:"column:secret;size:256" json:"-"`
	Config    *string   `gorm:"column:config;type:jsonb;default:'{}'" json:"config"`
	IsDefault bool      `gorm:"column:is_default;not null;default:false" json:"is_default"`
	Verified  bool      `gorm:"column:verified;not null;default:false" json:"verified"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

// TableName returns the table name for UserMFA.
func (UserMFA) TableName() string {
	return "mxid_user_mfa"
}
