// Package apitoken implements Personal Access Tokens — long-lived bearer
// credentials a user (typically an admin) attaches to scripts / CI to call
// the public /openapi/v1 surface without a browser session.
//
// Threat model:
//   - Plaintext returned ONCE; only bcrypt hash persists.
//   - Lookup uses a non-secret prefix + bcrypt compare so a leaked DB
//     dump alone doesn't expose any tokens.
//   - Scopes constrain what the token can do (subset of permission codes);
//     the bearer middleware blocks anything outside the scope set.
//   - revoked_at + expires_at gate every authenticated request.
package apitoken

import (
	"time"

	"gorm.io/datatypes"
)

// Token is the storage row.
type Token struct {
	ID          int64          `gorm:"column:id;primaryKey" json:"id"`
	TenantID    int64          `gorm:"column:tenant_id;not null" json:"tenant_id"`
	UserID      int64          `gorm:"column:user_id;not null" json:"user_id"`
	Name        string         `gorm:"column:name;not null;size:128" json:"name"`
	Prefix      string         `gorm:"column:prefix;not null;size:16" json:"prefix"`
	TokenHash   string         `gorm:"column:token_hash;not null;size:120" json:"-"`
	Scopes      datatypes.JSON `gorm:"column:scopes;type:jsonb;default:'[]'" json:"scopes"`
	ExpiresAt   *time.Time     `gorm:"column:expires_at" json:"expires_at"`
	LastUsedAt  *time.Time     `gorm:"column:last_used_at" json:"last_used_at"`
	RevokedAt   *time.Time     `gorm:"column:revoked_at" json:"revoked_at"`
	CreatedAt   time.Time      `gorm:"column:created_at;not null" json:"created_at"`
}

// TableName binds to the migration's table name.
func (Token) TableName() string { return "mxid_api_token" }

// AuditResource implements audit.Audited.
func (Token) AuditResource() string { return "api_token" }

// TenantScoped marks mxid_api_token for automatic tenant isolation.
func (Token) TenantScoped() {}

// IsActive reports whether the token is currently usable — not revoked and
// not past its expiry.
func (t *Token) IsActive(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
		return false
	}
	return true
}
