package user

import (
	"context"
	"time"
)

// ListParams holds parameters for listing users with filters.
type ListParams struct {
	Page     int
	PageSize int
	Search   string
	Status   *int
	OrgID    *int64
}

// Repository defines the data access interface for the user domain.
type Repository interface {
	// User CRUD
	Create(ctx context.Context, user *User) error
	// CreateWithProfile inserts the user, its empty detail row and the initial
	// password-history row atomically in one transaction, so a partial failure
	// can never leave an orphaned user without a detail / history record.
	CreateWithProfile(ctx context.Context, user *User, detail *UserDetail, history *UserPasswordHistory) error
	GetByID(ctx context.Context, id int64) (*User, error)
	GetByUsername(ctx context.Context, tenantID int64, username string) (*User, error)
	GetByEmail(ctx context.Context, tenantID int64, email string) (*User, error)
	GetByPhone(ctx context.Context, tenantID int64, phone string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, tenantID int64, params ListParams) ([]*User, int64, error)
	UpdateStatus(ctx context.Context, id int64, status int) error
	UpdatePassword(ctx context.Context, id int64, hash string) error
	UpdateLastLogin(ctx context.Context, id int64, ip string) error
	// CountByTenant returns the total number of users in the tenant. Used
	// by the license-quota pre-flight check on Create.
	CountByTenant(ctx context.Context, tenantID int64) (int64, error)
	// CountAll returns the total number of users across all tenants. Used
	// by the global license MaxUsers quota.
	CountAll(ctx context.Context) (int64, error)
	// SetMustChangePassword toggles the must_change_pwd flag without touching
	// the hash itself — used right after an admin-initiated reset to force the
	// user to pick a new password on their next login.
	SetMustChangePassword(ctx context.Context, id int64, must bool) error
	// SetSuperAdmin flips the is_super_admin flag. Mutations to this
	// field MUST go through Service.SetSuperAdmin so the grant/revoke
	// audit event is emitted alongside the column update.
	SetSuperAdmin(ctx context.Context, id int64, makeSuper bool) error
	// CountSuperAdmins returns how many active super admins exist for
	// the tenant — used by SetSuperAdmin to refuse revoking the last
	// one (otherwise the tenant becomes unmanageable).
	CountSuperAdmins(ctx context.Context, tenantID int64) (int64, error)
	// ListSuperAdmins returns the active super-admin users of the tenant.
	// Powers the super_admin role's member list (a façade over the flag).
	ListSuperAdmins(ctx context.Context, tenantID int64) ([]*User, error)

	// Detail
	CreateDetail(ctx context.Context, detail *UserDetail) error
	GetDetailByUserID(ctx context.Context, userID int64) (*UserDetail, error)
	UpdateDetail(ctx context.Context, detail *UserDetail) error

	// Password history
	CreatePasswordHistory(ctx context.Context, h *UserPasswordHistory) error
	GetPasswordHistory(ctx context.Context, userID int64, limit int) ([]*UserPasswordHistory, error)

	// Identity
	ListIdentities(ctx context.Context, userID int64) ([]*UserIdentity, error)
	DeleteIdentity(ctx context.Context, userID, identityID int64) error
	// GetIdentityByExternal looks up a binding by (tenant, provider_type,
	// provider_id, external_id). Used by the external-IdP login flow to
	// decide whether to attach to an existing user or auto-create one.
	GetIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error)
	CreateIdentity(ctx context.Context, identity *UserIdentity) error
	UpdateIdentity(ctx context.Context, identity *UserIdentity) error

	// MFA
	GetMFA(ctx context.Context, userID int64, mfaType string) (*UserMFA, error)
	ListMFA(ctx context.Context, userID int64) ([]*UserMFA, error)
	// MFAEnabledByUserIDs returns the set of user IDs (from the given list) that
	// have at least one verified MFA method. Batched (one GROUP BY) so the user
	// list view can show an MFA badge without an N+1.
	MFAEnabledByUserIDs(ctx context.Context, userIDs []int64) (map[int64]bool, error)
	// CreateMFA inserts only if absent (ON CONFLICT DO NOTHING); the bool reports
	// whether this call inserted (false = a concurrent enroll won the race).
	CreateMFA(ctx context.Context, mfa *UserMFA) (bool, error)
	UpdateMFA(ctx context.Context, mfa *UserMFA) error
	DeleteMFA(ctx context.Context, userID int64, mfaType string) error

	// Login records
	CreateLoginRecord(ctx context.Context, rec *LoginRecord) error
	ListLoginRecords(ctx context.Context, userID int64, page, pageSize int) ([]*LoginRecord, int64, error)
	PurgeLoginRecordsOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}
