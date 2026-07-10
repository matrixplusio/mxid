package user

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// gormRepository implements Repository using GORM.
type gormRepository struct {
	db *gorm.DB
}

// NewGormRepository creates a new GORM-based user repository.
func NewGormRepository(db *gorm.DB) Repository {
	return &gormRepository{db: db}
}

// Create inserts a new user record.
func (r *gormRepository) Create(ctx context.Context, user *User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// CreateWithProfile inserts the user + empty detail + initial password history
// in a single transaction. WithContext(ctx) carries the tenant scope into the
// transaction so the tenantscope plugin still stamps tenant_id on the user row.
func (r *gormRepository) CreateWithProfile(ctx context.Context, user *User, detail *UserDetail, history *UserPasswordHistory) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		if err := tx.Create(detail).Error; err != nil {
			return fmt.Errorf("create user detail: %w", err)
		}
		if err := tx.Create(history).Error; err != nil {
			return fmt.Errorf("create password history: %w", err)
		}
		return nil
	})
}

// SetSuperAdmin toggles the super-admin flag for a user.
func (r *gormRepository) SetSuperAdmin(ctx context.Context, id int64, makeSuper bool) error {
	res := r.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", id).
		Update("is_super_admin", makeSuper)
	if res.Error != nil {
		return fmt.Errorf("set super admin: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// CountSuperAdmins returns the number of active super admins in the tenant.
func (r *gormRepository) CountSuperAdmins(ctx context.Context, tenantID int64) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).
		Model(&User{}).
		Where("tenant_id = ? AND is_super_admin IS TRUE", tenantID).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("count super admins: %w", err)
	}
	return n, nil
}

// ListSuperAdmins returns the active super-admin users of the tenant, ordered
// by id. Powers the super_admin role's member list, which is a façade over the
// is_super_admin flag rather than role_binding rows.
func (r *gormRepository) ListSuperAdmins(ctx context.Context, tenantID int64) ([]*User, error) {
	var users []*User
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND is_super_admin IS TRUE AND deleted_at IS NULL", tenantID).
		Order("id ASC").
		Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("list super admins: %w", err)
	}
	return users, nil
}

// GetByID finds a user by primary key.
func (r *gormRepository) GetByID(ctx context.Context, id int64) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).First(&user, id).Error; err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &user, nil
}

// GetByUsername finds a user by tenant and username.
func (r *gormRepository) GetByUsername(ctx context.Context, tenantID int64, username string) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND username = ?", tenantID, username).
		First(&user).Error
	if err != nil {
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return &user, nil
}

// GetByEmail finds a user by tenant and email.
func (r *gormRepository) GetByEmail(ctx context.Context, tenantID int64, email string) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND email = ?", tenantID, email).
		First(&user).Error
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &user, nil
}

// GetByPhone finds a user by tenant and phone.
func (r *gormRepository) GetByPhone(ctx context.Context, tenantID int64, phone string) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND phone = ?", tenantID, phone).
		First(&user).Error
	if err != nil {
		return nil, fmt.Errorf("get user by phone: %w", err)
	}
	return &user, nil
}

// Update saves changes to an existing user.
func (r *gormRepository) Update(ctx context.Context, user *User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

// Delete performs a soft delete on a user.
func (r *gormRepository) Delete(ctx context.Context, id int64) error {
	if err := r.db.WithContext(ctx).Delete(&User{}, id).Error; err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// CountByTenant counts users in a single tenant. Cheap (single index scan).
func (r *gormRepository) CountByTenant(ctx context.Context, tenantID int64) (int64, error) {
	var n int64
	if err := r.db.WithContext(ctx).Model(&User{}).Where("tenant_id = ?", tenantID).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("count users by tenant: %w", err)
	}
	return n, nil
}

// CountAll counts users across all tenants. Used for global license quota.
func (r *gormRepository) CountAll(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.WithContext(ctx).Model(&User{}).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("count all users: %w", err)
	}
	return n, nil
}

// List returns a paginated list of users with optional filters.
func (r *gormRepository) List(ctx context.Context, tenantID int64, params ListParams) ([]*User, int64, error) {
	var users []*User
	var total int64

	query := r.db.WithContext(ctx).Model(&User{}).Where("tenant_id = ?", tenantID)

	// Apply scopes
	query = query.Scopes(
		searchScope(params.Search),
		statusScope(params.Status),
		orgScope(params.OrgID),
	)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	offset := (params.Page - 1) * params.PageSize
	if err := query.Offset(offset).Limit(params.PageSize).Order("created_at DESC").Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}

	return users, total, nil
}

// searchScope returns a GORM scope that filters by search term across username, email, phone, and display_name.
func searchScope(search string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if search == "" {
			return db
		}
		like := "%" + search + "%"
		return db.Where(
			"username ILIKE ? OR email ILIKE ? OR phone ILIKE ? OR display_name ILIKE ?",
			like, like, like, like,
		)
	}
}

// statusScope returns a GORM scope that filters by user status.
func statusScope(status *int) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if status == nil {
			return db
		}
		return db.Where("status = ?", *status)
	}
}

// orgScope returns a GORM scope that filters by organization membership via mxid_user_org join.
func orgScope(orgID *int64) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if orgID == nil {
			return db
		}
		return db.Where(
			"id IN (SELECT user_id FROM mxid_user_org WHERE org_id = ?)", *orgID,
		)
	}
}

// UpdateStatus updates only the status field of a user.
func (r *gormRepository) UpdateStatus(ctx context.Context, id int64, status int) error {
	result := r.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", id).
		Update("status", status)
	if result.Error != nil {
		return fmt.Errorf("update user status: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// UpdatePassword updates the password hash and password_changed_at timestamp.
func (r *gormRepository) UpdatePassword(ctx context.Context, id int64, hash string) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"password_hash":       hash,
			"password_changed_at": now,
			"must_change_pwd":     false,
		})
	if result.Error != nil {
		return fmt.Errorf("update user password: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// UpdateLastLogin updates the last login timestamp and IP.
func (r *gormRepository) UpdateLastLogin(ctx context.Context, id int64, ip string) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"last_login_at": now,
			"last_login_ip": ip,
		})
	if result.Error != nil {
		return fmt.Errorf("update last login: %w", result.Error)
	}
	return nil
}

// CreateDetail inserts a new user detail record.
func (r *gormRepository) CreateDetail(ctx context.Context, detail *UserDetail) error {
	if err := r.db.WithContext(ctx).Create(detail).Error; err != nil {
		return fmt.Errorf("create user detail: %w", err)
	}
	return nil
}

// GetDetailByUserID finds a user detail by user ID.
func (r *gormRepository) GetDetailByUserID(ctx context.Context, userID int64) (*UserDetail, error) {
	var detail UserDetail
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		First(&detail).Error
	if err != nil {
		return nil, fmt.Errorf("get user detail: %w", err)
	}
	return &detail, nil
}

// UpdateDetail saves changes to a user detail record.
func (r *gormRepository) UpdateDetail(ctx context.Context, detail *UserDetail) error {
	if err := r.db.WithContext(ctx).Save(detail).Error; err != nil {
		return fmt.Errorf("update user detail: %w", err)
	}
	return nil
}

// CreatePasswordHistory inserts a password history record.
func (r *gormRepository) CreatePasswordHistory(ctx context.Context, h *UserPasswordHistory) error {
	if err := r.db.WithContext(ctx).Create(h).Error; err != nil {
		return fmt.Errorf("create password history: %w", err)
	}
	return nil
}

// GetPasswordHistory returns recent password history entries for a user.
func (r *gormRepository) GetPasswordHistory(ctx context.Context, userID int64, limit int) ([]*UserPasswordHistory, error) {
	var history []*UserPasswordHistory
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&history).Error
	if err != nil {
		return nil, fmt.Errorf("get password history: %w", err)
	}
	return history, nil
}

// ListIdentities returns all identity bindings for a user.
func (r *gormRepository) ListIdentities(ctx context.Context, userID int64) ([]*UserIdentity, error) {
	var identities []*UserIdentity
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&identities).Error
	if err != nil {
		return nil, fmt.Errorf("list user identities: %w", err)
	}
	return identities, nil
}

// DeleteIdentity removes a single identity binding for a user. Scoped by
// both user_id and identity id so a stale identity id from one user cannot
// be used to unbind another user's identity.
func (r *gormRepository) DeleteIdentity(ctx context.Context, userID, identityID int64) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND id = ?", userID, identityID).
		Delete(&UserIdentity{})
	if result.Error != nil {
		return fmt.Errorf("delete user identity: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// SetMustChangePassword updates only the must_change_pwd flag.
func (r *gormRepository) SetMustChangePassword(ctx context.Context, id int64, must bool) error {
	result := r.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", id).
		Update("must_change_pwd", must)
	if result.Error != nil {
		return fmt.Errorf("set must change password: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// GetMFA finds a specific MFA configuration for a user.
func (r *gormRepository) GetMFA(ctx context.Context, userID int64, mfaType string) (*UserMFA, error) {
	var mfa UserMFA
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ?", userID, mfaType).
		First(&mfa).Error
	if err != nil {
		return nil, fmt.Errorf("get user mfa: %w", err)
	}
	return &mfa, nil
}

// ListMFA returns all MFA configurations for a user.
func (r *gormRepository) ListMFA(ctx context.Context, userID int64) ([]*UserMFA, error) {
	var mfas []*UserMFA
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&mfas).Error
	if err != nil {
		return nil, fmt.Errorf("list user mfa: %w", err)
	}
	return mfas, nil
}

// MFAEnabledByUserIDs returns which of the given users have at least one
// verified MFA method. One GROUP BY query for the whole page (no N+1). The
// user IDs are already tenant-scoped by the caller (the list query), and
// mxid_user_mfa has no tenant column, so filtering by user_id is sufficient.
func (r *gormRepository) MFAEnabledByUserIDs(ctx context.Context, userIDs []int64) (map[int64]bool, error) {
	out := make(map[int64]bool, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	var ids []int64
	if err := r.db.WithContext(ctx).
		Model(&UserMFA{}).
		Distinct("user_id").
		Where("user_id IN ? AND verified = ?", userIDs, true).
		Pluck("user_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("batch mfa-enabled lookup: %w", err)
	}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// CreateMFA inserts a new MFA configuration.
// CreateMFA inserts the row only if no (user_id, type) row exists yet, returning
// whether THIS call performed the insert. SetupTOTP can fire twice near
// simultaneously (a double-click, or React StrictMode double-invoking the enroll
// effect); DO-NOTHING-on-conflict makes the loser a no-op (inserted=false) rather
// than a 500, and — critically — does NOT overwrite the winner's secret, so the
// caller can hand BOTH setup responses the one stored secret (see SetupTOTP).
func (r *gormRepository) CreateMFA(ctx context.Context, mfa *UserMFA) (bool, error) {
	res := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "type"}},
		DoNothing: true,
	}).Create(mfa)
	if res.Error != nil {
		return false, fmt.Errorf("create user mfa: %w", res.Error)
	}
	return res.RowsAffected > 0, nil
}

// UpdateMFA saves changes to an MFA configuration.
func (r *gormRepository) UpdateMFA(ctx context.Context, mfa *UserMFA) error {
	if err := r.db.WithContext(ctx).Save(mfa).Error; err != nil {
		return fmt.Errorf("update user mfa: %w", err)
	}
	return nil
}

// DeleteMFA removes an MFA configuration for a user.
func (r *gormRepository) DeleteMFA(ctx context.Context, userID int64, mfaType string) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ?", userID, mfaType).
		Delete(&UserMFA{})
	if result.Error != nil {
		return fmt.Errorf("delete user mfa: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// CreateLoginRecord persists one login attempt.
func (r *gormRepository) CreateLoginRecord(ctx context.Context, rec *LoginRecord) error {
	if err := r.db.WithContext(ctx).Create(rec).Error; err != nil {
		return fmt.Errorf("create login record: %w", err)
	}
	return nil
}

// PurgeLoginRecordsOlderThan hard-deletes login-history rows older than cutoff.
// Login records are display/audit history — unbounded growth is the only
// concern (they carry no live security state). A global cross-tenant GC, so
// callers pass a system context; returns the number of rows removed.
func (r *gormRepository) PurgeLoginRecordsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("created_at < ?", cutoff).
		Delete(&LoginRecord{})
	return res.RowsAffected, res.Error
}

// ListLoginRecords returns paginated login records for a user, newest first.
func (r *gormRepository) ListLoginRecords(ctx context.Context, userID int64, page, pageSize int) ([]*LoginRecord, int64, error) {
	var total int64
	if err := r.db.WithContext(ctx).
		Model(&LoginRecord{}).
		Where("user_id = ?", userID).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count login records: %w", err)
	}

	rows := make([]*LoginRecord, 0, pageSize)
	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("list login records: %w", err)
	}
	return rows, total, nil
}

// GetIdentityByExternal looks up an identity binding by the external composite
// key. Used by the external-IdP login flow.
func (r *gormRepository) GetIdentityByExternal(ctx context.Context, tenantID int64, providerType, providerID, externalID string) (*UserIdentity, error) {
	var id UserIdentity
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND provider_type = ? AND provider_id = ? AND external_id = ?",
			tenantID, providerType, providerID, externalID).
		First(&id).Error
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// CreateIdentity inserts a new identity binding.
func (r *gormRepository) CreateIdentity(ctx context.Context, identity *UserIdentity) error {
	if err := r.db.WithContext(ctx).Create(identity).Error; err != nil {
		return fmt.Errorf("create identity: %w", err)
	}
	return nil
}

// UpdateIdentity persists changes to an identity binding.
func (r *gormRepository) UpdateIdentity(ctx context.Context, identity *UserIdentity) error {
	if err := r.db.WithContext(ctx).Save(identity).Error; err != nil {
		return fmt.Errorf("update identity: %w", err)
	}
	return nil
}
