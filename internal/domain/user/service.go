package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Service errors.
var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUsernameExists  = errors.New("username already exists")
	ErrEmailExists     = errors.New("email already exists")
	ErrPhoneExists     = errors.New("phone already exists")
	ErrInvalidPassword = errors.New("invalid password")
	ErrPasswordReused  = errors.New("password has been used recently")
	// ErrLicenseQuotaExceeded — admin tried to create a user beyond the
	// license MaxUsers limit. Maps to HTTP 402 / 403 at the handler.
	ErrLicenseQuotaExceeded = errors.New("license user quota exceeded")
	ErrWeakPassword         = errors.New("password does not meet complexity policy")
	ErrDetailNotFound       = errors.New("user detail not found")
	ErrIdentityNotFound     = errors.New("user identity not found")
	// ErrLastSuperAdmin blocks revoking the only remaining super_admin
	// of a tenant — without it the tenant becomes unmanageable.
	ErrLastSuperAdmin = errors.New("cannot revoke the last super admin of the tenant")
)

// PasswordPolicy is the runtime view user.Service uses for validation.
// Same shape as setting.PasswordPolicy but defined here so the user
// package doesn't import setting (would create a dep cycle with the
// adapter that provides it from cmd/server/main.go).
type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
	HistoryCount     int
}

// PasswordPolicyProvider returns the active password policy for a tenant.
// Implementations read from setting.Service (DB) with YAML fallback. nil
// = the user.Service falls back to its yaml-derived defaults.
type PasswordPolicyProvider func(ctx context.Context, tenantID int64) PasswordPolicy

// Service provides business logic for user management.
// LicenseQuotaCheck returns ErrLicenseQuotaExceeded when creating one more
// user in this tenant would exceed the active license. nil = no quota
// (legacy / OSS).
type LicenseQuotaCheck func(ctx context.Context, tenantID int64) error

type Service struct {
	repo            Repository
	backupRepo      BackupCodeRepository
	idGen           *snowflake.Generator
	eventBus        *event.Bus
	config          *bootstrap.SecurityConfig
	masterKey       *crypto.MasterKey
	issuer          string
	clearMFALockout func(ctx context.Context, userID int64)
	pwdPolicy       PasswordPolicyProvider
	licenseQuota    LicenseQuotaCheck
	totpReplayRDB   *redis.Client
}

// SetLicenseQuotaCheck wires the runtime license-quota lookup. Called by
// main.go after the setting service is built.
func (s *Service) SetLicenseQuotaCheck(c LicenseQuotaCheck) { s.licenseQuota = c }

// SetPasswordPolicyProvider injects the runtime policy lookup. Called by
// main.go after the setting service is built; nil = stay on YAML.
func (s *Service) SetPasswordPolicyProvider(p PasswordPolicyProvider) {
	s.pwdPolicy = p
}

// activePasswordPolicy returns the runtime policy: DB if provider wired,
// else YAML. tenantID may be 0 for global checks.
func (s *Service) activePasswordPolicy(ctx context.Context, tenantID int64) PasswordPolicy {
	if s.pwdPolicy != nil {
		return s.pwdPolicy(ctx, tenantID)
	}
	return PasswordPolicy{
		MinLength:        s.config.Password.MinLength,
		RequireUppercase: s.config.Password.RequireUppercase,
		RequireLowercase: s.config.Password.RequireLowercase,
		RequireNumber:    s.config.Password.RequireNumber,
		RequireSpecial:   s.config.Password.RequireSpecial,
		HistoryCount:     s.config.Password.HistoryCount,
	}
}

// validatePassword enforces the runtime password complexity policy.
// Returns ErrWeakPassword with the specific reason so the UI can be
// helpful ("缺少大写字母" vs generic "weak password").
func (s *Service) validatePassword(ctx context.Context, tenantID int64, pwd string) error {
	p := s.activePasswordPolicy(ctx, tenantID)
	if p.MinLength > 0 && len(pwd) < p.MinLength {
		return fmt.Errorf("%w: 密码至少需要 %d 位", ErrWeakPassword, p.MinLength)
	}
	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	for _, r := range pwd {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if p.RequireUppercase && !hasUpper {
		return fmt.Errorf("%w: 需要至少一个大写字母", ErrWeakPassword)
	}
	if p.RequireLowercase && !hasLower {
		return fmt.Errorf("%w: 需要至少一个小写字母", ErrWeakPassword)
	}
	if p.RequireNumber && !hasDigit {
		return fmt.Errorf("%w: 需要至少一个数字", ErrWeakPassword)
	}
	if p.RequireSpecial && !hasSpecial {
		return fmt.Errorf("%w: 需要至少一个特殊字符", ErrWeakPassword)
	}
	return nil
}

// SetBackupCodeRepository injects the backup-code storage post-construct
// so existing call sites of NewService don't have to grow another arg.
// Called by user.Register after wiring.
func (s *Service) SetBackupCodeRepository(r BackupCodeRepository) {
	s.backupRepo = r
}

// SetMFALockoutClearer injects a callback the admin "clear MFA lockout"
// endpoint calls to wipe the rate-limit counters. Avoids the user domain
// having to import Redis or authn directly.
func (s *Service) SetMFALockoutClearer(fn func(ctx context.Context, userID int64)) {
	s.clearMFALockout = fn
}

// ClearMFALockout invokes the injected clearer (no-op when not wired).
func (s *Service) ClearMFALockout(ctx context.Context, userID int64) {
	if s.clearMFALockout != nil {
		s.clearMFALockout(ctx, userID)
	}
}

// NewService creates a new user service.
//
// masterKey may be nil in tests; TOTP setup/verify will return ErrMasterKeyMissing
// in that case. issuer is the label embedded in otpauth URLs (and shown by
// authenticator apps); empty falls back to "MXID".
func NewService(
	repo Repository,
	idGen *snowflake.Generator,
	eventBus *event.Bus,
	config *bootstrap.SecurityConfig,
	masterKey *crypto.MasterKey,
	issuer string,
) *Service {
	if issuer == "" {
		issuer = "MXID"
	}
	return &Service{
		repo:      repo,
		idGen:     idGen,
		eventBus:  eventBus,
		config:    config,
		masterKey: masterKey,
		issuer:    issuer,
	}
}

// RecordPIIView publishes a UserPIIView audit event when an admin reads
// another user's full PII bundle. Self-views must be filtered by the
// caller — this always emits.
func (s *Service) RecordPIIView(ctx context.Context, actorID, tenantID, targetID int64, fields []string) {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: event.UserPIIView,
		Payload: map[string]any{
			"user_id":   actorID,
			"target_id": targetID,
			"tenant_id": tenantID,
			"fields":    fields,
		},
	})
}

// SetSuperAdmin flips the user's is_super_admin flag and emits the
// corresponding grant/revoke audit event. Returns ErrUserNotFound when
// the target does not exist. Refuses to revoke the last super admin of
// a tenant (license-defence convention — every tenant must keep at least
// one super admin or be unmanageable).
func (s *Service) SetSuperAdmin(ctx context.Context, actorID, tenantID, targetID int64, makeSuper bool) error {
	target, err := s.repo.GetByID(ctx, targetID)
	if err != nil {
		return ErrUserNotFound
	}
	if target.TenantID != tenantID {
		// Cross-tenant grant is a hard no — super_admin scope is per
		// tenant; the X-Tenant-ID override middleware already restricts
		// what's visible, but defend in depth here.
		return ErrUserNotFound
	}
	if target.IsSuperAdmin == makeSuper {
		return nil // idempotent
	}
	if !makeSuper {
		remaining, err := s.repo.CountSuperAdmins(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("count super admins: %w", err)
		}
		if remaining <= 1 {
			return ErrLastSuperAdmin
		}
	}
	if err := s.repo.SetSuperAdmin(ctx, targetID, makeSuper); err != nil {
		return fmt.Errorf("set super admin: %w", err)
	}
	evt := event.UserSuperAdminRevoke
	if makeSuper {
		evt = event.UserSuperAdminGrant
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: evt,
		Payload: map[string]any{
			"user_id":   actorID,
			"target_id": targetID,
			"tenant_id": tenantID,
			"username":  target.Username,
		},
	})
	return nil
}

// Create creates a new user with hashed password and detail record.
func (s *Service) Create(ctx context.Context, tenantID int64, req *CreateUserRequest) (*User, error) {
	// License quota — admin can cap users via license settings. Checked
	// before uniqueness queries so the early-rejection is fast.
	if s.licenseQuota != nil {
		if err := s.licenseQuota(ctx, tenantID); err != nil {
			return nil, err
		}
	}

	// Check username uniqueness
	if _, err := s.repo.GetByUsername(ctx, tenantID, req.Username); err == nil {
		return nil, ErrUsernameExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("check username: %w", err)
	}

	// Check email uniqueness if provided
	if req.Email != nil && *req.Email != "" {
		if _, err := s.repo.GetByEmail(ctx, tenantID, *req.Email); err == nil {
			return nil, ErrEmailExists
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("check email: %w", err)
		}
	}

	// Check phone uniqueness if provided
	if req.Phone != nil && *req.Phone != "" {
		if _, err := s.repo.GetByPhone(ctx, tenantID, *req.Phone); err == nil {
			return nil, ErrPhoneExists
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("check phone: %w", err)
		}
	}

	// Enforce password complexity policy BEFORE hashing — bcrypt cost is
	// non-trivial so reject weak passwords early.
	if err := s.validatePassword(ctx, tenantID, req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now()
	status := StatusActive
	if req.Status != nil {
		status = *req.Status
	}

	user := &User{
		ID:                s.idGen.Generate(),
		TenantID:          tenantID,
		Username:          req.Username,
		Email:             req.Email,
		Phone:             req.Phone,
		DisplayName:       req.DisplayName,
		PasswordHash:      hash,
		Status:            status,
		PasswordChangedAt: &now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// Empty detail record + initial password history, written together with the
	// user in one transaction so a partial failure never orphans the user row.
	detail := &UserDetail{
		ID:        s.idGen.Generate(),
		UserID:    user.ID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	pwdHistory := &UserPasswordHistory{
		ID:           s.idGen.Generate(),
		UserID:       user.ID,
		PasswordHash: hash,
		CreatedAt:    now,
	}
	if err := s.repo.CreateWithProfile(ctx, user, detail, pwdHistory); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	// Publish event. Email + display_name carried in the payload so async
	// listeners (welcome mailer, audit, downstream sync) don't need a
	// second DB round-trip.
	emailVal := ""
	if user.Email != nil {
		emailVal = *user.Email
	}
	displayVal := ""
	if user.DisplayName != nil {
		displayVal = *user.DisplayName
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: event.UserCreated,
		Payload: map[string]any{
			"user_id":      user.ID,
			"tenant_id":    tenantID,
			"username":     user.Username,
			"email":        emailVal,
			"display_name": displayVal,
		},
	})

	return user, nil
}

// GetByID retrieves a user by ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*User, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	return user, nil
}

// Update modifies a user's mutable fields.
func (s *Service) Update(ctx context.Context, id int64, tenantID int64, req *UpdateUserRequest) (*User, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Check email uniqueness if changed
	if req.Email != nil && *req.Email != "" {
		if user.Email == nil || *user.Email != *req.Email {
			if _, err := s.repo.GetByEmail(ctx, tenantID, *req.Email); err == nil {
				return nil, ErrEmailExists
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("check email: %w", err)
			}
		}
		user.Email = req.Email
	}

	// Check phone uniqueness if changed
	if req.Phone != nil && *req.Phone != "" {
		if user.Phone == nil || *user.Phone != *req.Phone {
			if _, err := s.repo.GetByPhone(ctx, tenantID, *req.Phone); err == nil {
				return nil, ErrPhoneExists
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("check phone: %w", err)
			}
		}
		user.Phone = req.Phone
	}

	if req.DisplayName != nil {
		user.DisplayName = req.DisplayName
	}
	if req.Avatar != nil {
		user.Avatar = req.Avatar
	}
	if req.Status != nil {
		user.Status = *req.Status
	}

	user.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": user.ID},
	})

	return user, nil
}

// Delete soft-deletes a user.
func (s *Service) Delete(ctx context.Context, id int64) error {
	if _, err := s.repo.GetByID(ctx, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserDeleted,
		Payload: map[string]any{"user_id": id},
	})

	return nil
}

// List returns a paginated list of users.
func (s *Service) List(ctx context.Context, tenantID int64, params ListParams) ([]*User, int64, error) {
	users, total, err := s.repo.List(ctx, tenantID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	return users, total, nil
}

// UpdateStatus updates a user's status.
func (s *Service) UpdateStatus(ctx context.Context, id int64, status int) error {
	if err := s.repo.UpdateStatus(ctx, id, status); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("update status: %w", err)
	}

	eventType := event.UserUpdated
	if status == StatusLocked {
		eventType = event.UserLocked
	} else if status == StatusActive {
		// Could be an unlock if the previous status was Locked
		eventType = event.UserUnlocked
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    eventType,
		Payload: map[string]any{"user_id": id, "status": status},
	})

	return nil
}

// ChangePassword verifies the old password, checks history, and sets a new password.
func (s *Service) ChangePassword(ctx context.Context, id int64, req *ChangePasswordRequest) error {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	// Verify old password
	if !crypto.CheckPassword(req.OldPassword, user.PasswordHash) {
		return ErrInvalidPassword
	}

	// Complexity policy check (DB-backed when wired).
	if err := s.validatePassword(ctx, user.TenantID, req.NewPassword); err != nil {
		return err
	}

	// Check password history
	if err := s.checkPasswordHistory(ctx, id, req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	hash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.repo.UpdatePassword(ctx, id, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Save to history
	pwdHistory := &UserPasswordHistory{
		ID:           s.idGen.Generate(),
		UserID:       id,
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	if err := s.repo.CreatePasswordHistory(ctx, pwdHistory); err != nil {
		return fmt.Errorf("create password history: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserPasswordChanged,
		Payload: map[string]any{"user_id": id},
	})

	return nil
}

// ResetPassword sets a new password without verifying the old one (admin action).
//
// req.MustChange defaults to true — the reset forces the user to pick a new
// password on their next login so a leaked temp password can't be reused.
// Pass MustChange=false explicitly for system accounts where there's no
// interactive flow to satisfy the prompt.
func (s *Service) ResetPassword(ctx context.Context, id int64, req *ResetPasswordRequest) error {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	// Admin-initiated, but complexity + history policies still apply.
	if err := s.validatePassword(ctx, u.TenantID, req.NewPassword); err != nil {
		return err
	}
	if err := s.checkPasswordHistory(ctx, id, req.NewPassword); err != nil {
		return err
	}

	hash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.repo.UpdatePassword(ctx, id, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	mustChange := true
	if req.MustChange != nil {
		mustChange = *req.MustChange
	}
	if mustChange {
		if err := s.repo.SetMustChangePassword(ctx, id, true); err != nil {
			return fmt.Errorf("set must change password: %w", err)
		}
	}

	// Save to history
	pwdHistory := &UserPasswordHistory{
		ID:           s.idGen.Generate(),
		UserID:       id,
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	if err := s.repo.CreatePasswordHistory(ctx, pwdHistory); err != nil {
		return fmt.Errorf("create password history: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserPasswordChanged,
		Payload: map[string]any{"user_id": id, "admin_reset": true},
	})

	return nil
}

// requireUser fetches the parent user via the tenant-scoped repo so the
// tenantscope plugin appends tenant_id=?. A cross-tenant userID resolves to
// ErrRecordNotFound, which we surface as ErrUserNotFound. This is the
// parent-ownership guard the tenant-less child tables (mxid_user_detail,
// mxid_user_mfa, mxid_user_mfa_backup_code) rely on, since the column plugin
// cannot filter them directly.
func (s *Service) requireUser(ctx context.Context, userID int64) error {
	if _, err := s.repo.GetByID(ctx, userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}
	return nil
}

// GetDetail retrieves a user's detail record.
func (s *Service) GetDetail(ctx context.Context, userID int64) (*UserDetail, error) {
	if err := s.requireUser(ctx, userID); err != nil {
		return nil, err
	}
	detail, err := s.repo.GetDetailByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDetailNotFound
		}
		return nil, fmt.Errorf("get user detail: %w", err)
	}
	return detail, nil
}

// UpdateDetail updates a user's detail record.
func (s *Service) UpdateDetail(ctx context.Context, detail *UserDetail) error {
	detail.UpdatedAt = time.Now()
	if err := s.repo.UpdateDetail(ctx, detail); err != nil {
		return fmt.Errorf("update user detail: %w", err)
	}
	return nil
}

// UpsertDetail applies UpdateDetailRequest to a user's detail record.
//
// Creates the row if missing — Create() seeds one but legacy users may not
// have one yet. Pointer fields are treated as patch semantics: nil leaves
// the existing value untouched; explicit "" clears the field.
func (s *Service) UpsertDetail(ctx context.Context, userID int64, req *UpdateDetailRequest) (*UserDetail, error) {
	if _, err := s.repo.GetByID(ctx, userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	detail, err := s.repo.GetDetailByUserID(ctx, userID)
	created := false
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("get user detail: %w", err)
		}
		now := time.Now()
		detail = &UserDetail{
			ID:        s.idGen.Generate(),
			UserID:    userID,
			CreatedAt: now,
			UpdatedAt: now,
		}
		created = true
	}

	if req.Gender != nil {
		detail.Gender = req.Gender
	}
	if req.Birthday != nil {
		v := *req.Birthday
		if v == "" {
			detail.Birthday = nil
		} else {
			detail.Birthday = &v
		}
	}
	if req.Address != nil {
		v := *req.Address
		if v == "" {
			detail.Address = nil
		} else {
			detail.Address = &v
		}
	}
	if req.EmployeeNo != nil {
		v := *req.EmployeeNo
		if v == "" {
			detail.EmployeeNo = nil
		} else {
			detail.EmployeeNo = &v
		}
	}
	if req.JobTitle != nil {
		v := *req.JobTitle
		if v == "" {
			detail.JobTitle = nil
		} else {
			detail.JobTitle = &v
		}
	}
	if req.Department != nil {
		v := *req.Department
		if v == "" {
			detail.Department = nil
		} else {
			detail.Department = &v
		}
	}
	detail.UpdatedAt = time.Now()

	if created {
		if err := s.repo.CreateDetail(ctx, detail); err != nil {
			return nil, fmt.Errorf("create user detail: %w", err)
		}
	} else {
		if err := s.repo.UpdateDetail(ctx, detail); err != nil {
			return nil, fmt.Errorf("update user detail: %w", err)
		}
	}
	return detail, nil
}

// UnbindIdentity removes a third-party identity binding for a user.
// Returns ErrIdentityNotFound when the row does not exist (or belongs to
// another user — the repo query is scoped to both ids).
func (s *Service) UnbindIdentity(ctx context.Context, userID, identityID int64) error {
	if err := s.repo.DeleteIdentity(ctx, userID, identityID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrIdentityNotFound
		}
		return fmt.Errorf("delete identity: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": userID, "action": "identity_unbound", "identity_id": identityID},
	})
	return nil
}

// LockUser locks a user account (admin action), recording the reason in the
// emitted UserLocked event. Independent of the auto-lockout flow (which is
// driven by failed-login counters) so audit can distinguish admin actions
// from policy-driven lockouts.
func (s *Service) LockUser(ctx context.Context, id int64, reason string, actorID int64) error {
	if err := s.repo.UpdateStatus(ctx, id, StatusLocked); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("lock user: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: event.UserLocked,
		Payload: map[string]any{
			"user_id":  id,
			"reason":   reason,
			"source":   "admin",
			"actor_id": actorID,
		},
	})
	return nil
}

// UnlockUser flips a locked account back to active. Also clears the
// failed-login counter so the user can log in immediately without waiting
// for the lockout window to elapse.
func (s *Service) UnlockUser(ctx context.Context, id int64, actorID int64) error {
	if err := s.repo.UpdateStatus(ctx, id, StatusActive); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("unlock user: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: event.UserUnlocked,
		Payload: map[string]any{
			"user_id":  id,
			"source":   "admin",
			"actor_id": actorID,
		},
	})
	return nil
}

// BatchAction applies a single admin action to a set of users. Errors are
// accumulated per-user — one failing ID does not abort the others. Treats
// the operation as best-effort: returns nil error overall but a populated
// errors slice so the caller can show "5 succeeded, 2 failed: ..." in the UI.
func (s *Service) BatchAction(ctx context.Context, ids []int64, action BatchAction, actorID int64) (*BatchUsersResponse, error) {
	resp := &BatchUsersResponse{Errors: []BatchItemError{}}
	for _, id := range ids {
		var err error
		switch action {
		case BatchActionEnable:
			err = s.UpdateStatus(ctx, id, StatusActive)
		case BatchActionDisable:
			err = s.UpdateStatus(ctx, id, StatusDisabled)
		case BatchActionDelete:
			err = s.Delete(ctx, id)
		default:
			return nil, fmt.Errorf("unknown batch action: %s", action)
		}
		if err != nil {
			resp.Errors = append(resp.Errors, BatchItemError{ID: id, Error: err.Error()})
			continue
		}
		resp.Affected++
	}
	if actorID != 0 {
		s.eventBus.Publish(ctx, event.Event{
			Type: event.UserUpdated,
			Payload: map[string]any{
				"action":   "batch_" + string(action),
				"actor_id": actorID,
				"affected": resp.Affected,
				"failed":   len(resp.Errors),
			},
		})
	}
	return resp, nil
}

// DeleteMFA force-removes an MFA factor for a user. Admin operation; bypasses
// the self-service flow that requires the user to verify a code first.
func (s *Service) DeleteMFA(ctx context.Context, userID int64, mfaType string) error {
	if err := s.requireUser(ctx, userID); err != nil {
		return err
	}
	if err := s.repo.DeleteMFA(ctx, userID, mfaType); err != nil {
		return fmt.Errorf("delete mfa: %w", err)
	}
	// Removing TOTP nukes the backup codes too — leaving stale codes alive
	// after the factor is gone is a silent way to weaken the account's
	// security posture.
	if mfaType == MFATypeTotp {
		_ = s.DeleteBackupCodes(ctx, userID)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.UserUpdated,
		Payload: map[string]any{"user_id": userID, "action": "mfa_removed", "type": mfaType},
	})
	return nil
}

// ListIdentities returns all identity bindings for a user.
//
// Returns an empty (non-nil) slice when the user has no bindings so JSON
// encoders emit `[]` instead of `null` — keeps frontend list rendering free
// of nil-guards.
func (s *Service) ListIdentities(ctx context.Context, userID int64) ([]*UserIdentity, error) {
	identities, err := s.repo.ListIdentities(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}
	if identities == nil {
		identities = []*UserIdentity{}
	}
	return identities, nil
}

// ListMFA returns all MFA configurations for a user.
//
// Returns an empty (non-nil) slice when the user has not enrolled any factor.
func (s *Service) ListMFA(ctx context.Context, userID int64) ([]*UserMFA, error) {
	if err := s.requireUser(ctx, userID); err != nil {
		return nil, err
	}
	mfas, err := s.repo.ListMFA(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list mfa: %w", err)
	}
	if mfas == nil {
		mfas = []*UserMFA{}
	}
	return mfas, nil
}

// checkPasswordHistory verifies the new password hasn't been used recently.
func (s *Service) checkPasswordHistory(ctx context.Context, userID int64, newPassword string) error {
	// Use runtime policy so admins can tighten/loosen history via DB.
	// Tenant ID is looked up from the user; cheap because the caller
	// already loaded it just above us. We re-fetch here to keep the
	// helper self-contained.
	u, _ := s.repo.GetByID(ctx, userID)
	tid := int64(0)
	if u != nil {
		tid = u.TenantID
	}
	historyCount := s.activePasswordPolicy(ctx, tid).HistoryCount
	if historyCount <= 0 {
		return nil
	}

	history, err := s.repo.GetPasswordHistory(ctx, userID, historyCount)
	if err != nil {
		return fmt.Errorf("get password history: %w", err)
	}

	for _, h := range history {
		if crypto.CheckPassword(newPassword, h.PasswordHash) {
			return ErrPasswordReused
		}
	}

	return nil
}
