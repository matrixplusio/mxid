package authn

import (
	"context"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
)

const LocalProviderType = "local"

// dummyPasswordHash is a real bcrypt hash burned on every credential-rejecting
// branch that doesn't otherwise run bcrypt — unknown username, disabled/locked/
// unknown status — so those paths take ~the same wall-clock time as a genuine
// password compare. Without it, an unknown username returns AuthFailed in
// microseconds while a valid one spends tens of ms in bcrypt, a measurable
// user-enumeration oracle (OWASP A07).
//
// It is generated via crypto.HashPassword so its cost ALWAYS tracks production
// password hashes: raising the password work factor must not desync this
// equalizer, or the timing oracle reopens (the fallback is a precomputed hash at
// the SAME cost for exactly that reason).
var dummyPasswordHash = func() string {
	h, err := crypto.HashPassword("mxid-enumeration-equalizer")
	if err != nil {
		return "$2a$12$5DCDajeTw8u.sNQn/.WLVOqZwu1HueIB0JWn61YNqHUiU9YfH3ida"
	}
	return h
}()

// burnDummyCompare runs a constant-cost bcrypt compare against a fixed hash
// and discards the result. Callers invoke it on the no-bcrypt rejection
// branches so an attacker can't distinguish "unknown user" / "disabled" from
// "wrong password" by response timing.
func burnDummyCompare(password string) {
	_ = crypto.CheckPassword(password, dummyPasswordHash)
}

// User status constants, mirrored to avoid importing the user package.
const (
	statusActive   = 1
	statusLocked   = 2
	statusDisabled = 3
)

// LocalProvider authenticates users via username and password stored locally.
type LocalProvider struct {
	userRepo       UserAuthQuerier
	passwordExpiry int // days; 0 means no expiry
}

// NewLocalProvider creates a local authentication provider.
func NewLocalProvider(userRepo UserAuthQuerier, passwordExpiryDays int) *LocalProvider {
	return &LocalProvider{
		userRepo:       userRepo,
		passwordExpiry: passwordExpiryDays,
	}
}

// Type returns the provider identifier.
func (p *LocalProvider) Type() string {
	return LocalProviderType
}

// Authenticate verifies a username/password credential pair.
func (p *LocalProvider) Authenticate(ctx context.Context, req *AuthRequest) (*AuthResult, error) {
	username := req.Credentials["username"]
	password := req.Credentials["password"]
	if username == "" || password == "" {
		return &AuthResult{Status: AuthFailed}, nil
	}

	u, err := p.userRepo.GetByUsername(ctx, req.TenantID, username)
	if err != nil {
		// Unknown user: burn an equivalent bcrypt compare so this path takes
		// the same time as a real one (anti-enumeration). Uniform AuthFailed.
		burnDummyCompare(password)
		return &AuthResult{Status: AuthFailed}, nil
	}

	// Check account status. The locked/default branches short-circuit before
	// the real password compare, so each burns a dummy bcrypt first to keep
	// account-state from leaking via response timing.
	//
	// statusDisabled is the exception: it does NOT short-circuit here. A
	// disabled account is indistinguishable from a wrong password to anyone who
	// doesn't already know the password (both burn one bcrypt and return
	// AuthFailed below) — but a caller who supplies the CORRECT password has
	// proven ownership, so we tell them the truth ("account disabled") instead
	// of the misleading "wrong password". This fixes offboarded users being
	// told their (correct) password is wrong, without leaking which accounts
	// exist or are disabled.
	switch u.Status {
	case statusLocked:
		burnDummyCompare(password)
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthLocked,
		}, nil
	case statusActive, statusDisabled:
		// proceed to password verification
	default:
		burnDummyCompare(password)
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthFailed,
		}, nil
	}

	// Verify password
	if !crypto.CheckPassword(password, u.PasswordHash) {
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthFailed,
		}, nil
	}

	// Password verified. Reveal a disabled account only now — the caller proved
	// ownership, so this discloses nothing to an attacker guessing usernames.
	if u.Status == statusDisabled {
		return &AuthResult{
			UserID:   u.ID,
			Username: u.Username,
			Status:   AuthDisabled,
		}, nil
	}

	// Check password expiry
	if p.passwordExpiry > 0 && u.PasswordChangedAt != nil {
		expiry := u.PasswordChangedAt.Add(time.Duration(p.passwordExpiry) * 24 * time.Hour)
		if time.Now().After(expiry) {
			return &AuthResult{
				UserID:      u.ID,
				Username:    u.Username,
				DisplayName: u.DisplayName,
				Status:      AuthPasswordExpired,
			}, nil
		}
	}

	return &AuthResult{
		UserID:      u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Status:      AuthSuccess,
	}, nil
}

// Ensure LocalProvider implements Provider at compile time.
var _ Provider = (*LocalProvider)(nil)

// authQuerierAdapter adapts a function into a UserAuthQuerier.
type authQuerierAdapter struct {
	fn func(ctx context.Context, tenantID int64, username string) (*UserAuth, error)
}

func (a *authQuerierAdapter) GetByUsername(ctx context.Context, tenantID int64, username string) (*UserAuth, error) {
	return a.fn(ctx, tenantID, username)
}

var _ UserAuthQuerier = (*authQuerierAdapter)(nil)

// userQuerierAdapter wraps functions into a UserQuerier.
type userQuerierAdapter struct {
	getByIDFn         func(ctx context.Context, id int64) (*UserInfo, error)
	updateLastLoginFn func(ctx context.Context, id int64, ip string) error
	updateStatusFn    func(ctx context.Context, id int64, status int) error
}

func (a *userQuerierAdapter) GetByID(ctx context.Context, id int64) (*UserInfo, error) {
	return a.getByIDFn(ctx, id)
}

func (a *userQuerierAdapter) UpdateLastLogin(ctx context.Context, id int64, ip string) error {
	return a.updateLastLoginFn(ctx, id, ip)
}

func (a *userQuerierAdapter) UpdateStatus(ctx context.Context, id int64, status int) error {
	return a.updateStatusFn(ctx, id, status)
}

var _ UserQuerier = (*userQuerierAdapter)(nil)

// BuildAuthQuerier creates a UserAuthQuerier from a function.
func BuildAuthQuerier(fn func(ctx context.Context, tenantID int64, username string) (*UserAuth, error)) UserAuthQuerier {
	return &authQuerierAdapter{fn: fn}
}

// BuildUserQuerier creates a UserQuerier from functions.
func BuildUserQuerier(
	getByID func(ctx context.Context, id int64) (*UserInfo, error),
	updateLastLogin func(ctx context.Context, id int64, ip string) error,
	updateStatus func(ctx context.Context, id int64, status int) error,
) UserQuerier {
	return &userQuerierAdapter{
		getByIDFn:         getByID,
		updateLastLoginFn: updateLastLogin,
		updateStatusFn:    updateStatus,
	}
}
