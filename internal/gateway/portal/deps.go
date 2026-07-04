package portal

import (
	"context"
	"time"
)

// UserInfo holds user data for portal display.
//
// ID is emitted as a JSON string to preserve int64 precision (Snowflake
// IDs exceed 2^53). See Twitter API v2 / Discord docs for the standard.
type UserInfo struct {
	ID            int64      `json:"id,string"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Phone         string     `json:"phone"`
	DisplayName   string     `json:"display_name"`
	Avatar        string     `json:"avatar"`
	Status        int        `json:"status"`
	LastLoginAt   *time.Time `json:"last_login_at"`
}

// UserDetail holds extended user details.
type UserDetail struct {
	Gender     *int    `json:"gender"`
	Birthday   *string `json:"birthday"`
	Address    *string `json:"address"`
	EmployeeNo *string `json:"employee_no"`
	JobTitle   *string `json:"job_title"`
	Department *string `json:"department"`
}

// AppInfo holds application data for portal app list.
//
// All ID-bearing fields use string serialization. `,string` covers scalar
// int64; for `[]int64` slices we change the storage type to `[]string`
// because Go's json tag does not propagate `,string` into slice elements.
// Adapters MUST format with strconv.FormatInt(id, 10).
type AppInfo struct {
	ID          int64    `json:"id,string"`
	Name        string   `json:"name"`
	Code        string   `json:"code"`
	Protocol    string   `json:"protocol"`
	ClientType  string   `json:"client_type"`
	Icon        string   `json:"icon"`
	LogoURL     string   `json:"logo_url"`
	Description string   `json:"description"`
	HomeURL     string   `json:"home_url"`
	LoginURL    string   `json:"login_url"`
	GroupIDs    []string `json:"group_ids"`
}

// AppGroupInfo is a single bucket shown in the portal sidebar.
// AppCount is computed against apps the requesting user can actually access,
// so the sidebar badge never overstates what the right pane will render.
type AppGroupInfo struct {
	ID        int64   `json:"id,string"`
	Name      string  `json:"name"`
	Code      string  `json:"code"`
	ParentID  *string `json:"parent_id,omitempty"`
	SortOrder int     `json:"sort_order"`
	AppCount  int     `json:"app_count"`
}

// SessionInfo holds session data for portal display.
type SessionInfo struct {
	ID           string    `json:"id"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	AuthType     string    `json:"auth_type"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
}

// MFAInfo holds MFA enrollment info.
type MFAInfo struct {
	Type      string `json:"type"`
	IsDefault bool   `json:"is_default"`
	Verified  bool   `json:"verified"`
}

// IdentityInfo holds linked identity info.
type IdentityInfo struct {
	ProviderType string `json:"provider_type"`
	ProviderID   string `json:"provider_id"`
	ExternalName string `json:"external_name"`
}

// UserQuerier provides user data access for portal handlers.
type UserQuerier interface {
	GetByID(ctx context.Context, userID int64) (*UserInfo, error)
	GetDetail(ctx context.Context, userID int64) (*UserDetail, error)
	UpdateProfile(ctx context.Context, userID int64, displayName, phone, email string) error
	UpdateAvatar(ctx context.Context, userID int64, avatar string) error
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error
	// MarkEmailVerified flips the email_verified flag once the user has
	// clicked the verification link. Idempotent.
	MarkEmailVerified(ctx context.Context, userID int64) error
	// GetEmail returns the current email so the verification handler can
	// rebuild the link without re-fetching the full user row.
	GetEmail(ctx context.Context, userID int64) (string, error)
	// LookupByEmail returns the user_id matching (tenant, email). Returns
	// (0, nil) when no user is bound to that email — callers MUST NOT
	// surface this difference to the client (timing attack on enumeration).
	LookupByEmail(ctx context.Context, tenantID int64, email string) (int64, error)
	// ResetPassword sets a new password for the user. Used by the portal
	// password-reset handler after the recovery token is consumed. Implementations
	// must run the full password-policy + history checks (the user.Service
	// ResetPassword path already does this).
	ResetPassword(ctx context.Context, userID int64, newPassword string) error
	// LookupByPhone returns the user_id matching (tenant, phone). Used by
	// the SMS OTP login flow. (0, nil) on miss — no enumeration leak.
	LookupByPhone(ctx context.Context, tenantID int64, phone string) (int64, error)
}

// AppQuerier provides app data access for portal handlers.
type AppQuerier interface {
	// ListAuthorizedApps returns the user's accessible apps. `q` is an
	// optional case-insensitive substring filter on name/code/description;
	// empty string means no filter. Server-side filter is preferred over
	// client-side once N grows past a few hundred apps — the pg_trgm
	// index on mxid_app makes it cheap.
	ListAuthorizedApps(ctx context.Context, userID, tenantID int64, q string) ([]*AppInfo, error)
	GetAppLaunchURL(ctx context.Context, appID, userID int64) (string, error)
	// AppName returns an app's display name, used to label the app.launched
	// audit row so the trail reads "launched <name>" not a bare id.
	AppName(ctx context.Context, appID int64) (string, error)
	ListAuthorizedAppGroups(ctx context.Context, userID, tenantID int64) ([]*AppGroupInfo, error)
	ListFavoriteAppIDs(ctx context.Context, userID int64) ([]int64, error)
	AddFavorite(ctx context.Context, userID, tenantID, appID int64) error
	RemoveFavorite(ctx context.Context, userID, appID int64) error
	ReorderFavorites(ctx context.Context, userID int64, orderedAppIDs []int64) error
	ListRecentAppIDs(ctx context.Context, userID, tenantID int64, limit int) ([]int64, error)
}

// SessionQuerier provides session management for portal handlers.
type SessionQuerier interface {
	ListSessions(ctx context.Context, namespace string, userID int64) ([]*SessionInfo, error)
	// DeleteSession removes a single session, but ONLY if it belongs to userID
	// — the id is opaque, so without the owner check any portal user could
	// revoke another user's session by id. Not-owned is a secure no-op.
	DeleteSession(ctx context.Context, namespace, sessionID string, userID int64) error
	// DeleteAllByUserExcept invalidates every session for `userID` in the
	// given namespace except `exceptSID`. Used by change-password so the
	// caller's own session survives the global purge.
	DeleteAllByUserExcept(ctx context.Context, namespace string, userID int64, exceptSID string) error
}

// MFAQuerier provides MFA data access for portal handlers.
type MFAQuerier interface {
	ListMFA(ctx context.Context, userID int64) ([]*MFAInfo, error)
	SetupTOTP(ctx context.Context, userID int64) (secret, qrURL string, err error)
	VerifyTOTP(ctx context.Context, userID int64, code string) error
	DeleteTOTP(ctx context.Context, userID int64) error
	// GenerateBackupCodes returns 10 freshly minted plaintext recovery
	// codes (caller MUST surface them to the user exactly once). Only
	// bcrypt hashes persist server-side.
	GenerateBackupCodes(ctx context.Context, userID int64) ([]string, error)
	CountBackupCodes(ctx context.Context, userID int64) (int, error)
}

// IdentityQuerier provides identity binding for portal handlers.
type IdentityQuerier interface {
	ListIdentities(ctx context.Context, userID int64) ([]*IdentityInfo, error)
}

// LoginEvent is one row in the login-history list. EventType is the raw
// audit event ("login.success", "login.failed", "logout") so the SPA can
// pick the badge colour; Reason is the audit detail.reason for failed
// attempts so admins can spot patterns (e.g. wrong-password vs
// account-locked).
type LoginEvent struct {
	EventType string    `json:"event_type"`
	Success   bool      `json:"success"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginHistoryQuerier provides the per-user login history shown on the
// account page. Backed by the audit log so we don't duplicate state.
type LoginHistoryQuerier interface {
	ListLoginHistory(ctx context.Context, tenantID, userID int64, limit int) ([]*LoginEvent, error)
}

// APITokenInfo is the JSON shape returned to the SPA on list/create.
// Plaintext is set ONLY on create (one-shot); never on list.
type APITokenInfo struct {
	ID         int64      `json:"id,string"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedAt  time.Time  `json:"created_at"`
	Plaintext  string     `json:"plaintext,omitempty"`
}

// APITokenQuerier is the surface security_handler uses for the
// /security/api-tokens routes.
type APITokenQuerier interface {
	List(ctx context.Context, userID int64) ([]*APITokenInfo, error)
	Create(ctx context.Context, userID, tenantID int64, name string, scopes []string, expiresInDays int) (*APITokenInfo, error)
	Revoke(ctx context.Context, userID, tokenID int64) error
}
