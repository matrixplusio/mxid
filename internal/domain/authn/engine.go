package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/redis/go-redis/v9"
)

// Engine errors.
var (
	ErrUnknownProvider = errors.New("unknown authentication provider")
	ErrAuthFailed      = errors.New("authentication failed")
	ErrAccountLocked   = errors.New("account is locked")
	ErrAccountDisabled = errors.New("account is disabled")
	ErrPasswordExpired = errors.New("password has expired")
	ErrMFARequired     = errors.New("mfa verification required")
	ErrSessionNotFound = errors.New("session not found")
)

// LoginResponse is returned by Engine.Login.
//
// Two terminal shapes:
//
//   - Success: SessionID populated; MFARequired=false. Caller sets session cookie.
//   - MFA required: SessionID empty; MFARequired=true with Challenge + MFAMethods.
//     Caller surfaces Challenge to the client; client POSTs it back to
//     /auth/mfa/verify together with the TOTP code.
type LoginResponse struct {
	UserID      int64    `json:"user_id,string,omitempty"`
	TenantID    int64    `json:"tenant_id,string,omitempty"`
	Username    string   `json:"username,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	MFARequired bool     `json:"mfa_required,omitempty"`
	MFAMethods  []string `json:"mfa_methods,omitempty"`
	Challenge   string   `json:"challenge,omitempty"`
}

// LoginRecorder persists each login attempt for audit. Implementations live
// outside the authn package (user domain) — the engine only depends on the
// minimal interface to avoid an import cycle.
type LoginRecorder interface {
	RecordAttempt(ctx context.Context, attempt LoginAttempt)
}

// LoginAttempt is the data engine hands to LoginRecorder for each attempt.
type LoginAttempt struct {
	TenantID  int64
	UserID    int64
	Username  string
	Success   bool
	Stage     string // "password" or "mfa"
	AuthType  string
	Reason    string
	IP        string
	UserAgent string
}

// Engine orchestrates authentication across multiple providers.
// LoginPolicyProvider returns the runtime login policy for a tenant
// (max_failed_attempts / lockout_duration). Implementations read from
// setting.Service and fall back to the YAML LoginConfig defaults; nil
// keeps the engine on YAML.
type LoginPolicyProvider func(ctx context.Context, tenantID int64) (maxFailedAttempts int, lockoutDuration time.Duration)

type Engine struct {
	providers      map[string]Provider
	sessionMgr     *session.Manager
	eventBus       *event.Bus
	idGen          *snowflake.Generator
	loginConfig    *bootstrap.LoginConfig
	loginPolicy    LoginPolicyProvider
	userRepo       UserQuerier
	rdb            *redis.Client
	mfaVerifier    MFAVerifier
	mfaRateLimiter *MFARateLimiter
	loginRecorder  LoginRecorder
	loginLimiter   *ratelimit.Limiter
}

// SetLoginLimiter wires the brute-force limiter that backs the password
// login path (per-IP + per-user). When nil the engine falls back to its
// legacy per-user Redis counter (tests without redis). Called by main.go.
func (e *Engine) SetLoginLimiter(l *ratelimit.Limiter) { e.loginLimiter = l }

// SetLoginPolicyProvider injects the runtime policy lookup. Called by
// main.go after the setting service is built; nil keeps engine on YAML.
func (e *Engine) SetLoginPolicyProvider(p LoginPolicyProvider) { e.loginPolicy = p }

// NewEngine creates a new authentication engine.
func NewEngine(
	sessionMgr *session.Manager,
	eventBus *event.Bus,
	idGen *snowflake.Generator,
	loginConfig *bootstrap.LoginConfig,
	userRepo UserQuerier,
	rdb *redis.Client,
) *Engine {
	return &Engine{
		providers:      make(map[string]Provider),
		sessionMgr:     sessionMgr,
		eventBus:       eventBus,
		idGen:          idGen,
		loginConfig:    loginConfig,
		userRepo:       userRepo,
		rdb:            rdb,
		mfaRateLimiter: NewMFARateLimiter(rdb),
	}
}

// MFARateLimiter exposes the shared rate limiter so handlers (security
// enrollment verify) can plug into the same counters the login challenge
// uses. Nil when redis isn't wired (tests).
func (e *Engine) MFARateLimiter() *MFARateLimiter { return e.mfaRateLimiter }

// SetMFAVerifier wires the MFA factor verifier. Called by Register after the
// user module is built; nil mfaVerifier disables the second-factor step
// (used in tests; production must always set it).
func (e *Engine) SetMFAVerifier(v MFAVerifier) {
	e.mfaVerifier = v
}

// SetLoginRecorder wires the audit recorder. Nil disables login-record
// persistence (event bus events still fire). Called by Register after the
// user module is built.
func (e *Engine) SetLoginRecorder(r LoginRecorder) {
	e.loginRecorder = r
}

// RegisterProvider adds an authentication provider.
func (e *Engine) RegisterProvider(p Provider) {
	e.providers[p.Type()] = p
}

// Login performs authentication and creates a session on success.
func (e *Engine) Login(ctx context.Context, req *AuthRequest, namespace string) (*LoginResponse, error) {
	provider, ok := e.providers[req.AuthType]
	if !ok {
		return nil, ErrUnknownProvider
	}

	// Login runs BEFORE any session exists, so the request context carries no
	// tenant scope. The target tenant is resolved explicitly upstream
	// (effectiveTenant -> req.TenantID); pin it onto the context so the gorm
	// tenant-isolation plugin can scope the user lookups (GetByUsername/Email/
	// Phone) instead of failing closed.
	if req.TenantID > 0 {
		ctx = tenantscope.WithTenant(ctx, req.TenantID)
	}

	// Brute-force gate (pre-auth, IP-scoped): if this client IP has already
	// tripped the limiter, reject before spending a bcrypt compare. The
	// per-user dimension is checked post-auth (we don't know the userID yet
	// for a username that may not exist — keeping the pre-auth check IP-only
	// also avoids leaking which usernames are locked).
	if err := e.checkLoginLock(ctx, 0, req.ClientIP); err != nil {
		return nil, err
	}

	result, err := provider.Authenticate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	switch result.Status {
	case AuthFailed:
		// Track failure count
		if result.UserID > 0 {
			e.trackFailure(ctx, result.UserID, req)
		}
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrAuthFailed

	case AuthLocked:
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrAccountLocked

	case AuthDisabled:
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrAccountDisabled

	case AuthPasswordExpired:
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrPasswordExpired

	case AuthMFARequired:
		// Return without creating a session; MFA step needed
		return nil, ErrMFARequired

	case AuthSuccess:
		// Clear failure count (both per-user and per-IP) so a legitimate
		// login relieves the brute-force budget it may have nudged via typos.
		if result.UserID > 0 {
			e.clearFailureCountIP(ctx, result.UserID, req.ClientIP)
		}

		// MFA gate: if the user has a verified TOTP factor, password-success
		// does NOT yet grant a session. Mint a single-use challenge token,
		// hand it to the client, and wait for /auth/mfa/verify to call
		// VerifyMFAChallenge with the second factor.
		if e.mfaVerifier != nil {
			hasTOTP, mfaErr := e.mfaVerifier.HasVerifiedTOTP(ctx, result.UserID)
			if mfaErr != nil {
				return nil, fmt.Errorf("check mfa: %w", mfaErr)
			}
			if hasTOTP {
				challenge, err := e.issueMFAChallenge(ctx, &mfaChallengePayload{
					UserID:      result.UserID,
					TenantID:    req.TenantID,
					Username:    result.Username,
					DisplayName: result.DisplayName,
					AuthType:    req.AuthType,
					Namespace:   namespace,
					ClientIP:    req.ClientIP,
					UserAgent:   req.UserAgent,
				})
				if err != nil {
					return nil, fmt.Errorf("issue mfa challenge: %w", err)
				}
				return &LoginResponse{
					UserID:      result.UserID,
					TenantID:    req.TenantID,
					Username:    result.Username,
					DisplayName: result.DisplayName,
					MFARequired: true,
					MFAMethods:  []string{"totp"},
					Challenge:   challenge,
				}, nil
			}
		}

		return e.completeLogin(ctx, namespace, req, result, "password")

	default:
		return nil, ErrAuthFailed
	}
}

// completeLogin issues the session that ends a successful login (first factor
// only, or both factors when MFA is in play). Updates last-login, mints the
// session row, publishes the success event, and returns the response shape
// the handler expects.
//
// stage records which step finalised the login ("password" for no-MFA users,
// "mfa" for users who went through the challenge).
func (e *Engine) completeLogin(ctx context.Context, namespace string, req *AuthRequest, result *AuthResult, stage string) (*LoginResponse, error) {
	_ = e.userRepo.UpdateLastLogin(ctx, result.UserID, req.ClientIP)

	sess, err := e.sessionMgr.Create(
		ctx, namespace,
		result.UserID, req.TenantID,
		req.ClientIP, req.UserAgent, req.AuthType,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	e.publishLoginEvent(ctx, result, req, true, stage)

	return &LoginResponse{
		UserID:      result.UserID,
		TenantID:    req.TenantID,
		Username:    result.Username,
		DisplayName: result.DisplayName,
		SessionID:   sess.ID,
	}, nil
}

// VerifyMFAChallenge validates the TOTP code submitted against a pending
// challenge token. On success, consumes the token (single-use) and creates
// the namespace session that Login deferred. The returned LoginResponse
// mirrors the password-only success shape so the caller can finalize cookies
// the same way.
//
// The original client IP/User-Agent captured at password verification are
// reused for the session record, NOT the values from the MFA-verify request.
// Rationale: the session belongs to the device that started the login —
// consistent audit signals matter more here than the transport endpoint.
// HasMFA reports whether the user has a verified MFA factor enrolled. Used by
// step-up enforcement to choose between challenging an enrolled user and
// demanding enrollment from one who has none.
func (e *Engine) HasMFA(ctx context.Context, userID int64) (bool, error) {
	if e.mfaVerifier == nil {
		return false, nil
	}
	return e.mfaVerifier.HasVerifiedTOTP(ctx, userID)
}

// VerifyStepUp validates a TOTP (or backup) code for an ALREADY-authenticated
// user performing a high-risk operation. Unlike VerifyMFAChallenge there is no
// login challenge token — the caller already holds a live session. Rate-limited
// per user+IP. Returns nil on success, ErrMFAVerifyFailed on a bad code,
// ErrMFANotConfigured / ErrMFARateLimited otherwise.
func (e *Engine) VerifyStepUp(ctx context.Context, userID int64, clientIP, code string) error {
	if e.mfaVerifier == nil {
		return ErrMFANotConfigured
	}
	if err := e.mfaRateLimiter.Check(ctx, userID, clientIP); err != nil {
		return err
	}
	verifyErr := e.mfaVerifier.VerifyTOTP(ctx, userID, code)
	if verifyErr != nil && looksLikeBackupCode(code) {
		if err := e.mfaVerifier.ConsumeBackupCode(ctx, userID, code); err == nil {
			verifyErr = nil
		}
	}
	if verifyErr != nil {
		e.mfaRateLimiter.RecordFailure(ctx, userID, clientIP)
		return ErrMFAVerifyFailed
	}
	e.mfaRateLimiter.Reset(ctx, userID, clientIP)
	return nil
}

func (e *Engine) VerifyMFAChallenge(ctx context.Context, challenge, code string) (*LoginResponse, error) {
	if e.mfaVerifier == nil {
		return nil, ErrMFANotConfigured
	}
	payload, err := e.consumeMFAChallenge(ctx, challenge)
	if err != nil {
		return nil, err
	}

	// Second-factor verification also runs pre-session; pin the challenge's
	// tenant so downstream user/MFA repo reads are tenant-scoped.
	if payload.TenantID > 0 {
		ctx = tenantscope.WithTenant(ctx, payload.TenantID)
	}

	if err := e.mfaRateLimiter.Check(ctx, payload.UserID, payload.ClientIP); err != nil {
		return nil, err
	}

	// Accept TOTP code OR backup code. We check TOTP first because it's
	// the dominant case; only fall through to backup-code consumption when
	// the format unambiguously rules TOTP out (contains a hyphen or has
	// alpha chars). This keeps the fast path fast and avoids burning a
	// backup code on a typo'd TOTP digit.
	verifyErr := e.mfaVerifier.VerifyTOTP(ctx, payload.UserID, code)
	if verifyErr != nil && looksLikeBackupCode(code) {
		if err := e.mfaVerifier.ConsumeBackupCode(ctx, payload.UserID, code); err == nil {
			verifyErr = nil
		}
	}
	if verifyErr != nil {
		e.mfaRateLimiter.RecordFailure(ctx, payload.UserID, payload.ClientIP)
		err := verifyErr
		// Token already consumed; client must restart login. We do NOT
		// fold MFA failures into the password lockout counter — the
		// password was already valid and the challenge TTL caps brute
		// force. A dedicated MFA-attempt counter is a future hardening step.
		e.eventBus.Publish(ctx, event.Event{
			Type: event.LoginFailed,
			Payload: map[string]any{
				"user_id":    payload.UserID,
				"username":   payload.Username,
				"auth_type":  payload.AuthType,
				"ip":         payload.ClientIP,
				"user_agent": payload.UserAgent,
				"tenant_id":  payload.TenantID,
				"stage":      "mfa",
				"reason":     err.Error(),
				"success":    false,
			},
		})
		if e.loginRecorder != nil {
			e.loginRecorder.RecordAttempt(ctx, LoginAttempt{
				TenantID:  payload.TenantID,
				UserID:    payload.UserID,
				Username:  payload.Username,
				Success:   false,
				Stage:     "mfa",
				AuthType:  payload.AuthType,
				Reason:    err.Error(),
				IP:        payload.ClientIP,
				UserAgent: payload.UserAgent,
			})
		}
		return nil, ErrMFAVerifyFailed
	}

	// Code accepted — wipe both per-user and per-IP fail counters so the
	// user isn't penalised for a typo earlier in the session.
	e.mfaRateLimiter.Reset(ctx, payload.UserID, payload.ClientIP)

	authReq := &AuthRequest{
		TenantID:  payload.TenantID,
		AuthType:  payload.AuthType,
		ClientIP:  payload.ClientIP,
		UserAgent: payload.UserAgent,
	}
	result := &AuthResult{
		UserID:      payload.UserID,
		Username:    payload.Username,
		DisplayName: payload.DisplayName,
		Status:      AuthSuccess,
	}
	return e.completeLogin(ctx, payload.Namespace, authReq, result, "mfa")
}

// Logout deletes a session. meta carries the request context (ip, user agent,
// tenant) so the audit row is complete — without it the logout event records
// only a user_id and the console shows blank actor / IP columns.
func (e *Engine) Logout(ctx context.Context, namespace, sessionID string, userID int64, meta LogoutMeta) error {
	if err := e.sessionMgr.Delete(ctx, namespace, sessionID); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	e.eventBus.Publish(ctx, event.Event{
		Type: event.Logout,
		Payload: map[string]any{
			"user_id":    userID,
			"session_id": sessionID,
			"tenant_id":  meta.TenantID,
			"ip":         meta.IP,
			"user_agent": meta.UserAgent,
		},
	})

	return nil
}

// LogoutMeta carries request-scoped context for the logout audit row.
type LogoutMeta struct {
	TenantID  int64
	IP        string
	UserAgent string
}

// GetSession retrieves and validates a session.
func (e *Engine) GetSession(ctx context.Context, namespace, sessionID string) (*session.Session, error) {
	sess, err := e.sessionMgr.Get(ctx, namespace, sessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	if sess == nil {
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

// GetCurrentUser returns user info for a session.
func (e *Engine) GetCurrentUser(ctx context.Context, userID int64) (*UserInfo, error) {
	return e.userRepo.GetByID(ctx, userID)
}

// failCountKey returns the legacy Redis key for tracking login failures.
// Retained for the fallback path when no loginLimiter is wired (tests).
func (e *Engine) failCountKey(userID int64) string {
	return "mxid:login_fail:" + strconv.FormatInt(userID, 10)
}

// loginIdentifiers builds the per-user and per-IP identifiers the brute-force
// limiter keys on. Empty parts are omitted so a missing IP (test) or pre-auth
// userID=0 simply narrows the scope rather than poisoning a shared key.
func loginIdentifiers(userID int64, clientIP string) []string {
	ids := make([]string, 0, 2)
	if userID > 0 {
		ids = append(ids, "u:"+strconv.FormatInt(userID, 10))
	}
	if clientIP != "" {
		ids = append(ids, "ip:"+clientIP)
	}
	return ids
}

// checkLoginLock reports whether the (user, ip) pair is currently locked by
// the brute-force limiter, returning ErrAccountLocked (with the limiter's
// RateLimitError as cause, so the handler can surface Retry-After). userID may
// be 0 pre-auth (IP-only check). nil limiter = no lock (legacy path).
func (e *Engine) checkLoginLock(ctx context.Context, userID int64, clientIP string) error {
	if e.loginLimiter == nil {
		return nil
	}
	ids := loginIdentifiers(userID, clientIP)
	if len(ids) == 0 {
		return nil
	}
	if err := e.loginLimiter.CheckMany(ctx, ids...); err != nil {
		return fmt.Errorf("%w: %w", ErrAccountLocked, err)
	}
	return nil
}

// LoginFailureCount returns the current brute-force failure count for the
// given IP (and optionally user). Used by the handler to enforce
// CaptchaAfterFailures: captcha is demanded only once an identifier has
// crossed the policy threshold. Returns 0 when no limiter is wired.
func (e *Engine) LoginFailureCount(ctx context.Context, clientIP string) int {
	if e.loginLimiter == nil {
		return 0
	}
	return e.loginLimiter.FailureCount(ctx, "ip:"+clientIP)
}

// trackFailure records a failed login against the brute-force limiter
// (per-user + per-IP, auto-expiring lock) and emits UserLocked when the
// threshold is crossed. It NO LONGER flips mxid_user.status — that permanent
// DB lock is reserved for admin LockUser. The Redis lock self-heals when its
// TTL elapses, so a brute-forced victim is not stranded until an admin
// intervenes, while the per-IP dimension also throttles a scripted scan.
func (e *Engine) trackFailure(ctx context.Context, userID int64, req *AuthRequest) {
	if e.loginLimiter == nil {
		// Legacy fallback (no limiter wired, e.g. tests): keep a per-user
		// counter but DO NOT flip account status — auto-lock is Redis-only now.
		e.trackFailureLegacy(ctx, userID, req)
		return
	}
	ids := loginIdentifiers(userID, req.ClientIP)
	if len(ids) == 0 {
		return
	}
	// Read the pre-increment lock state so we only emit UserLocked on the
	// transition (this failure is the one that trips it), not on every
	// subsequent attempt while already locked.
	alreadyLocked := e.loginLimiter.CheckMany(ctx, ids...) != nil
	tripped := e.loginLimiter.RecordFailureMany(ctx, ids...)
	if tripped != nil && !alreadyLocked {
		e.eventBus.Publish(ctx, event.Event{
			Type: event.UserLocked,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  "max_failed_attempts",
				"ip":      req.ClientIP,
			},
		})
	}
}

// trackFailureLegacy is the pre-limiter per-user counter, kept for the
// no-redis-limiter path. It records the failure and emits UserLocked at the
// threshold but never touches mxid_user.status (no permanent auto-lock).
func (e *Engine) trackFailureLegacy(ctx context.Context, userID int64, req *AuthRequest) {
	if e.rdb == nil {
		return
	}
	key := e.failCountKey(userID)
	count, err := e.rdb.Incr(ctx, key).Result()
	if err != nil {
		return
	}
	maxAttempts := e.loginConfig.MaxFailedAttempts
	lockout := e.loginConfig.LockoutDuration
	if e.loginPolicy != nil {
		if m, d := e.loginPolicy(ctx, req.TenantID); m > 0 {
			maxAttempts = m
			lockout = d
		}
	}
	if count == 1 {
		e.rdb.Expire(ctx, key, lockout)
	}
	maxAttemptsI64 := int64(maxAttempts)
	if maxAttemptsI64 > 0 && count == maxAttemptsI64 {
		e.eventBus.Publish(ctx, event.Event{
			Type: event.UserLocked,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  "max_failed_attempts",
				"ip":      req.ClientIP,
			},
		})
	}
}

// clearFailureCount removes all brute-force failure state after a successful
// login — both the new limiter keys (per-user + per-IP) and the legacy
// per-user counter.
func (e *Engine) clearFailureCount(ctx context.Context, userID int64) {
	e.clearFailureCountIP(ctx, userID, "")
}

// clearFailureCountIP clears the limiter keys for the user AND the supplied IP
// (so a legitimate login also relieves the per-IP budget), plus the legacy
// per-user counter.
func (e *Engine) clearFailureCountIP(ctx context.Context, userID int64, clientIP string) {
	if e.loginLimiter != nil {
		e.loginLimiter.ResetMany(ctx, loginIdentifiers(userID, clientIP)...)
	}
	if e.rdb != nil {
		e.rdb.Del(ctx, e.failCountKey(userID))
	}
}

// publishLoginEvent emits a login success or failure event AND persists a
// login record for audit. The two paths are independent — event subscribers
// can do live notifications (slack, security tooling) while the record
// table backs the per-user history view in the console.
//
// stage is "password" for first-factor attempts and "mfa" for second-factor
// verification calls. Callers default to "password" by passing "".
func (e *Engine) publishLoginEvent(ctx context.Context, result *AuthResult, req *AuthRequest, success bool, stage ...string) {
	stageStr := "password"
	if len(stage) > 0 && stage[0] != "" {
		stageStr = stage[0]
	}
	eventType := event.LoginFailed
	if success {
		eventType = event.LoginSuccess
	}

	payload := map[string]any{
		"user_id":   result.UserID,
		"username":  result.Username,
		"auth_type": req.AuthType,
		"ip":        req.ClientIP,
		"user_agent": req.UserAgent,
		"tenant_id": req.TenantID,
		"success":   success,
	}

	reason := ""
	if !success {
		payload["failure_status"] = int(result.Status)
		switch result.Status {
		case AuthFailed:
			reason = "invalid credentials"
		case AuthLocked:
			reason = "account locked"
		case AuthDisabled:
			reason = "account disabled"
		case AuthPasswordExpired:
			reason = "password expired"
		case AuthMFARequired:
			reason = "mfa required"
		}
		// Carry the reason into the audit detail too — previously it was only
		// fed to the login recorder, leaving every login.failed audit row with
		// a blank reason (can't tell "account disabled" from "wrong password").
		payload["reason"] = reason
	}

	e.eventBus.Publish(ctx, event.Event{
		Type:    eventType,
		Payload: payload,
	})

	if e.loginRecorder != nil {
		e.loginRecorder.RecordAttempt(ctx, LoginAttempt{
			TenantID:  req.TenantID,
			UserID:    result.UserID,
			Username:  result.Username,
			Success:   success,
			Stage:     stageStr,
			AuthType:  req.AuthType,
			Reason:    reason,
			IP:        req.ClientIP,
			UserAgent: req.UserAgent,
		})
	}
}

// SessionManager returns the underlying session manager (for middleware use).
func (e *Engine) SessionManager() *session.Manager {
	return e.sessionMgr
}

