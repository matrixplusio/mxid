package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Namespace prefixes for session isolation.
const (
	NamespaceConsole  = "mxid:session:console"
	NamespacePortal   = "mxid:session:portal"
	NamespaceProtocol = "mxid:session:protocol"
)

// Session represents an authenticated user session.
type Session struct {
	ID           string    `json:"id"`
	UserID       int64     `json:"user_id"`
	TenantID     int64     `json:"tenant_id"`
	Namespace    string    `json:"namespace"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	AuthType     string    `json:"auth_type"`
	MFAVerified  bool      `json:"mfa_verified"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	// MFAVerifiedAt is the last time the user passed a multi-factor check on
	// THIS session — set at MFA login and refreshed by a step-up challenge.
	// nil means never. Step-up enforcement compares it against the configured
	// grace window to decide whether a high-risk operation needs a fresh MFA.
	MFAVerifiedAt *time.Time `json:"mfa_verified_at,omitempty"`
	// MFAEnrollPending is true when the MFA policy requires this user to hold a
	// factor but they have none — the session is blocked from everything except
	// MFA enrollment until they bind one. Cleared automatically once a factor
	// is detected.
	MFAEnrollPending bool `json:"mfa_enroll_pending,omitempty"`
}

// StepUpFresh reports whether this session passed MFA within `window` of now —
// i.e. a high-risk operation may proceed without a new step-up challenge.
// A nil MFAVerifiedAt (never verified) is never fresh. A non-positive window
// disables the grace period, forcing a challenge on every high-risk call.
func (s *Session) StepUpFresh(now time.Time, window time.Duration) bool {
	if s.MFAVerifiedAt == nil || window <= 0 {
		return false
	}
	return now.Before(s.MFAVerifiedAt.Add(window))
}

// PolicyProvider returns runtime idle and absolute timeouts. When set,
// values are looked up per Create / Get call from admin-configured policy
// (DB-backed setting). Static fields stay as fallback when provider is nil
// or returns zero/negative values.
type PolicyProvider func(ctx context.Context) (idle, absolute time.Duration)

// EnrollDecider reports whether a NEWLY created session must be flagged
// MFAEnrollPending — i.e. the MFA policy requires this user to hold a factor
// and they have none yet. Evaluated inside Create so EVERY login path (local
// password, SMS OTP, magic link, external IdP / Lark) enforces mandatory MFA
// uniformly, instead of each handler having to remember to set the flag.
type EnrollDecider func(ctx context.Context, tenantID, userID int64) bool

// Manager handles session lifecycle operations.
type Manager struct {
	redis           *redis.Client
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	policy          PolicyProvider
	enrollDecider   EnrollDecider
}

// NewManager creates a session manager.
func NewManager(rdb *redis.Client, idleTimeout, absoluteTimeout time.Duration) *Manager {
	return &Manager{
		redis:           rdb,
		idleTimeout:     idleTimeout,
		absoluteTimeout: absoluteTimeout,
	}
}

// SetPolicyProvider installs a runtime policy lookup. Safe to call once
// after construction; not goroutine-safe for repeated swaps.
func (m *Manager) SetPolicyProvider(p PolicyProvider) { m.policy = p }

// SetEnrollDecider installs the mandatory-MFA-enrollment predicate applied to
// every newly created session. Nil disables mandatory enrollment. Wired once
// after construction.
func (m *Manager) SetEnrollDecider(d EnrollDecider) { m.enrollDecider = d }

// CountActive returns the number of live session value keys in the given
// namespace. Session values live at `namespace:<id>`; the per-user index sets
// live at `namespace:user:<uid>` and are excluded. Uses SCAN (non-blocking) so
// it's safe to call against a production redis — it's an estimate under churn,
// which is fine for a dashboard gauge.
func (m *Manager) CountActive(ctx context.Context, namespace string) (int64, error) {
	var count int64
	prefix := namespace + ":"
	userPrefix := namespace + ":user:"
	var cursor uint64
	for {
		keys, next, err := m.redis.Scan(ctx, cursor, prefix+"*", 256).Result()
		if err != nil {
			return count, err
		}
		for _, k := range keys {
			if len(k) >= len(userPrefix) && k[:len(userPrefix)] == userPrefix {
				continue // user index set, not a session
			}
			count++
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return count, nil
}

// resolveTimeouts returns the effective (idle, absolute) for this request,
// preferring the runtime policy and falling back to the static config.
func (m *Manager) resolveTimeouts(ctx context.Context) (time.Duration, time.Duration) {
	idle, abs := m.idleTimeout, m.absoluteTimeout
	if m.policy != nil {
		if pIdle, pAbs := m.policy(ctx); pIdle > 0 && pAbs > 0 {
			idle, abs = pIdle, pAbs
		}
	}
	return idle, abs
}

// Create creates a new session.
func (m *Manager) Create(ctx context.Context, namespace string, userID, tenantID int64, ip, userAgent, authType string) (*Session, error) {
	_, absolute := m.resolveTimeouts(ctx)
	now := time.Now()
	sess := &Session{
		ID:           uuid.New().String(),
		UserID:       userID,
		TenantID:     tenantID,
		Namespace:    namespace,
		IP:           ip,
		UserAgent:    userAgent,
		AuthType:     authType,
		CreatedAt:    now,
		ExpiresAt:    now.Add(absolute),
		LastActiveAt: now,
	}

	// Mandatory-MFA enrollment gate, applied at the single session-creation
	// chokepoint so it covers every login method (password / SMS / magic link /
	// external IdP). The EnrollGate middleware then blocks a pending session from
	// everything but the MFA-enrollment surface until a factor is bound.
	if m.enrollDecider != nil && m.enrollDecider(ctx, tenantID, userID) {
		sess.MFAEnrollPending = true
	}

	if err := m.save(ctx, sess); err != nil {
		return nil, err
	}

	// Add to user's session set for listing
	userKey := fmt.Sprintf("%s:user:%d", namespace, userID)
	m.redis.SAdd(ctx, userKey, sess.ID)
	m.redis.Expire(ctx, userKey, absolute)

	return sess, nil
}

// Get retrieves a session by ID. READ-ONLY: this method does NOT refresh
// LastActiveAt. Callers that represent a real user request (auth
// middleware) must call Touch() afterwards. Listing/inspection callers
// (security/sessions UI, admin tools) must NOT touch — otherwise every
// list view extends every idle session's clock and idle timeout never
// fires.
//
// Returns (nil, nil) when the session is absent, absolute-expired, or
// idle-expired. Idle/absolute expired rows are deleted as a side effect
// (cheap cleanup; idempotent).
func (m *Manager) Get(ctx context.Context, namespace, sessionID string) (*Session, error) {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	data, err := m.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	now := time.Now()
	idle, _ := m.resolveTimeouts(ctx)
	if now.After(sess.ExpiresAt) || now.After(sess.LastActiveAt.Add(idle)) {
		_ = m.Delete(ctx, namespace, sessionID)
		return nil, nil
	}

	return &sess, nil
}

// Touch refreshes LastActiveAt on a live session. Called by the auth
// middleware after Get() succeeds on a real user request. Errors are
// logged at the caller; we don't want a Redis hiccup to fail the request.
func (m *Manager) Touch(ctx context.Context, namespace, sessionID string) error {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	data, err := m.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("touch get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return fmt.Errorf("touch unmarshal: %w", err)
	}
	sess.LastActiveAt = time.Now()
	return m.save(ctx, &sess)
}

// MarkMFAVerified stamps the session's MFAVerifiedAt to now and persists it.
// Called after a successful MFA login or step-up challenge so subsequent
// high-risk operations fall inside the grace window. No-op if the session is
// gone (already expired/revoked).
func (m *Manager) MarkMFAVerified(ctx context.Context, namespace, sessionID string) error {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	data, err := m.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("mark mfa get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return fmt.Errorf("mark mfa unmarshal: %w", err)
	}
	now := time.Now()
	sess.MFAVerifiedAt = &now
	return m.save(ctx, &sess)
}

// CarryMFAVerifiedAt copies a step-up timestamp onto an existing session,
// preserving the original moment (unlike MarkMFAVerified which stamps now). Used
// when deriving one session from another via seamless SSO so the derived session
// inherits — without extending — the source's step-up (sudo) freshness. A nil or
// zero `at` is a no-op, so a source that never passed MFA carries nothing.
func (m *Manager) CarryMFAVerifiedAt(ctx context.Context, namespace, sessionID string, at *time.Time) error {
	if at == nil || at.IsZero() {
		return nil
	}
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	data, err := m.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("carry mfa get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return fmt.Errorf("carry mfa unmarshal: %w", err)
	}
	t := *at
	sess.MFAVerifiedAt = &t
	return m.save(ctx, &sess)
}

// SetEnrollPending sets the MFA-enrollment-pending flag on a session and
// persists it. Used to force a user with no factor through enrollment before
// they can use the app, and to clear the flag once they bind one. No-op if the
// session is gone.
func (m *Manager) SetEnrollPending(ctx context.Context, namespace, sessionID string, pending bool) error {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	data, err := m.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("set enroll pending get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return fmt.Errorf("set enroll pending unmarshal: %w", err)
	}
	sess.MFAEnrollPending = pending
	return m.save(ctx, &sess)
}

// Delete removes a session.
func (m *Manager) Delete(ctx context.Context, namespace, sessionID string) error {
	key := fmt.Sprintf("%s:%s", namespace, sessionID)
	return m.redis.Del(ctx, key).Err()
}

// ListByUser returns all sessions for a user in a namespace.
func (m *Manager) ListByUser(ctx context.Context, namespace string, userID int64) ([]*Session, error) {
	userKey := fmt.Sprintf("%s:user:%d", namespace, userID)
	ids, err := m.redis.SMembers(ctx, userKey).Result()
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(ids))
	for _, id := range ids {
		sess, err := m.Get(ctx, namespace, id)
		if err != nil {
			continue
		}
		if sess != nil {
			sessions = append(sessions, sess)
		} else {
			// Cleanup stale reference
			m.redis.SRem(ctx, userKey, id)
		}
	}

	return sessions, nil
}

// DeleteAllByUser removes all sessions for a user in a namespace.
func (m *Manager) DeleteAllByUser(ctx context.Context, namespace string, userID int64) error {
	sessions, err := m.ListByUser(ctx, namespace, userID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		_ = m.Delete(ctx, namespace, s.ID)
	}
	userKey := fmt.Sprintf("%s:user:%d", namespace, userID)
	return m.redis.Del(ctx, userKey).Err()
}

func (m *Manager) save(ctx context.Context, sess *Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	key := fmt.Sprintf("%s:%s", sess.Namespace, sess.ID)
	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	return m.redis.Set(ctx, key, data, ttl).Err()
}
