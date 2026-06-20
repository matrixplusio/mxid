package event

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

// Event represents a domain event.
type Event struct {
	Type    string
	Payload any
}

// Handler processes events.
type Handler func(ctx context.Context, event Event)

// Bus is an in-process event bus for module decoupling.
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
	logger   *zap.Logger
}

// NewBus creates a new event bus.
func NewBus(logger *zap.Logger) *Bus {
	return &Bus{
		handlers: make(map[string][]Handler),
		logger:   logger,
	}
}

// Subscribe registers a handler for an event type.
func (b *Bus) Subscribe(eventType string, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

// Publish sends an event to all registered handlers asynchronously. Safe to
// call on a nil Bus (no subscribers → no-op), so services wired without an
// event bus — unit tests, minimal embeddings — don't need to guard each call.
func (b *Bus) Publish(ctx context.Context, evt Event) {
	if b == nil {
		return
	}
	b.mu.RLock()
	handlers := b.handlers[evt.Type]
	b.mu.RUnlock()

	for _, h := range handlers {
		go func(handler Handler) {
			defer func() {
				if r := recover(); r != nil {
					b.logger.Error("event handler panic",
						zap.String("event_type", evt.Type),
						zap.Any("recover", r),
					)
				}
			}()
			handler(ctx, evt)
		}(h)
	}
}

// Event type constants.
const (
	UserCreated         = "user.created"
	UserUpdated         = "user.updated"
	UserDeleted         = "user.deleted"
	UserLocked          = "user.locked"
	UserUnlocked        = "user.unlocked"
	UserPasswordChanged = "user.password_changed"
	// UserPIIView fires when an admin reads another user's full PII
	// (phone / email / address / id-card). Self-views are excluded.
	// Carries actor_id, target_user_id, tenant_id, fields=[...]
	UserPIIView = "user.pii_view"
	// UserSuperAdminGrant / Revoke fires when the is_super_admin flag
	// flips on a user. Always audited; never auto-granted.
	UserSuperAdminGrant  = "user.super_admin.grant"
	UserSuperAdminRevoke = "user.super_admin.revoke"

	// UserOffboarded fires on a one-click offboard: the user is disabled and
	// all their sessions are killed in one atomic admin action (L1 access
	// cutoff). Audited as a high-risk security event.
	UserOffboarded = "user.offboarded"

	LoginSuccess = "login.success"
	LoginFailed  = "login.failed"
	Logout       = "logout"
	// LoginRisk marks a login that conditional access flagged as risky (new
	// country / impossible travel / new device) but allowed through because the
	// user had no second factor to challenge. Surfaced in the audit trail.
	LoginRisk = "login.risk"

	AppCreated  = "app.created"
	AppUpdated  = "app.updated"
	AppDeleted  = "app.deleted"
	AppLaunched = "app.launched" // portal user clicked an app card → drives "Recently used"

	// Security-sensitive app sub-resource changes. The resource is the parent
	// app (resource_id = app_id) so the trail reads "who changed access/keys on
	// which app". Distinct from the SSE cache-bust events (EventAppRoleChanged,
	// EventAccessPolicyChanged) which carry no actor.
	AppAccessGranted       = "app.access_granted"
	AppAccessRevoked       = "app.access_revoked"
	AppCertCreated         = "app.cert_created"
	AppCertDeleted         = "app.cert_deleted"
	AppRoleCreated         = "app.role_created"
	AppRoleUpdated         = "app.role_updated"
	AppRoleDeleted         = "app.role_deleted"
	AppRoleBindingCreated  = "app.role_binding_created"
	AppRoleBindingDeleted  = "app.role_binding_deleted"
	AppAccessPolicyCreated = "app.access_policy_created"
	AppAccessPolicyDeleted = "app.access_policy_deleted"

	OrgCreated     = "org.created"
	OrgUpdated     = "org.updated"
	OrgDeleted     = "org.deleted"
	OrgMemberMoved = "org.member_moved"

	GroupCreated       = "group.created"
	GroupUpdated       = "group.updated"
	GroupDeleted       = "group.deleted"
	GroupMemberAdded   = "group.member_added"
	GroupMemberRemoved = "group.member_removed"

	SessionKicked = "session.kicked"
	MFAEnabled    = "mfa.enabled"
	MFADisabled   = "mfa.disabled"

	// OIDC token-lifecycle events. Captured into the audit log so admins can
	// trace per-RP token issuance, refresh, revoke and reuse-detection
	// incidents across the IdP.
	OIDCTokenIssued       = "oidc.token.issued"
	OIDCTokenRefreshed    = "oidc.token.refreshed"
	OIDCTokenRevoked      = "oidc.token.revoked"
	OIDCTokenReuse        = "oidc.token.reuse_detected"
	OIDCConsentGranted    = "oidc.consent.granted"
	OIDCConsentRevoked    = "oidc.consent.revoked"
	OIDCBackchannelLogout = "oidc.backchannel_logout"

	// Tenant lifecycle (super-admin operations).
	TenantCreated = "tenant.created"
	TenantUpdated = "tenant.updated"
	TenantDeleted = "tenant.deleted"

	// External IdP (inbound federation) configuration changes.
	IDPCreated = "idp.created"
	IDPUpdated = "idp.updated"
	IDPDeleted = "idp.deleted"

	// Application group lifecycle + membership.
	AppGroupCreated       = "app_group.created"
	AppGroupUpdated       = "app_group.updated"
	AppGroupDeleted       = "app_group.deleted"
	AppGroupMemberAdded   = "app_group.member_added"
	AppGroupMemberRemoved = "app_group.member_removed"

	// SettingsUpdated fires when an admin changes a runtime config section
	// (security policy, branding, SMTP, login methods, MFA, …). Carries the
	// changed `section` so the audit row reads which knob moved.
	SettingsUpdated = "settings.updated"

	// Portal self-service identity changes.
	ProfileUpdated   = "profile.updated"
	APITokenCreated  = "api_token.created"
	APITokenRevoked  = "api_token.revoked"
)
