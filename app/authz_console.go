package app

import (
	"net/http"
	"strings"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/authz"
	"go.uber.org/zap"
)

const (
	// consolePrefix matches every route on the admin console group.
	consolePrefix = "/api/v1/console"
	// consoleAuthPrefix is the pre-auth auth surface (login / logout / captcha /
	// mfa / sso / step-up). These routes are registered by authn.Register BEFORE
	// the deny-by-default gateway's .Use, so gin never runs the gateway on them —
	// they are NOT governed and must be skipped by the coverage audit.
	consoleAuthPrefix = "/api/v1/console/auth/"
)

// consoleProtectedRoutes is the deny-by-default gateway's authoritative view of
// the console admin surface. Every entry is Protect'd so the gateway recognises
// the route as gated; ENFORCEMENT still comes from each route's own
// authz.Require (the permission lives there, not here — the perm arg to Protect
// is diagnostic only). Generated from the live gin route table and audited
// 2026-07-04: every one of these carries an authz.Require. The self-service
// surfaces (profile / security) and the intentionally-open tenant-switcher
// reads are allow-listed in registerConsoleAuthz instead.
//
// A NEW console route not covered here 403s under hard deny-by-default — that is
// the point. Add it here alongside its authz.Require, or AllowPublic it in
// registerConsoleAuthz if it is deliberately unauthenticated. registerConsoleAuthz
// runs a boot-time audit that loudly logs any governed route missing from both.
var consoleProtectedRoutes = [][2]string{
	{http.MethodDelete, "/api/v1/console/access-eligibilities/:id"},
	{http.MethodDelete, "/api/v1/console/app-groups/:id"},
	{http.MethodDelete, "/api/v1/console/app-groups/:id/access-policies/:policy_id"},
	{http.MethodDelete, "/api/v1/console/app-groups/:id/apps/:aid"},
	{http.MethodDelete, "/api/v1/console/app-groups/:id/role-bindings/:binding_id"},
	{http.MethodDelete, "/api/v1/console/app-groups/:id/roles/:role_id"},
	{http.MethodDelete, "/api/v1/console/apps/:id"},
	{http.MethodDelete, "/api/v1/console/apps/:id/access-policies/:policy_id"},
	{http.MethodDelete, "/api/v1/console/apps/:id/access/:aid"},
	{http.MethodDelete, "/api/v1/console/apps/:id/certs/:cid"},
	{http.MethodDelete, "/api/v1/console/apps/:id/role-bindings/:binding_id"},
	{http.MethodDelete, "/api/v1/console/apps/:id/roles/:role_id"},
	{http.MethodDelete, "/api/v1/console/groups/:id"},
	{http.MethodDelete, "/api/v1/console/groups/:id/members/:uid"},
	{http.MethodDelete, "/api/v1/console/groups/:id/members/batch"},
	{http.MethodDelete, "/api/v1/console/groups/:id/rule"},
	{http.MethodDelete, "/api/v1/console/orgs/:id"},
	{http.MethodDelete, "/api/v1/console/orgs/:id/members/:uid"},
	{http.MethodDelete, "/api/v1/console/roles/:id"},
	{http.MethodDelete, "/api/v1/console/roles/:id/members/:mid"},
	{http.MethodDelete, "/api/v1/console/tenants/:id"},
	{http.MethodDelete, "/api/v1/console/users/:id"},
	{http.MethodDelete, "/api/v1/console/users/:id/identities/:iid"},
	{http.MethodDelete, "/api/v1/console/users/:id/mfa/:type"},
	{http.MethodDelete, "/api/v1/console/users/:id/sessions"},
	{http.MethodDelete, "/api/v1/console/users/:id/sessions/:sid"},
	{http.MethodGet, "/api/v1/console/access-eligibilities"},
	{http.MethodGet, "/api/v1/console/access-requests"},
	{http.MethodGet, "/api/v1/console/app-groups"},
	{http.MethodGet, "/api/v1/console/app-groups/:id/access-policies"},
	{http.MethodGet, "/api/v1/console/app-groups/:id/apps"},
	{http.MethodGet, "/api/v1/console/app-groups/:id/member-apps-roles"},
	{http.MethodGet, "/api/v1/console/app-groups/:id/role-bindings"},
	{http.MethodGet, "/api/v1/console/app-groups/:id/roles"},
	{http.MethodGet, "/api/v1/console/app-templates"},
	{http.MethodGet, "/api/v1/console/app-templates/:key"},
	{http.MethodGet, "/api/v1/console/apps"},
	{http.MethodGet, "/api/v1/console/apps/:id"},
	{http.MethodGet, "/api/v1/console/apps/:id/access"},
	{http.MethodGet, "/api/v1/console/apps/:id/access-policies"},
	{http.MethodGet, "/api/v1/console/apps/:id/certs"},
	{http.MethodGet, "/api/v1/console/apps/:id/config"},
	{http.MethodGet, "/api/v1/console/apps/:id/provisioning"},
	{http.MethodGet, "/api/v1/console/apps/:id/quickstart/:lang"},
	{http.MethodGet, "/api/v1/console/apps/:id/role-bindings"},
	{http.MethodGet, "/api/v1/console/apps/:id/roles"},
	{http.MethodGet, "/api/v1/console/audit/logs"},
	{http.MethodGet, "/api/v1/console/audit/stats"},
	{http.MethodGet, "/api/v1/console/dashboard/export"},
	{http.MethodGet, "/api/v1/console/dashboard/overview"},
	{http.MethodGet, "/api/v1/console/groups"},
	{http.MethodGet, "/api/v1/console/groups/:id"},
	{http.MethodGet, "/api/v1/console/groups/:id/app-role-bindings"},
	{http.MethodGet, "/api/v1/console/groups/:id/members"},
	{http.MethodGet, "/api/v1/console/groups/:id/rule"},
	{http.MethodGet, "/api/v1/console/groups/rule-fields"},
	{http.MethodGet, "/api/v1/console/offboarding/tasks"},
	{http.MethodGet, "/api/v1/console/offboarding/tasks/:id/items"},
	{http.MethodGet, "/api/v1/console/orgs"},
	{http.MethodGet, "/api/v1/console/orgs/:id"},
	{http.MethodGet, "/api/v1/console/orgs/:id/members"},
	{http.MethodGet, "/api/v1/console/permissions"},
	{http.MethodGet, "/api/v1/console/roles"},
	{http.MethodGet, "/api/v1/console/roles/:id"},
	{http.MethodGet, "/api/v1/console/roles/:id/members"},
	{http.MethodGet, "/api/v1/console/roles/:id/permissions"},
	{http.MethodGet, "/api/v1/console/settings/audit-policy"},
	{http.MethodGet, "/api/v1/console/settings/branding"},
	{http.MethodGet, "/api/v1/console/settings/conditional-access"},
	{http.MethodGet, "/api/v1/console/settings/external-urls"},
	{http.MethodGet, "/api/v1/console/settings/license"},
	{http.MethodGet, "/api/v1/console/settings/localization"},
	{http.MethodGet, "/api/v1/console/settings/login-methods"},
	{http.MethodGet, "/api/v1/console/settings/mail/smtp"},
	{http.MethodGet, "/api/v1/console/settings/mail/templates"},
	{http.MethodGet, "/api/v1/console/settings/mfa"},
	{http.MethodGet, "/api/v1/console/settings/offboarding-webhook"},
	{http.MethodGet, "/api/v1/console/settings/protocol-defaults"},
	{http.MethodGet, "/api/v1/console/settings/security"},
	{http.MethodGet, "/api/v1/console/settings/sms"},
	{http.MethodGet, "/api/v1/console/system/version"},
	{http.MethodGet, "/api/v1/console/users"},
	{http.MethodGet, "/api/v1/console/users/:id"},
	{http.MethodGet, "/api/v1/console/users/:id/app-role-bindings"},
	{http.MethodGet, "/api/v1/console/users/:id/detail"},
	{http.MethodGet, "/api/v1/console/users/:id/groups"},
	{http.MethodGet, "/api/v1/console/users/:id/identities"},
	{http.MethodGet, "/api/v1/console/users/:id/login-history"},
	{http.MethodGet, "/api/v1/console/users/:id/mfa"},
	{http.MethodGet, "/api/v1/console/users/:id/roles"},
	{http.MethodGet, "/api/v1/console/users/:id/sessions"},
	{http.MethodPost, "/api/v1/console/access-eligibilities"},
	{http.MethodPost, "/api/v1/console/access-requests/:id/approve"},
	{http.MethodPost, "/api/v1/console/access-requests/:id/reject"},
	{http.MethodPost, "/api/v1/console/access-requests/:id/revoke"},
	{http.MethodPost, "/api/v1/console/app-groups"},
	{http.MethodPost, "/api/v1/console/app-groups/:id/access-policies"},
	{http.MethodPost, "/api/v1/console/app-groups/:id/apps"},
	{http.MethodPost, "/api/v1/console/app-groups/:id/role-bindings"},
	{http.MethodPost, "/api/v1/console/app-groups/:id/roles"},
	{http.MethodPost, "/api/v1/console/apps"},
	{http.MethodPost, "/api/v1/console/apps/:id/access"},
	{http.MethodPost, "/api/v1/console/apps/:id/access-policies"},
	{http.MethodPost, "/api/v1/console/apps/:id/certs"},
	{http.MethodPost, "/api/v1/console/apps/:id/regenerate-secret"},
	{http.MethodPost, "/api/v1/console/apps/:id/role-bindings"},
	{http.MethodPost, "/api/v1/console/apps/:id/roles"},
	{http.MethodPost, "/api/v1/console/apps/:id/rotate-signing-key"},
	{http.MethodPost, "/api/v1/console/apps/:id/saml/import-metadata"},
	{http.MethodPost, "/api/v1/console/groups"},
	{http.MethodPost, "/api/v1/console/groups/:id/members"},
	{http.MethodPost, "/api/v1/console/groups/:id/members/batch"},
	{http.MethodPost, "/api/v1/console/groups/:id/sync"},
	{http.MethodPost, "/api/v1/console/offboarding/items/:id/done"},
	{http.MethodPost, "/api/v1/console/orgs"},
	{http.MethodPost, "/api/v1/console/orgs/:id/members"},
	{http.MethodPost, "/api/v1/console/roles"},
	{http.MethodPost, "/api/v1/console/roles/:id/members"},
	{http.MethodPost, "/api/v1/console/settings/mail/smtp/test"},
	{http.MethodPost, "/api/v1/console/system/version/check"},
	{http.MethodPost, "/api/v1/console/tenants"},
	{http.MethodPost, "/api/v1/console/users"},
	{http.MethodPost, "/api/v1/console/users/:id/lock"},
	{http.MethodPost, "/api/v1/console/users/:id/mfa/lockout/clear"},
	{http.MethodPost, "/api/v1/console/users/:id/offboard"},
	{http.MethodPost, "/api/v1/console/users/:id/unlock"},
	{http.MethodPost, "/api/v1/console/users/batch"},
	{http.MethodPut, "/api/v1/console/access-eligibilities/:id"},
	{http.MethodPut, "/api/v1/console/app-groups/:id"},
	{http.MethodPut, "/api/v1/console/app-groups/:id/roles/:role_id"},
	{http.MethodPut, "/api/v1/console/apps/:id"},
	{http.MethodPut, "/api/v1/console/apps/:id/config"},
	{http.MethodPut, "/api/v1/console/apps/:id/provisioning"},
	{http.MethodPut, "/api/v1/console/apps/:id/roles/:role_id"},
	{http.MethodPut, "/api/v1/console/apps/:id/status"},
	{http.MethodPut, "/api/v1/console/groups/:id"},
	{http.MethodPut, "/api/v1/console/groups/:id/rule"},
	{http.MethodPut, "/api/v1/console/orgs/:id"},
	{http.MethodPut, "/api/v1/console/orgs/:id/move"},
	{http.MethodPut, "/api/v1/console/roles/:id"},
	{http.MethodPut, "/api/v1/console/roles/:id/permissions"},
	{http.MethodPut, "/api/v1/console/settings/audit-policy"},
	{http.MethodPut, "/api/v1/console/settings/branding"},
	{http.MethodPut, "/api/v1/console/settings/conditional-access"},
	{http.MethodPut, "/api/v1/console/settings/external-urls"},
	{http.MethodPut, "/api/v1/console/settings/license"},
	{http.MethodPut, "/api/v1/console/settings/localization"},
	{http.MethodPut, "/api/v1/console/settings/login-methods"},
	{http.MethodPut, "/api/v1/console/settings/mail/smtp"},
	{http.MethodPut, "/api/v1/console/settings/mail/templates"},
	{http.MethodPut, "/api/v1/console/settings/mfa"},
	{http.MethodPut, "/api/v1/console/settings/offboarding-webhook"},
	{http.MethodPut, "/api/v1/console/settings/protocol-defaults"},
	{http.MethodPut, "/api/v1/console/settings/security"},
	{http.MethodPut, "/api/v1/console/settings/sms"},
	{http.MethodPut, "/api/v1/console/tenants/:id"},
	{http.MethodPut, "/api/v1/console/users/:id"},
	{http.MethodPut, "/api/v1/console/users/:id/detail"},
	{http.MethodPut, "/api/v1/console/users/:id/password"},
	{http.MethodPut, "/api/v1/console/users/:id/status"},
	{http.MethodPut, "/api/v1/console/users/:id/super-admin"},
}

// registerConsoleAuthz populates the deny-by-default gateway registry before the
// server starts serving: allow-list the self-service + intentionally-public
// console routes, Protect the admin routes, then audit coverage. Must be called
// after all console routes are registered (so the audit sees the full table) and
// before the first request.
func registerConsoleAuthz(a *bootstrap.App) {
	// Self-service surfaces mounted on the console group (portal.Register*Routes
	// on ConsoleGroup): they authenticate via the caller's own session and need
	// no admin permission, so they are intentionally public to the gateway.
	authz.AllowPublicPrefix("/api/v1/console/profile")
	authz.AllowPublicPrefix("/api/v1/console/security/")
	// Tenant-switcher reads: intentionally readable by any authenticated console
	// user (the console renders the tenant dropdown from them). Writes stay
	// Protect'd with tenant.manage below.
	authz.AllowPublic(http.MethodGet, "/api/v1/console/tenants")
	authz.AllowPublic(http.MethodGet, "/api/v1/console/tenants/:id")

	for _, r := range consoleProtectedRoutes {
		authz.Protect(r[0], r[1], "")
	}

	auditConsoleCoverage(a)
}

// auditConsoleCoverage logs an error for every gateway-governed console route
// (console-prefixed, excluding the pre-auth /auth/* routes registered before the
// gateway) that is neither Protect'd nor AllowPublic'd — i.e. one that would 403
// under hard deny-by-default. Catches a route shipped without a matching authz
// declaration. Loud but non-fatal: the gateway is the hard stop; this just makes
// a drift visible at boot instead of as a mystery 403 in production.
func auditConsoleCoverage(a *bootstrap.App) {
	for _, ri := range a.Router.Routes() {
		if !strings.HasPrefix(ri.Path, consolePrefix) {
			continue
		}
		if strings.HasPrefix(ri.Path, consoleAuthPrefix) {
			continue // pre-auth, registered before the gateway — not governed
		}
		if authz.IsRegistered(ri.Method, ri.Path) {
			continue
		}
		a.Logger.Error("authz gateway: console route has NO authz declaration — "+
			"will 403 under hard deny-by-default; add authz.Require+Protect (consoleProtectedRoutes) or AllowPublic it",
			zap.String("method", ri.Method), zap.String("route", ri.Path))
	}
}
