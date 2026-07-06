package audit

// chainClassForEvent maps an audit event_type to the tamper-proof chain class it
// should be bridged into, or ("", false) if it must NOT be bridged.
//
// SELECTIVE by design: data-mutation events (user.*, app.*, role.*, api_token.*,
// user.password_changed) are already captured by the Phase 2 ORM callback in the
// "data" chain — bridging them here would double-capture. Only auth/session/token/
// consent events (which have no audited-table equivalent) plus pii_view are bridged.
func chainClassForEvent(eventType string) (string, bool) {
	switch eventType {
	case "login.success", "login.failed", "login.risk", "logout", "session.kicked",
		"mfa.enabled", "mfa.disabled",
		"oidc.token.issued", "oidc.token.refreshed", "oidc.token.revoked", "oidc.token.reuse_detected",
		"oidc.consent.granted", "oidc.consent.revoked", "oidc.backchannel_logout":
		return "auth", true
	case "user.pii_view":
		return "sensitive_read", true
	default:
		return "", false
	}
}
