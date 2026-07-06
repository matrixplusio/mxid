// internal/domain/audit/eventclass_test.go
package audit

import "testing"

func TestChainClassForEvent(t *testing.T) {
	auth := []string{
		"login.success", "login.failed", "login.risk", "logout", "session.kicked",
		"mfa.enabled", "mfa.disabled",
		"oidc.token.issued", "oidc.token.refreshed", "oidc.token.revoked", "oidc.token.reuse_detected",
		"oidc.consent.granted", "oidc.consent.revoked", "oidc.backchannel_logout",
	}
	for _, et := range auth {
		c, ok := chainClassForEvent(et)
		if !ok || c != "auth" {
			t.Errorf("%s: got (%q,%v), want (auth,true)", et, c, ok)
		}
	}
	if c, ok := chainClassForEvent("user.pii_view"); !ok || c != "sensitive_read" {
		t.Errorf("pii_view: got (%q,%v), want (sensitive_read,true)", c, ok)
	}
	// data-mutation + already-audited events must NOT be bridged (no double-capture)
	for _, et := range []string{"user.created", "app.updated", "app.deleted", "api_token.created", "user.password_changed", "role.binding.added"} {
		if _, ok := chainClassForEvent(et); ok {
			t.Errorf("%s must NOT be bridged (already in data chain / not chain-worthy)", et)
		}
	}
}
