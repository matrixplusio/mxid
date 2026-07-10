package oidcop

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIssuerOption_DynamicOverridesStaticPerRequest locks the runtime-override
// contract: a non-empty dynamicIssuer(r) wins, everything else (nil request,
// empty override) falls back to the static boot issuer — the issuer is never
// empty, so id_token/discovery `iss` stays valid under any request.
func TestIssuerOption_DynamicOverridesStaticPerRequest(t *testing.T) {
	const static = "https://boot.example.com/protocol/oidc"
	const override = "https://override.example.com/protocol/oidc"

	fn, err := issuerOption(static, func(r *http.Request) string {
		if r != nil && r.Host == "override.example.com" {
			return override
		}
		return ""
	})(true)
	if err != nil {
		t.Fatalf("issuerOption: %v", err)
	}

	if got := fn(nil); got != static {
		t.Errorf("nil request: want static %q, got %q", static, got)
	}

	r1 := httptest.NewRequest("GET", "https://override.example.com/protocol/oidc/authorize", nil)
	r1.Host = "override.example.com"
	if got := fn(r1); got != override {
		t.Errorf("override host: want %q, got %q", override, got)
	}

	r2 := httptest.NewRequest("GET", "https://other.example.com/x", nil)
	if got := fn(r2); got != static {
		t.Errorf("non-override host: want static %q, got %q", static, got)
	}
}

// TestIssuerOption_NilDynamicIsStatic proves the nil-dynamicIssuer path is the
// unchanged static-only behaviour.
func TestIssuerOption_NilDynamicIsStatic(t *testing.T) {
	const static = "https://boot.example.com/protocol/oidc"
	fn, err := issuerOption(static, nil)(true)
	if err != nil {
		t.Fatalf("issuerOption: %v", err)
	}
	r := httptest.NewRequest("GET", "https://anything.example.com/x", nil)
	if got := fn(r); got != static {
		t.Errorf("nil dynamic: want static %q, got %q", static, got)
	}
	if got := fn(nil); got != static {
		t.Errorf("nil dynamic + nil request: want static %q, got %q", static, got)
	}
}
