package oidcop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// mapAppResolver resolves apps by client_id from a fixed map — needed (unlike
// client_credentials_test.go's fixedAppResolver, which always returns the same
// single app) to prove two different client_ids get independent rate-limit
// buckets.
type mapAppResolver struct {
	resolver.AppResolver
	byClientID map[string]*resolver.AppConfig
}

func (m *mapAppResolver) GetAppByClientID(_ context.Context, clientID string) (*resolver.AppConfig, error) {
	return m.byClientID[clientID], nil
}

// newRateLimitedProvider wires the real op.OpenIDProvider (same harness as
// client_credentials_test.go's newClientCredentialsProvider) wrapped in
// WithTokenRateLimit, over an in-memory Redis, exactly as adapters_oidcop.go
// composes it before Mount.
func newRateLimitedProvider(t *testing.T, rdb *redis.Client, apps ...*resolver.AppConfig) *httptest.Server {
	t.Helper()
	byClientID := make(map[string]*resolver.AppConfig, len(apps))
	for _, a := range apps {
		byClientID[a.ClientID] = a
	}
	resolver := &mapAppResolver{byClientID: byClientID}
	clients := NewClientStore(resolver, func(string) string { return "" })
	storage := NewStorage(rdb, nil, clients, nil, nil, nil, DefaultConfig())
	var key [32]byte
	provider, err := NewProvider("https://issuer.example.com", storage, key, true, nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	wrapped := WithTokenRateLimit(rdb, resolver)(provider)
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)
	return srv
}

func postClientCredentialsForm(t *testing.T, srv *httptest.Server, clientID, clientSecret string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	// Uses the httptest.Server's own client (never the banned package-level
	// stdlib entry points) since the target is always the loopback test
	// server, never attacker-influenced — the SSRF guard does not apply here.
	resp, err := srv.Client().Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// postClientCredentialsBasic authenticates via HTTP Basic auth (no client_id
// in the form) — the other client-auth surface withTokenRateLimit must peek
// client_id from.
func postClientCredentialsBasic(t *testing.T, srv *httptest.Server, clientID, clientSecret string) *http.Response {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /token (basic): %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func rateLimitedAppSecret(t *testing.T, id int64, clientID, secret string, limit int, authMode string) *resolver.AppConfig {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	cfg := map[string]any{
		"grant_types": []string{"client_credentials"},
	}
	if limit > 0 {
		cfg["rate_limit_per_min"] = limit
	}
	if authMode != "" {
		cfg["token_endpoint_auth_mode"] = authMode
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return &resolver.AppConfig{
		ID: id, ClientID: clientID, ClientType: "m2m", Protocol: "oidc", Status: 1,
		ClientSecret:   string(hash),
		ProtocolConfig: raw,
	}
}

// TestTokenRateLimit_SameClientExceedsLimit_Returns429 is the RED/GREEN case:
// a client whose protocol_config caps it at 2 req/min gets a 200 for the
// first two token requests within the window and a 429 slow_down for the
// third — mirroring the hand-rolled engine's checkRateLimit behavior
// (internal/protocol/oidc/handler.go:558) now ported to the zitadel engine.
func TestTokenRateLimit_SameClientExceedsLimit_Returns429(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	app := rateLimitedAppSecret(t, 1, "m2m-limited", "s3cr3t", 2, "")
	srv := newRateLimitedProvider(t, rdb, app)

	for i := 0; i < 2; i++ {
		resp := postClientCredentialsForm(t, srv, "m2m-limited", "s3cr3t")
		if resp.StatusCode != http.StatusOK {
			body := decodeJSON(t, resp)
			t.Fatalf("request %d: status = %d, want 200 (body: %v)", i+1, resp.StatusCode, body)
		}
	}

	resp := postClientCredentialsForm(t, srv, "m2m-limited", "s3cr3t")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("3rd request: status = %d, want 429", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "slow_down" {
		t.Fatalf("error = %v, want slow_down", body["error"])
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429")
	}
}

// TestTokenRateLimit_DifferentClientIndependentBucket proves the fixed-window
// bucket is keyed per client_id: client A hitting its (very low) limit must
// not throttle client B's own independent request.
func TestTokenRateLimit_DifferentClientIndependentBucket(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	appA := rateLimitedAppSecret(t, 1, "client-a", "secretA", 1, "")
	appB := rateLimitedAppSecret(t, 2, "client-b", "secretB", 1, "")
	srv := newRateLimitedProvider(t, rdb, appA, appB)

	respA1 := postClientCredentialsForm(t, srv, "client-a", "secretA")
	if respA1.StatusCode != http.StatusOK {
		t.Fatalf("client-a request 1: status = %d, want 200", respA1.StatusCode)
	}
	respA2 := postClientCredentialsForm(t, srv, "client-a", "secretA")
	if respA2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("client-a request 2: status = %d, want 429 (limit=1)", respA2.StatusCode)
	}

	respB1 := postClientCredentialsForm(t, srv, "client-b", "secretB")
	if respB1.StatusCode != http.StatusOK {
		t.Fatalf("client-b request 1: status = %d, want 200 — independent bucket from client-a", respB1.StatusCode)
	}
}

// TestTokenRateLimit_BasicAuthClientID proves client_id extraction also works
// when the client authenticates via HTTP Basic auth (client_secret_basic)
// instead of posting client_id in the form body.
func TestTokenRateLimit_BasicAuthClientID(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	app := rateLimitedAppSecret(t, 1, "m2m-basic", "s3cr3t", 1, "client_secret_basic")
	srv := newRateLimitedProvider(t, rdb, app)

	resp1 := postClientCredentialsBasic(t, srv, "m2m-basic", "s3cr3t")
	if resp1.StatusCode != http.StatusOK {
		body := decodeJSON(t, resp1)
		t.Fatalf("request 1: status = %d, want 200 (body: %v)", resp1.StatusCode, body)
	}

	resp2 := postClientCredentialsBasic(t, srv, "m2m-basic", "s3cr3t")
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 2: status = %d, want 429 (limit=1, basic-auth client_id)", resp2.StatusCode)
	}
	body := decodeJSON(t, resp2)
	if body["error"] != "slow_down" {
		t.Fatalf("error = %v, want slow_down", body["error"])
	}
}

// TestTokenRateLimit_BodyNotCorrupted proves reading the form body to peek
// client_id does not prevent op from parsing the real grant afterward — an
// under-limit request must still receive a genuine access_token, not just a
// bare 200.
func TestTokenRateLimit_BodyNotCorrupted(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	app := rateLimitedAppSecret(t, 1, "m2m-intact", "s3cr3t", defaultTokenRateLimitPerMin, "")
	srv := newRateLimitedProvider(t, rdb, app)

	resp := postClientCredentialsForm(t, srv, "m2m-intact", "s3cr3t")
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", resp.StatusCode, body)
	}
	if s, _ := body["access_token"].(string); s == "" {
		t.Fatalf("expected a non-empty access_token — form body may have been corrupted, got %v", body)
	}
}

// unsignedAssertion builds a JWT with the given iss/sub claims and a dummy
// signature segment — deliberately NOT signed, since the rate limiter only
// base64-decodes the payload for its bucket key and never verifies the
// signature. Mirrors an RFC 7523 client_assertion shape (header.payload.sig).
func unsignedAssertion(t *testing.T, iss, sub string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]string{}
	if iss != "" {
		claims["iss"] = iss
	}
	if sub != "" {
		claims["sub"] = sub
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".sig"
}

// postPrivateKeyJWT sends a token request authenticated via client_assertion
// (private_key_jwt / RFC 7523) with NO client_id form field — the exact shape
// that made such clients bypass the rate limiter before the third fallback.
func postPrivateKeyJWT(t *testing.T, srv *httptest.Server, assertion string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	resp, err := srv.Client().Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token (private_key_jwt): %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestTokenRateLimit_PrivateKeyJWT_NoClientIDForm is the Important-gap
// regression: a private_key_jwt client that presents a client_assertion but
// OMITS the client_id form field must still be rate-limited, keyed on the
// assertion's iss/sub. The rate limiter runs BEFORE op's assertion
// verification, so the (deliberately unsigned) assertion is fine — op will
// reject the request downstream, but the limiter has already bucketed it.
// With limit=1 the first request passes the limiter (op then errors, NOT 429)
// and the second is throttled with 429 slow_down.
func TestTokenRateLimit_PrivateKeyJWT_NoClientIDForm(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	// The app is resolvable under the assertion's iss so the custom limit=1
	// applies; client_id == iss.
	app := rateLimitedAppSecret(t, 1, "pkjwt-client", "unused", 1, "private_key_jwt")
	srv := newRateLimitedProvider(t, rdb, app)

	assertion := unsignedAssertion(t, "pkjwt-client", "")

	resp1 := postPrivateKeyJWT(t, srv, assertion)
	if resp1.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("request 1: got 429 too early — limiter should admit the first request")
	}

	resp2 := postPrivateKeyJWT(t, srv, assertion)
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 2: status = %d, want 429 — private_key_jwt client with no client_id form field must be rate-limited on its assertion iss", resp2.StatusCode)
	}
	body := decodeJSON(t, resp2)
	if body["error"] != "slow_down" {
		t.Fatalf("error = %v, want slow_down", body["error"])
	}
}
