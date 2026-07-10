package oidcop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// fixedAppResolver resolves a single fixed app for any client_id lookup.
// Mirrors client_test.go's fakeClientAppResolver shape.
type fixedAppResolver struct {
	resolver.AppResolver
	app *resolver.AppConfig
}

func (f *fixedAppResolver) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	return f.app, nil
}

// newClientCredentialsProvider wires a full op.OpenIDProvider (real HTTP
// stack) over an in-memory Redis, with app resolvable as the only client.
// Confidential-only client_credentials issuance never touches
// Storage.SigningKey (the engine's AccessTokenType is always opaque Bearer,
// encrypted via the provider's own AES CryptoKey — see op.CreateBearerToken),
// so this harness deliberately passes a nil *oidckey.Service: exercising it
// would panic, and nothing in this grant should ever reach it.
func newClientCredentialsProvider(t *testing.T, app *resolver.AppConfig) *httptest.Server {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	clients := NewClientStore(&fixedAppResolver{app: app}, func(string) string { return "" })
	storage := NewStorage(rdb, nil, clients, nil, nil, nil, DefaultConfig())
	var key [32]byte
	provider, err := NewProvider("https://issuer.example.com", storage, key, true, nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)
	return srv
}

func hashSecret(t *testing.T, plain string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

func postClientCredentials(t *testing.T, srv *httptest.Server, clientID, clientSecret, scope string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	// Use an explicit client so the safehttp outbound-HTTP ban guard is not
	// tripped (the package convenience helpers route through the shared default
	// client). This is a loopback httptest server, so there is no SSRF surface.
	resp, err := (&http.Client{}).PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
	return m
}

// TestClientCredentials_ConfidentialClient_IssuesToken proves that a
// confidential (m2m) client presenting its correct client_secret via
// grant_type=client_credentials gets a bearer access token back — the zitadel
// engine parity target for the hand-rolled tokenClientCredentials
// (internal/protocol/oidc/handler.go:928).
func TestClientCredentials_ConfidentialClient_IssuesToken(t *testing.T) {
	app := &resolver.AppConfig{
		ID: 1, ClientID: "m2m-client", ClientType: "m2m", Protocol: "oidc", Status: 1,
		ClientSecret:   hashSecret(t, "s3cr3t"),
		ProtocolConfig: json.RawMessage(`{"grant_types":["client_credentials"],"scopes":["custom:read"]}`),
	}
	srv := newClientCredentialsProvider(t, app)

	resp := postClientCredentials(t, srv, "m2m-client", "s3cr3t", "custom:read")
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", resp.StatusCode, body)
	}
	if s, _ := body["access_token"].(string); s == "" {
		t.Fatalf("expected a non-empty access_token, got %v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body["token_type"])
	}
}

// TestClientCredentials_PublicClient_Rejected proves the fail-closed
// confidential-only gate: a public (spa) client MUST NOT obtain a
// client_credentials token even if it somehow presents a value in the
// client_secret field.
func TestClientCredentials_PublicClient_Rejected(t *testing.T) {
	app := &resolver.AppConfig{
		ID: 2, ClientID: "spa-client", ClientType: "spa", Protocol: "oidc", Status: 1,
		ProtocolConfig: json.RawMessage(`{"grant_types":["client_credentials"]}`),
	}
	srv := newClientCredentialsProvider(t, app)

	resp := postClientCredentials(t, srv, "spa-client", "", "")
	body := decodeJSON(t, resp)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200, want an error status — public clients must never get a client_credentials token (body: %v)", body)
	}
	if errStr, _ := body["error"].(string); errStr == "" {
		t.Fatalf("expected an OAuth error response, got %v", body)
	}
}

// TestClientCredentials_WrongSecret_Rejected proves a confidential client
// presenting an incorrect secret is denied.
func TestClientCredentials_WrongSecret_Rejected(t *testing.T) {
	app := &resolver.AppConfig{
		ID: 3, ClientID: "m2m-client-2", ClientType: "m2m", Protocol: "oidc", Status: 1,
		ClientSecret:   hashSecret(t, "correct-secret"),
		ProtocolConfig: json.RawMessage(`{"grant_types":["client_credentials"]}`),
	}
	srv := newClientCredentialsProvider(t, app)

	resp := postClientCredentials(t, srv, "m2m-client-2", "wrong-secret", "")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200, want an error status for a wrong client_secret")
	}
}
