package oidclogout

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/session"
)

// ----------------------------------------------------------------------------
// Test doubles
// ----------------------------------------------------------------------------

// fakeAppResolver resolves apps by ID; only the fields sendLogout reads
// (ClientID, ProtocolConfig) are populated by the tests below.
type fakeAppResolver struct {
	apps map[int64]*resolver.AppConfig
}

func (f *fakeAppResolver) GetApp(_ context.Context, _ string) (*resolver.AppConfig, error) {
	return nil, nil
}
func (f *fakeAppResolver) GetAppByID(_ context.Context, appID int64) (*resolver.AppConfig, error) {
	if cfg, ok := f.apps[appID]; ok {
		return cfg, nil
	}
	return nil, nil
}
func (f *fakeAppResolver) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	return nil, nil
}
func (f *fakeAppResolver) GetCert(_ context.Context, _ int64, _ string) (*resolver.CertConfig, error) {
	return nil, nil
}
func (f *fakeAppResolver) ListCerts(_ context.Context, _ int64) ([]*resolver.CertConfig, error) {
	return nil, nil
}
func (f *fakeAppResolver) ListAllActiveSigningCerts(_ context.Context) ([]*resolver.CertConfig, error) {
	return nil, nil
}
func (f *fakeAppResolver) MintSigningCert(_ context.Context, _ int64) (*resolver.CertConfig, error) {
	return nil, nil
}

// fakeSigner records every claims payload it was asked to sign and returns a
// deterministic token string, so tests stay focused on fan-out targeting
// rather than JWT internals (covered separately in signer_test.go).
type fakeSigner struct {
	mu    sync.Mutex
	calls []LogoutTokenClaims
}

func (f *fakeSigner) SignLogoutToken(_ context.Context, claims LogoutTokenClaims) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, claims)
	return "signed-token", nil
}

// hitCounter is an httptest.Server wrapper that counts POST hits.
type hitCounter struct {
	srv  *httptest.Server
	hits atomic.Int32
}

func newHitCounter(t *testing.T) *hitCounter {
	t.Helper()
	hc := &hitCounter{}
	hc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hc.hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hc.srv.Close)
	return hc
}

// oidcCfgJSON serialises a minimal protocol_config blob with only the
// backchannel_logout_* fields set — the JSON shape shared with the retiring
// hand-rolled engine (internal/protocol/oidc.OIDCConfig).
func oidcCfgJSON(t *testing.T, backchannelURI string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"backchannel_logout_uri": backchannelURI,
	})
	if err != nil {
		t.Fatalf("marshal protocol config: %v", err)
	}
	return b
}

// waitAsync gives the service's detached fan-out goroutine time to complete
// before the test inspects hit counters. Not relied on for exact timing —
// only that delivery (or skip) happens before the deadline.
func waitAsync() { time.Sleep(200 * time.Millisecond) }

// setupServiceHarness builds a Service wired to miniredis with two apps
// (appA, appB) each pointing at its own fake RP httptest server.
func setupServiceHarness(t *testing.T) (svc *Service, sm *session.Manager, idx *Index, rpA, rpB *hitCounter, appA, appB int64) {
	t.Helper()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	sm = session.NewManager(rdb, 30*time.Minute, 12*time.Hour)
	idx = NewIndex(rdb)

	rpA = newHitCounter(t)
	rpB = newHitCounter(t)

	appA = int64(1001)
	appB = int64(1002)

	apps := &fakeAppResolver{
		apps: map[int64]*resolver.AppConfig{
			appA: {ID: appA, ClientID: "client-a", Protocol: "oidc", ProtocolConfig: oidcCfgJSON(t, rpA.srv.URL+"/backchannel-logout")},
			appB: {ID: appB, ClientID: "client-b", Protocol: "oidc", ProtocolConfig: oidcCfgJSON(t, rpB.srv.URL+"/backchannel-logout")},
		},
	}

	svc = NewService(sm, idx, apps, &fakeSigner{}, "https://sso.example.com/protocol/oidc",
		// Loopback httptest servers: the production safehttp client blocks
		// them (SSRF guard), so tests inject a plain http.Client instead.
		&http.Client{Timeout: 5 * time.Second},
		// nil resolvers → `sub` falls back to the raw user id and `iss` to the
		// static issuer, matching the pre-override behaviour these fan-out tests
		// assert on.
		nil, nil, nil,
	)

	return svc, sm, idx, rpA, rpB, appA, appB
}

// ----------------------------------------------------------------------------
// Tests — ported from internal/protocol/oidc/backchannel_logout_test.go
// ----------------------------------------------------------------------------

// TestLogoutUserApp_OnlyTargetsApp verifies LogoutUserApp(userID, appA) posts
// a logout_token to appA's RP and does NOT post to appB's RP, even though the
// user has an active SSO session for both.
func TestLogoutUserApp_OnlyTargetsApp(t *testing.T) {
	svc, sm, idx, rpA, rpB, appA, appB := setupServiceHarness(t)

	ctx := context.Background()
	userID := int64(5001)

	sess, err := sm.Create(ctx, session.NamespaceProtocol, userID, 1, "127.0.0.1", "test-ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appA, 30*time.Minute); err != nil {
		t.Fatalf("track appA: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appB, 30*time.Minute); err != nil {
		t.Fatalf("track appB: %v", err)
	}

	svc.LogoutUserApp(ctx, userID, appA)
	waitAsync()

	if n := rpA.hits.Load(); n != 1 {
		t.Errorf("appA RP: want 1 logout_token hit, got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("appB RP: want 0 hits (must not be logged out), got %d", n)
	}
}

// TestLogoutUserApp_NoSessions is a guard against panics when the user has no
// protocol sessions at all.
func TestLogoutUserApp_NoSessions(t *testing.T) {
	svc, _, _, rpA, rpB, appA, _ := setupServiceHarness(t)

	svc.LogoutUserApp(context.Background(), int64(9999), appA)
	waitAsync()

	if n := rpA.hits.Load(); n != 0 {
		t.Errorf("rpA: want 0 hits with no sessions, got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("rpB: want 0 hits with no sessions, got %d", n)
	}
}

// TestLogoutUserApp_DoesNotDestroySessionTracking is the regression test for
// the JIT peek-not-destroy invariant: a per-app JIT logout must leave the
// session's tracking set intact so a later full offboarding logout still
// reaches the OTHER participating app.
//
//  1. User has one SSO session with appA and appB both tracked.
//  2. JIT per-app logout fires for appA → sends logout_token to appA only.
//  3. Full offboarding logout fires for the same user → MUST still deliver a
//     logout_token to appB (tracking set must still be present).
func TestLogoutUserApp_DoesNotDestroySessionTracking(t *testing.T) {
	svc, sm, idx, rpA, rpB, appA, appB := setupServiceHarness(t)

	ctx := context.Background()
	userID := int64(5003)

	sess, err := sm.Create(ctx, session.NamespaceProtocol, userID, 1, "127.0.0.1", "test-ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appA, 30*time.Minute); err != nil {
		t.Fatalf("track appA: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appB, 30*time.Minute); err != nil {
		t.Fatalf("track appB: %v", err)
	}

	// Step 1: JIT per-app logout for appA only.
	svc.LogoutUserApp(ctx, userID, appA)
	waitAsync()

	if n := rpA.hits.Load(); n != 1 {
		t.Errorf("after JIT logout: appA RP want 1 hit, got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("after JIT logout: appB RP want 0 hits, got %d", n)
	}

	// Step 2: Full offboarding logout — must still reach appB.
	svc.LogoutUser(ctx, userID)
	waitAsync()

	if n := rpA.hits.Load(); n < 1 {
		t.Errorf("after full logout: appA RP want >=1 hit, got %d", n)
	}
	// The critical assertion: appB must have received exactly one
	// logout_token from the full logout. If the JIT path had consumed
	// (deleted) the tracking set via a destructive read, this would be 0.
	if n := rpB.hits.Load(); n != 1 {
		t.Errorf("after full logout: appB RP want 1 hit (regression: JIT path must not consume the tracking set), got %d", n)
	}
}

// TestLogoutUserApp_AppNotInSession verifies no logout is sent when the
// target appID was not among the apps tracked on the user's session (e.g. the
// user never authenticated to that app in this session).
func TestLogoutUserApp_AppNotInSession(t *testing.T) {
	svc, sm, idx, rpA, rpB, appA, appB := setupServiceHarness(t)

	ctx := context.Background()
	userID := int64(5002)

	sess, err := sm.Create(ctx, session.NamespaceProtocol, userID, 1, "127.0.0.1", "test-ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appB, 30*time.Minute); err != nil {
		t.Fatalf("track appB: %v", err)
	}

	svc.LogoutUserApp(ctx, userID, appA)
	waitAsync()

	if n := rpA.hits.Load(); n != 0 {
		t.Errorf("rpA: want 0 hits (app not in session), got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("rpB: want 0 hits (not the target app), got %d", n)
	}
}

// TestLogoutUser_NoSessions guards LogoutUser (the offboarding fan-out)
// against panics when the user has no protocol sessions.
func TestLogoutUser_NoSessions(t *testing.T) {
	svc, _, _, rpA, rpB, _, _ := setupServiceHarness(t)

	svc.LogoutUser(context.Background(), int64(9998))
	waitAsync()

	if n := rpA.hits.Load(); n != 0 {
		t.Errorf("rpA: want 0 hits with no sessions, got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("rpB: want 0 hits with no sessions, got %d", n)
	}
}

// TestLogoutUser_FansOutToAllTrackedApps verifies LogoutUser posts a
// logout_token to every app tracked on the user's protocol session.
func TestLogoutUser_FansOutToAllTrackedApps(t *testing.T) {
	svc, sm, idx, rpA, rpB, appA, appB := setupServiceHarness(t)

	ctx := context.Background()
	userID := int64(5004)

	sess, err := sm.Create(ctx, session.NamespaceProtocol, userID, 1, "127.0.0.1", "test-ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appA, 30*time.Minute); err != nil {
		t.Fatalf("track appA: %v", err)
	}
	if err := idx.Track(ctx, sess.ID, appB, 30*time.Minute); err != nil {
		t.Fatalf("track appB: %v", err)
	}

	svc.LogoutUser(ctx, userID)
	waitAsync()

	if n := rpA.hits.Load(); n != 1 {
		t.Errorf("appA RP: want 1 hit, got %d", n)
	}
	if n := rpB.hits.Load(); n != 1 {
		t.Errorf("appB RP: want 1 hit, got %d", n)
	}
}

// ----------------------------------------------------------------------------
// Subject resolution — the logout_token `sub` must equal the id_token `sub`
// (resolved via the app's subject_strategy), not the raw internal user id.
// ----------------------------------------------------------------------------

type fakeIdentity struct {
	u *resolver.IdentityInfo
}

func (f *fakeIdentity) ResolveUser(context.Context, int64) (*resolver.IdentityInfo, error) {
	return f.u, nil
}
func (f *fakeIdentity) ResolveClaims(context.Context, int64, []string) (map[string]any, error) {
	return nil, nil
}

type fakeTenants struct{ code string }

func (f *fakeTenants) GetTenantCode(context.Context, int64) (string, error) { return f.code, nil }

func TestResolveSubject_UsesStrategyNotRawID(t *testing.T) {
	s := &Service{
		identity: &fakeIdentity{u: &resolver.IdentityInfo{ID: 42, Username: "alice", Email: "alice@x.com", TenantID: 7}},
		tenants:  &fakeTenants{code: "acme"},
	}
	cases := []struct {
		strategy string
		want     string
	}{
		{resolver.StrategyUsername, "alice"},
		{resolver.StrategyUsernameSuffixed, "alice@acme"},
		{resolver.StrategyEmail, "alice@x.com"},
		{resolver.StrategyPersistentID, "42"}, // == raw id by design (why the bug hid here)
	}
	for _, c := range cases {
		app := &resolver.AppConfig{ID: 1, ClientID: "client-a", SubjectStrategy: c.strategy}
		if got := s.resolveSubject(context.Background(), app, 42); got != c.want {
			t.Errorf("strategy %q: want sub=%q, got %q", c.strategy, c.want, got)
		}
	}
}

func TestResolveSubject_FallsBackToRawIDWhenUnwired(t *testing.T) {
	s := &Service{} // nil identity resolver
	app := &resolver.AppConfig{SubjectStrategy: resolver.StrategyUsername}
	if got := s.resolveSubject(context.Background(), app, 99); got != "99" {
		t.Fatalf("nil identity: want raw id 99, got %q", got)
	}
}
