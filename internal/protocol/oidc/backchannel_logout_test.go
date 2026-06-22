package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/session"
)

// ----------------------------------------------------------------------------
// Fake AppResolver for logout tests.
// Only GetAppByID and ListCerts are exercised by sendBackchannelLogout.
// ----------------------------------------------------------------------------

type fakeAppResolver struct {
	apps  map[int64]*resolver.AppConfig
	certs map[int64][]*resolver.CertConfig
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
func (f *fakeAppResolver) ListCerts(_ context.Context, appID int64) ([]*resolver.CertConfig, error) {
	return f.certs[appID], nil
}
func (f *fakeAppResolver) ListAllActiveSigningCerts(_ context.Context) ([]*resolver.CertConfig, error) {
	return nil, nil
}
func (f *fakeAppResolver) MintSigningCert(_ context.Context, _ int64) (*resolver.CertConfig, error) {
	return nil, nil
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

// testRSAPEM generates a fresh 2048-bit RSA key and returns it as a PKCS1
// PEM string. Small keys are fine for test-time JWTs.
func testRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})
	return string(block)
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

// oidcCfgJSON serialises an OIDCConfig with only BackchannelLogoutURI set.
func oidcCfgJSON(t *testing.T, backchannelURI string) json.RawMessage {
	t.Helper()
	cfg := &OIDCConfig{BackchannelLogoutURI: backchannelURI}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal oidc config: %v", err)
	}
	return b
}

// setupBackchannelHarness builds a Handler wired to miniredis with two apps
// (appA, appB) each pointing at its own fake RP httptest server.
func setupBackchannelHarness(t *testing.T) (h *Handler, sm *session.Manager, store *Store, rpA, rpB *hitCounter, appA, appB int64) {
	t.Helper()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	sm = session.NewManager(rdb, 30*time.Minute, 12*time.Hour)
	store = NewStore(rdb)

	rpA = newHitCounter(t)
	rpB = newHitCounter(t)

	appA = int64(1001)
	appB = int64(1002)

	privPEM := testRSAPEM(t)

	fakeRes := &fakeAppResolver{
		apps: map[int64]*resolver.AppConfig{
			appA: {
				ID:             appA,
				ClientID:       "client-a",
				Protocol:       "oidc",
				ProtocolConfig: oidcCfgJSON(t, rpA.srv.URL+"/backchannel-logout"),
			},
			appB: {
				ID:             appB,
				ClientID:       "client-b",
				Protocol:       "oidc",
				ProtocolConfig: oidcCfgJSON(t, rpB.srv.URL+"/backchannel-logout"),
			},
		},
		certs: map[int64][]*resolver.CertConfig{
			appA: {{ID: 1, AppID: appA, PrivateKey: privPEM, KID: "kid-a"}},
			appB: {{ID: 2, AppID: appB, PrivateKey: privPEM, KID: "kid-b"}},
		},
	}

	h = &Handler{
		issuer:     "https://sso.example.com",
		sessionMgr: sm,
		store:      store,
		appRes:     fakeRes,
		// Use a plain http.Client in tests: httptest servers are on loopback,
		// which the production SSRF-safe client intentionally blocks.
		backchannelClient: &http.Client{Timeout: 5 * time.Second},
	}

	return h, sm, store, rpA, rpB, appA, appB
}

// waitAsync gives goroutines spawned by LogoutUserAppBackchannel time to
// complete before the test checks hit counters.  In CI the httptest server is
// on localhost so 200 ms is ample; the test explicitly does not rely on exact
// timing but on the fact that the POST must have been delivered (or skipped)
// before the deadline.
func waitAsync() { time.Sleep(200 * time.Millisecond) }

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

// TestLogoutUserAppBackchannel_OnlyTargetsApp verifies that calling
// LogoutUserAppBackchannel(userID, appA) posts a logout_token to appA's RP
// and does NOT post to appB's RP, even though the user has an active SSO
// session for both.
func TestLogoutUserAppBackchannel_OnlyTargetsApp(t *testing.T) {
	h, sm, store, rpA, rpB, appA, appB := setupBackchannelHarness(t)

	ctx := context.Background()
	userID := int64(5001)

	// Seed one protocol SSO session for the user, with both appA and appB tracked.
	sess, err := sm.Create(ctx, session.NamespaceProtocol, userID, 1, "127.0.0.1", "test-ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sessionTTL := 30 * time.Minute
	if err := store.TrackSSOApp(ctx, sess.ID, appA, sessionTTL); err != nil {
		t.Fatalf("track appA: %v", err)
	}
	if err := store.TrackSSOApp(ctx, sess.ID, appB, sessionTTL); err != nil {
		t.Fatalf("track appB: %v", err)
	}

	// Target only appA.
	h.LogoutUserAppBackchannel(ctx, userID, appA)
	waitAsync()

	if n := rpA.hits.Load(); n != 1 {
		t.Errorf("appA RP: want 1 logout_token hit, got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("appB RP: want 0 hits (must not be logged out), got %d", n)
	}
}

// TestLogoutUserAppBackchannel_NoSessions is a guard against panics when
// the user has no protocol sessions at all.
func TestLogoutUserAppBackchannel_NoSessions(t *testing.T) {
	h, _, _, rpA, rpB, appA, _ := setupBackchannelHarness(t)

	// No sessions seeded — must return silently.
	h.LogoutUserAppBackchannel(context.Background(), int64(9999), appA)
	waitAsync()

	if n := rpA.hits.Load(); n != 0 {
		t.Errorf("rpA: want 0 hits with no sessions, got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("rpB: want 0 hits with no sessions, got %d", n)
	}
}

// TestLogoutUserAppBackchannel_AppNotInSession verifies no logout is sent when
// the target appID was not among the apps tracked on the user's session (e.g.
// the user never authenticated to that app in this session).
func TestLogoutUserAppBackchannel_AppNotInSession(t *testing.T) {
	h, sm, store, rpA, rpB, appA, appB := setupBackchannelHarness(t)

	ctx := context.Background()
	userID := int64(5002)

	// Seed a session for the user but track only appB.
	sess, err := sm.Create(ctx, session.NamespaceProtocol, userID, 1, "127.0.0.1", "test-ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.TrackSSOApp(ctx, sess.ID, appB, 30*time.Minute); err != nil {
		t.Fatalf("track appB: %v", err)
	}

	// Request logout for appA which was NOT tracked on this session.
	h.LogoutUserAppBackchannel(ctx, userID, appA)
	waitAsync()

	if n := rpA.hits.Load(); n != 0 {
		t.Errorf("rpA: want 0 hits (app not in session), got %d", n)
	}
	if n := rpB.hits.Load(); n != 0 {
		t.Errorf("rpB: want 0 hits (not the target app), got %d", n)
	}
}
