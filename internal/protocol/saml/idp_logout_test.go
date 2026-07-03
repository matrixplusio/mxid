package saml

import (
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"go.uber.org/zap"
)

// decodeSAMLRedirectParam reverses the HTTP-Redirect binding payload encoding
// (base64 -> raw DEFLATE) back to the original XML string.
func decodeSAMLRedirectParam(t *testing.T, v string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("base64 decode SAMLRequest: %v", err)
	}
	fr := flate.NewReader(strings.NewReader(string(raw)))
	defer fr.Close()
	out, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}
	return string(out)
}

// recordingSP stands in for a SAML SP's SLO endpoint. It counts requests and
// remembers the query params of every request received (in arrival order),
// including the most recent one for convenience.
type recordingSP struct {
	srv      *httptest.Server
	count    atomic.Int64
	mu       sync.Mutex
	all      []url.Values
	lastQuer url.Values
}

func (r *recordingSP) hits() int { return int(r.count.Load()) }

func (r *recordingSP) lastHadParam(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.lastQuer[name]
	return ok
}

func (r *recordingSP) lastParam(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastQuer.Get(name)
}

// allRequests returns a snapshot of every request's query params, in the
// order they were received.
func (r *recordingSP) allRequests() []url.Values {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]url.Values, len(r.all))
	copy(out, r.all)
	return out
}

func newRecordingSP(t *testing.T) *recordingSP {
	t.Helper()
	sp := &recordingSP{}
	sp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sp.count.Add(1)
		sp.mu.Lock()
		sp.lastQuer = req.URL.Query()
		sp.all = append(sp.all, req.URL.Query())
		sp.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sp.srv.Close)
	return sp
}

// testSigningCert generates an RSA key + self-signed cert PEM for an app so the
// AppResolver stub can hand the handler real signing material.
func testSigningCert(t *testing.T, appID int64) *resolver.CertConfig {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mxid-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &resolver.CertConfig{
		ID:         1,
		AppID:      appID,
		CertType:   "signing",
		Algorithm:  "RS256",
		PublicKey:  string(certPEM),
		PrivateKey: string(keyPEM),
		Status:     1,
	}
}

// setupSAMLLogoutHarness wires a Handler whose AppResolver returns a SAML app
// pointed at a recording SP's SLO endpoint, an injected loopback-capable HTTP
// doer (production uses the SSRF-safe client), and an in-memory session index.
func setupSAMLLogoutHarness(t *testing.T) (*Handler, *SessionIndexStore, *recordingSP) {
	t.Helper()
	sp := newRecordingSP(t)
	const appID = int64(1001)
	cert := testSigningCert(t, appID)

	cfg := SAMLConfig{
		SPEntityID: "sp",
		SLOURL:     sp.srv.URL + "/slo",
	}
	cfgRaw, _ := json.Marshal(cfg)

	appCfg := &resolver.AppConfig{
		ID:             appID,
		Protocol:       "saml",
		Code:           "sp-app",
		ProtocolConfig: cfgRaw,
	}

	appRes := resolver.NewAppResolver(
		func(ctx context.Context, tenantID int64, code string) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, id int64) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, clientID string) (*resolver.AppConfig, error) { return appCfg, nil },
		func(ctx context.Context, id int64, certType string) (*resolver.CertConfig, error) { return cert, nil },
		func(ctx context.Context, id int64) ([]*resolver.CertConfig, error) {
			return []*resolver.CertConfig{cert}, nil
		},
		func(ctx context.Context) ([]*resolver.CertConfig, error) { return []*resolver.CertConfig{cert}, nil },
		func(ctx context.Context, id int64) (*resolver.CertConfig, error) { return cert, nil },
	)

	idxStore := NewSessionIndexStore(miniredisClient(t))

	h := NewHandler("https://idp.example", "https://idp.example", appRes, nil, nil, nil, idxStore, zap.NewNop())
	// Inject a loopback-capable doer so the httptest SP (127.0.0.1) is reachable.
	// Production always uses the package-level SSRF-safe samlBackchannelClient.
	h.backchannelClient = &http.Client{Timeout: 5 * time.Second}
	return h, idxStore, sp
}

func waitAsync() { time.Sleep(200 * time.Millisecond) }

func TestIdPInitiatedLogout_HitsSPWithSignedRequest(t *testing.T) {
	h, idxStore, sp := setupSAMLLogoutHarness(t)
	userID, appID := int64(5001), int64(1001)
	if err := idxStore.Record(context.Background(), userID, appID,
		SAMLSessionRef{SessionIndex: "idx-1", NameID: "u@x", SPEntityID: "sp"}, time.Hour); err != nil {
		t.Fatalf("record: %v", err)
	}

	h.IdPInitiatedLogout(context.Background(), userID, appID)
	waitAsync()

	if sp.hits() != 1 {
		t.Fatalf("SP SLO endpoint should receive 1 LogoutRequest, got %d", sp.hits())
	}
	if !sp.lastHadParam("SAMLRequest") {
		t.Fatal("LogoutRequest missing SAMLRequest param")
	}
	if !sp.lastHadParam("Signature") {
		t.Fatal("LogoutRequest missing Signature param")
	}
	if !sp.lastHadParam("SigAlg") {
		t.Fatal("LogoutRequest missing SigAlg param")
	}

	// The SAMLRequest must decode to a <LogoutRequest> carrying the stored
	// SessionIndex + NameID — that is what targets the specific SP session.
	xmlStr := decodeSAMLRedirectParam(t, sp.lastParam("SAMLRequest"))
	for _, want := range []string{"LogoutRequest", "idx-1", "u@x"} {
		if !strings.Contains(xmlStr, want) {
			t.Fatalf("LogoutRequest XML missing %q; got:\n%s", want, xmlStr)
		}
	}

	// The index entry must be removed after dispatch.
	refs, err := idxStore.Get(context.Background(), userID, appID)
	if err != nil {
		t.Fatalf("get after logout: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("session index should be deleted after logout, got %d refs", len(refs))
	}
}

// TestIdPInitiatedLogout_MultipleSessions verifies the multi-session SLO fix:
// when a user has two concurrent SAML sessions to the same app (e.g. two
// browsers), both must be terminated — the SP must receive one signed
// LogoutRequest per SessionIndex, not just the most-recently recorded one.
func TestIdPInitiatedLogout_MultipleSessions(t *testing.T) {
	h, idxStore, sp := setupSAMLLogoutHarness(t)
	userID, appID := int64(5002), int64(1001)

	if err := idxStore.Record(context.Background(), userID, appID,
		SAMLSessionRef{SessionIndex: "idx-a", NameID: "u@x", SPEntityID: "sp", NameIDFormat: NameIDEmail}, time.Hour); err != nil {
		t.Fatalf("record ref A: %v", err)
	}
	if err := idxStore.Record(context.Background(), userID, appID,
		SAMLSessionRef{SessionIndex: "idx-b", NameID: "u@x", SPEntityID: "sp", NameIDFormat: NameIDEmail}, time.Hour); err != nil {
		t.Fatalf("record ref B: %v", err)
	}

	h.IdPInitiatedLogout(context.Background(), userID, appID)
	waitAsync()

	if sp.hits() != 2 {
		t.Fatalf("SP SLO endpoint should receive 2 LogoutRequests (one per session), got %d", sp.hits())
	}

	// Each request must carry its own distinct SessionIndex.
	seenIdx := map[string]bool{}
	for _, q := range sp.allRequests() {
		if !q.Has("SAMLRequest") || !q.Has("Signature") || !q.Has("SigAlg") {
			t.Fatalf("LogoutRequest missing a required redirect-binding param: %v", q)
		}
		xmlStr := decodeSAMLRedirectParam(t, q.Get("SAMLRequest"))
		if !strings.Contains(xmlStr, "LogoutRequest") {
			t.Fatalf("expected <LogoutRequest> in decoded XML, got:\n%s", xmlStr)
		}
		switch {
		case strings.Contains(xmlStr, "idx-a"):
			seenIdx["idx-a"] = true
		case strings.Contains(xmlStr, "idx-b"):
			seenIdx["idx-b"] = true
		}
	}
	if !seenIdx["idx-a"] || !seenIdx["idx-b"] {
		t.Fatalf("want both SessionIndex idx-a and idx-b sent, got %+v", seenIdx)
	}

	// Both refs must be dropped from the index in a single Delete once
	// dispatch is done.
	refs, err := idxStore.Get(context.Background(), userID, appID)
	if err != nil {
		t.Fatalf("get after logout: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("session index should be fully cleared after logout, got %d refs", len(refs))
	}
}
