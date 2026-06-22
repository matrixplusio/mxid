package cas

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// stubSP is a minimal httptest.Server that records CAS logoutRequest POSTs.
type stubSP struct {
	srv       *httptest.Server
	postCount atomic.Int32
	lastBody  atomic.Value // stores string
}

func newStubSP(t *testing.T) *stubSP {
	t.Helper()
	sp := &stubSP{}
	sp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		sp.lastBody.Store(string(body))
		sp.postCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sp.srv.Close)
	return sp
}

func (s *stubSP) posts() int                       { return int(s.postCount.Load()) }
func (s *stubSP) lastBodyStr() string              { v := s.lastBody.Load(); if v == nil { return "" }; return v.(string) }
func (s *stubSP) lastBodyContains(sub string) bool { return strings.Contains(s.lastBodyStr(), sub) }

// extractLogoutRequestID extracts the ID attribute value from a CAS logoutRequest
// form body (URL-encoded). The body looks like: logoutRequest=<url-encoded XML>.
func extractLogoutRequestID(rawBody string) string {
	vals, err := url.ParseQuery(rawBody)
	if err != nil {
		return ""
	}
	xml := vals.Get("logoutRequest")
	// ID attribute appears as: ... ID="LR-..." ...
	const prefix = ` ID="`
	idx := strings.Index(xml, prefix)
	if idx < 0 {
		return ""
	}
	rest := xml[idx+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// waitAsync gives the goroutines spawned by SingleLogout time to complete.
func waitAsync() { time.Sleep(150 * time.Millisecond) }

// newSLOHandler builds a Handler wired for SLO testing: real ServiceRegistry
// backed by miniredis, a nop logger, and a plain http.Client so the httptest
// SP on loopback can be reached (the SSRF guard blocks loopback in prod).
func newSLOHandler(t *testing.T, doer httpDoer) (*Handler, *ServiceRegistry) {
	t.Helper()
	rdb := miniredisClient(t)
	reg := NewServiceRegistry(rdb)
	h := &Handler{
		serviceRegistry:   reg,
		logger:            zap.NewNop(),
		backchannelClient: doer,
		// appRes is nil: SingleLogout handles nil by skipping the LogoutURL
		// override and using the recorded ServiceURL directly.
	}
	return h, reg
}

// TestSingleLogout_PostsLogoutRequestPerService verifies that SingleLogout
// POSTs one CAS logoutRequest to the recorded service URL, the body contains
// both "LogoutRequest" and the original service ticket, and the registry is
// cleared afterwards.
func TestSingleLogout_PostsLogoutRequestPerService(t *testing.T) {
	sp := newStubSP(t)
	h, reg := newSLOHandler(t, sp.srv.Client())

	userID, appID := int64(5001), int64(1001)
	if err := reg.RecordService(context.Background(), userID, appID, sp.srv.URL, "ST-9", time.Hour); err != nil {
		t.Fatalf("RecordService: %v", err)
	}

	h.SingleLogout(context.Background(), userID, appID)
	waitAsync()

	if sp.posts() != 1 {
		t.Fatalf("service should receive 1 logout POST, got %d", sp.posts())
	}
	if !sp.lastBodyContains("LogoutRequest") {
		t.Fatalf("CAS logout body missing 'LogoutRequest'; got: %s", sp.lastBodyStr())
	}
	if !sp.lastBodyContains("ST-9") {
		t.Fatalf("CAS logout body missing ticket 'ST-9'; got: %s", sp.lastBodyStr())
	}

	// Registry should be cleared after SingleLogout.
	remaining, err := reg.ListServices(context.Background(), userID, appID)
	if err != nil {
		t.Fatalf("ListServices after logout: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("registry should be cleared after SingleLogout, got %d entries", len(remaining))
	}
}

// TestSingleLogout_MultipleServices verifies that SingleLogout posts to ALL
// recorded services (fan-out), not just the first one.
func TestSingleLogout_MultipleServices(t *testing.T) {
	sp1 := newStubSP(t)
	sp2 := newStubSP(t)

	// Use a multi-dispatch doer that routes based on URL.
	// We record both services; use a dispatcher that routes to sp1 or sp2.
	dispatcher := &routingDoer{routes: map[string]*stubSP{
		sp1.srv.URL: sp1,
		sp2.srv.URL: sp2,
	}}

	h, reg := newSLOHandler(t, dispatcher)
	ctx := context.Background()
	userID, appID := int64(5002), int64(1002)

	if err := reg.RecordService(ctx, userID, appID, sp1.srv.URL, "ST-A", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := reg.RecordService(ctx, userID, appID, sp2.srv.URL, "ST-B", time.Hour); err != nil {
		t.Fatal(err)
	}

	h.SingleLogout(ctx, userID, appID)
	waitAsync()

	if sp1.posts() != 1 {
		t.Errorf("sp1 should receive 1 POST, got %d", sp1.posts())
	}
	if sp2.posts() != 1 {
		t.Errorf("sp2 should receive 1 POST, got %d", sp2.posts())
	}

	// Both tickets should appear in their respective SP bodies.
	if !sp1.lastBodyContains("ST-A") && !sp2.lastBodyContains("ST-A") {
		t.Error("ticket ST-A not found in any SP body")
	}
	if !sp1.lastBodyContains("ST-B") && !sp2.lastBodyContains("ST-B") {
		t.Error("ticket ST-B not found in any SP body")
	}

	// Each LogoutRequest must have a unique ID (Fix 1: index suffix prevents collisions).
	id1 := extractLogoutRequestID(sp1.lastBodyStr())
	id2 := extractLogoutRequestID(sp2.lastBodyStr())
	if id1 == "" || id2 == "" {
		t.Errorf("could not extract LogoutRequest IDs (id1=%q id2=%q)", id1, id2)
	} else if id1 == id2 {
		t.Errorf("LogoutRequest IDs must be unique across services, both were %q", id1)
	}
}

// TestSingleLogout_NoServices verifies that SingleLogout is a no-op when
// there are no recorded services (no POST, no error).
func TestSingleLogout_NoServices(t *testing.T) {
	sp := newStubSP(t)
	h, _ := newSLOHandler(t, sp.srv.Client())

	// Do NOT record any service for this (userID, appID) pair.
	h.SingleLogout(context.Background(), int64(9999), int64(8888))
	waitAsync()

	if sp.posts() != 0 {
		t.Fatalf("expected no POSTs for empty registry, got %d", sp.posts())
	}
}

// routingDoer dispatches Do calls to the correct stubSP by matching the
// request URL prefix to a registered route.
type routingDoer struct {
	routes map[string]*stubSP
}

func (d *routingDoer) Do(req *http.Request) (*http.Response, error) {
	// Find the matching stubSP by host.
	for prefix, sp := range d.routes {
		if strings.HasPrefix(req.URL.String(), prefix) {
			return sp.srv.Client().Do(req)
		}
	}
	// Fallback: let the default transport handle it.
	return http.DefaultClient.Do(req)
}
