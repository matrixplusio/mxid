package cas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"go.uber.org/zap"
)

// --- stubs ---------------------------------------------------------------

// stubAppResolver serves a single fixed app for GetApp; the rest of the
// AppResolver surface is unused by the proxy path.
type stubAppResolver struct{ app *resolver.AppConfig }

func (s stubAppResolver) GetApp(context.Context, string) (*resolver.AppConfig, error) {
	return s.app, nil
}
func (s stubAppResolver) GetAppByID(context.Context, int64) (*resolver.AppConfig, error) {
	return s.app, nil
}
func (s stubAppResolver) GetAppByClientID(context.Context, string) (*resolver.AppConfig, error) {
	return s.app, nil
}
func (stubAppResolver) GetCert(context.Context, int64, string) (*resolver.CertConfig, error) {
	return nil, nil
}
func (stubAppResolver) ListCerts(context.Context, int64) ([]*resolver.CertConfig, error) {
	return nil, nil
}
func (stubAppResolver) ListAllActiveSigningCerts(context.Context) ([]*resolver.CertConfig, error) {
	return nil, nil
}
func (stubAppResolver) MintSigningCert(context.Context, int64) (*resolver.CertConfig, error) {
	return nil, nil
}

// captureDoer records the last pgtUrl callback and returns a scripted status.
type captureDoer struct {
	status  int
	lastURL atomic.Value // string
}

func (d *captureDoer) Do(req *http.Request) (*http.Response, error) {
	d.lastURL.Store(req.URL.String())
	st := d.status
	if st == 0 {
		st = http.StatusOK
	}
	return &http.Response{StatusCode: st, Body: io.NopCloser(strings.NewReader(""))}, nil
}
func (d *captureDoer) last() string { v := d.lastURL.Load(); if v == nil { return "" }; return v.(string) }

func casAppConfig(id int64, proxyEnabled bool, serviceURLs ...string) *resolver.AppConfig {
	cfg := map[string]any{"proxy_enabled": proxyEnabled, "service_urls": serviceURLs, "pgt_ticket_ttl": 3600}
	raw, _ := json.Marshal(cfg)
	return &resolver.AppConfig{ID: id, Code: "app1", Status: 1, Protocol: "cas", ProtocolConfig: raw}
}

func newProxyHandler(t *testing.T, app *resolver.AppConfig, doer httpDoer) *Handler {
	t.Helper()
	return &Handler{
		appRes:            stubAppResolver{app: app},
		store:             NewTicketStore(miniredisClient(t)),
		logger:            zap.NewNop(),
		backchannelClient: doer,
	}
}

// runGET calls handler h with the given app_code param + query, returns the body.
func runGET(h func(*gin.Context), appCode, rawQuery string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "app_code", Value: appCode}}
	c.Request = httptest.NewRequest("GET", "/?"+rawQuery, nil)
	h(c)
	return w
}

// --- tests ---------------------------------------------------------------

// The proxy chain must prepend each proxying service's pgtUrl, most-recent
// first, as a proxy ticket is minted from a PGT (and a PGT minted from a PT
// inherits that PT's chain).
func TestProxyTicket_ChainOrder(t *testing.T) {
	store := NewTicketStore(miniredisClient(t))
	ctx := context.Background()

	// PGT_A from a service ticket: empty inherited chain, pgtUrl = A.
	pgtA, err := store.CreatePGT(ctx, 5, 1, 9, "alice", "https://a.example/cb", nil, 3600)
	if err != nil {
		t.Fatalf("CreatePGT A: %v", err)
	}
	pt1, err := store.CreateProxyTicket(ctx, pgtA, "https://backend-b.example")
	if err != nil {
		t.Fatalf("CreateProxyTicket 1: %v", err)
	}
	if !pt1.IsProxy || len(pt1.Proxies) != 1 || pt1.Proxies[0] != "https://a.example/cb" {
		t.Fatalf("PT1 chain = %v (isProxy=%v), want [https://a.example/cb]", pt1.Proxies, pt1.IsProxy)
	}

	// PGT_B minted from PT1 (B validated PT1 with its own pgtUrl): inherits PT1's chain.
	pgtB, err := store.CreatePGT(ctx, 5, 1, 9, "alice", "https://b.example/cb", pt1.Proxies, 3600)
	if err != nil {
		t.Fatalf("CreatePGT B: %v", err)
	}
	pt2, err := store.CreateProxyTicket(ctx, pgtB, "https://backend-c.example")
	if err != nil {
		t.Fatalf("CreateProxyTicket 2: %v", err)
	}
	want := []string{"https://b.example/cb", "https://a.example/cb"}
	if len(pt2.Proxies) != 2 || pt2.Proxies[0] != want[0] || pt2.Proxies[1] != want[1] {
		t.Fatalf("PT2 chain = %v, want %v (most-recent first)", pt2.Proxies, want)
	}

	// The PT is single-use and carries IsProxy through the store.
	got, err := store.ConsumeTicket(ctx, pt2.Ticket)
	if err != nil || !got.IsProxy {
		t.Fatalf("ConsumeTicket PT2: got=%+v err=%v", got, err)
	}
}

// /proxy issues a proxy ticket for a valid PGT + allow-listed targetService.
func TestProxy_IssuesProxyTicket(t *testing.T) {
	app := casAppConfig(9, true, "https://backend.example")
	h := newProxyHandler(t, app, nil)
	pgt, err := h.store.CreatePGT(context.Background(), 5, 1, 9, "alice", "https://sp.example/cb", nil, 3600)
	if err != nil {
		t.Fatalf("CreatePGT: %v", err)
	}

	w := runGET(h.proxy, "app1", "pgt="+pgt.PGT+"&targetService="+url.QueryEscape("https://backend.example/api"))
	body := w.Body.String()
	if !strings.Contains(body, "<cas:proxySuccess>") || !strings.Contains(body, "PT-") {
		t.Fatalf("expected proxySuccess with a PT, got: %s", body)
	}
}

// /proxy is refused when the app has proxy disabled.
func TestProxy_DisabledRejected(t *testing.T) {
	app := casAppConfig(9, false, "https://backend.example")
	h := newProxyHandler(t, app, nil)
	pgt, _ := h.store.CreatePGT(context.Background(), 5, 1, 9, "alice", "https://sp.example/cb", nil, 3600)

	w := runGET(h.proxy, "app1", "pgt="+pgt.PGT+"&targetService="+url.QueryEscape("https://backend.example/api"))
	if !strings.Contains(w.Body.String(), `code="UNAUTHORIZED_SERVICE"`) {
		t.Fatalf("proxy disabled must fail UNAUTHORIZED_SERVICE, got: %s", w.Body.String())
	}
}

// A PGT minted by another app cannot mint tickets here.
func TestProxy_WrongAppRejected(t *testing.T) {
	app := casAppConfig(9, true, "https://backend.example")
	h := newProxyHandler(t, app, nil)
	// PGT bound to app 999, not 9.
	pgt, _ := h.store.CreatePGT(context.Background(), 5, 1, 999, "alice", "https://sp.example/cb", nil, 3600)

	w := runGET(h.proxy, "app1", "pgt="+pgt.PGT+"&targetService="+url.QueryEscape("https://backend.example/api"))
	if !strings.Contains(w.Body.String(), `code="BAD_PGT"`) {
		t.Fatalf("cross-app PGT must fail BAD_PGT, got: %s", w.Body.String())
	}
}

// targetService outside the app's allow-list is refused (fail-closed).
func TestProxy_TargetNotAllowlisted(t *testing.T) {
	app := casAppConfig(9, true, "https://backend.example")
	h := newProxyHandler(t, app, nil)
	pgt, _ := h.store.CreatePGT(context.Background(), 5, 1, 9, "alice", "https://sp.example/cb", nil, 3600)

	w := runGET(h.proxy, "app1", "pgt="+pgt.PGT+"&targetService="+url.QueryEscape("https://evil.example/api"))
	if !strings.Contains(w.Body.String(), `code="UNAUTHORIZED_SERVICE"`) {
		t.Fatalf("unlisted targetService must fail UNAUTHORIZED_SERVICE, got: %s", w.Body.String())
	}
}

// serviceValidate must REJECT a proxy ticket; proxyValidate accepts it and
// reports the <cas:proxies> chain.
func TestValidate_ProxyTicketOnlyAtProxyValidate(t *testing.T) {
	app := casAppConfig(9, true, "https://backend.example")
	target := "https://backend.example/api"

	// serviceValidate rejects a PT.
	h1 := newProxyHandler(t, app, nil)
	pgt1, _ := h1.store.CreatePGT(context.Background(), 5, 1, 9, "alice", "https://sp.example/cb", nil, 3600)
	pt1, _ := h1.store.CreateProxyTicket(context.Background(), pgt1, target)
	w1 := runGET(h1.serviceValidate, "app1", "ticket="+pt1.Ticket+"&service="+url.QueryEscape(target))
	if !strings.Contains(w1.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("serviceValidate must reject a PT, got: %s", w1.Body.String())
	}

	// proxyValidate accepts it and lists the proxy chain.
	h2 := newProxyHandler(t, app, nil)
	pgt2, _ := h2.store.CreatePGT(context.Background(), 5, 1, 9, "alice", "https://sp.example/cb", nil, 3600)
	pt2, _ := h2.store.CreateProxyTicket(context.Background(), pgt2, target)
	w2 := runGET(h2.proxyValidate, "app1", "ticket="+pt2.Ticket+"&service="+url.QueryEscape(target))
	body := w2.Body.String()
	if !strings.Contains(body, "<cas:authenticationSuccess>") {
		t.Fatalf("proxyValidate must accept a PT, got: %s", body)
	}
	if !strings.Contains(body, "<cas:proxies>") || !strings.Contains(body, "https://sp.example/cb") {
		t.Fatalf("proxyValidate must report the proxy chain, got: %s", body)
	}
}

// maybeIssuePGT: happy path mints a PGT, hits the callback with pgtId+pgtIou,
// and returns the PGTIOU to embed in the response.
func TestMaybeIssuePGT_CallbackAndGate(t *testing.T) {
	app := casAppConfig(9, true, "https://sp.example")
	st := &ServiceTicket{UserID: 5, TenantID: 1, Username: "alice"}

	// Happy path.
	doer := &captureDoer{status: 200}
	h := newProxyHandler(t, app, doer)
	cfg := h.parseCASConfig(app.ProtocolConfig)
	c := ginCtx()
	iou := h.maybeIssuePGT(c, cfg, app, st, "https://sp.example/pgtCallback")
	if !strings.HasPrefix(iou, "PGTIOU-") {
		t.Fatalf("expected a PGTIOU, got %q", iou)
	}
	cb := doer.last()
	if !strings.Contains(cb, "pgtId=PGT-") || !strings.Contains(cb, "pgtIou=PGTIOU-") {
		t.Fatalf("callback must carry pgtId + pgtIou, got %q", cb)
	}

	// Proxy disabled → no PGT, no callback.
	doer2 := &captureDoer{status: 200}
	appOff := casAppConfig(9, false, "https://sp.example")
	h2 := newProxyHandler(t, appOff, doer2)
	if iou := h2.maybeIssuePGT(ginCtx(), h2.parseCASConfig(appOff.ProtocolConfig), appOff, st, "https://sp.example/cb"); iou != "" {
		t.Fatalf("proxy disabled must not mint a PGT, got %q", iou)
	}
	if doer2.last() != "" {
		t.Fatal("proxy disabled must not call pgtUrl")
	}

	// pgtUrl outside the allow-list → no PGT.
	doer3 := &captureDoer{status: 200}
	h3 := newProxyHandler(t, app, doer3)
	if iou := h3.maybeIssuePGT(ginCtx(), h3.parseCASConfig(app.ProtocolConfig), app, st, "https://evil.example/cb"); iou != "" {
		t.Fatalf("unlisted pgtUrl must not mint a PGT, got %q", iou)
	}

	// Callback non-2xx → PGT rolled back, empty return.
	doer4 := &captureDoer{status: 500}
	h4 := newProxyHandler(t, app, doer4)
	if iou := h4.maybeIssuePGT(ginCtx(), h4.parseCASConfig(app.ProtocolConfig), app, st, "https://sp.example/cb"); iou != "" {
		t.Fatalf("failed callback must not yield a PGTIOU, got %q", iou)
	}
}

func ginCtx() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	return c
}
