package access

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// ── handler-test helpers ──────────────────────────────────────────────────────

// newHandlerWithFakeSvc constructs a Handler backed by in-memory fakes (no DB).
// It reuses the fakes from service_test.go (same package).
func newHandlerWithFakeSvc(t *testing.T) (*Handler, *testFakes) {
	t.Helper()
	idGen, err := snowflake.New(3)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}
	fakes := &testFakes{
		repo:       newFakeRepo(),
		cache:      &fakeCache{},
		bus:        &fakePublisher{},
		matcher:    fakeMatcher{},
		terminator: &fakeTerminator{},
	}
	svc := NewService(fakes.repo, idGen, fakes.bus, fakes.cache, fakes.matcher, fakes.terminator)
	h := NewHandler(svc, testTenant)
	return h, fakes
}

// injectAuth returns a gin middleware that sets user_id and tenant_id in the
// context — simulating what the auth + tenant middlewares do in production.
func injectAuth(userID, tenantID int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Set("tenant_id", tenantID)
		c.Next()
	}
}

func doPOST(r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func doGET(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	r.ServeHTTP(w, req)
	return w
}

func doDELETE(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, path, nil)
	r.ServeHTTP(w, req)
	return w
}

// portalEngine wires portal routes WITHOUT the feature-flag middleware.
// The feature gate (middleware.RequireFeature) is tested in its own package;
// handler tests focus on the handler behaviour only.
func portalEngine(h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/portal")
	grp.Use(injectAuth(testRequester, testTenant))
	// Wire routes directly, mirroring RegisterPortal but omitting middleware.
	grp.GET("/access-eligibilities", h.myEligibilities)
	rq := grp.Group("/access-requests")
	{
		rq.GET("", h.myRequests)
		rq.POST("", h.createRequest)
		rq.POST("/:id/cancel", h.cancel)
	}
	return r
}

// consoleEngine wires console routes WITHOUT feature-flag or authz middleware.
// The authz middleware is tested in its own package; handler tests focus on
// the handler behaviour only.
func consoleEngine(h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/console")
	grp.Use(injectAuth(testApprover, testTenant))
	// Wire routes directly, mirroring RegisterConsole but omitting middleware.
	el := grp.Group("/access-eligibilities")
	{
		el.GET("", h.listEligibility)
		el.POST("", h.createEligibility)
		el.DELETE("/:id", h.deleteEligibility)
	}
	rq := grp.Group("/access-requests")
	{
		rq.GET("", h.listRequests)
		rq.POST("/:id/approve", h.approve)
		rq.POST("/:id/reject", h.reject)
		rq.POST("/:id/revoke", h.revoke)
	}
	return r
}

// seedElig creates an active eligibility directly via the fakeRepo so
// handler tests can reference a known ID.
func seedElig(t *testing.T, fakes *testFakes, idGen *snowflake.Generator) *Eligibility {
	t.Helper()
	elig := &Eligibility{
		ID:                   idGen.Generate(),
		TenantID:             testTenant,
		TargetKind:           TargetConsole,
		RoleID:               42,
		RequesterSubjectType: "any",
		AllowedDurations:     IntSlice{3600},
		MaxDurationSeconds:   3600,
		ApproverSubjectType:  ApproverRole,
		RequireJustification: false,
		Status:               1,
	}
	if err := fakes.repo.CreateEligibility(testCtx, elig); err != nil {
		t.Fatalf("seedElig: %v", err)
	}
	return elig
}

// ── tests ──────────────────────────────────────────────────────────────────────

func TestPortalCreateRequest_Returns201(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(4)
	elig := seedElig(t, fakes, idGen)

	r := portalEngine(h)
	body := fmt.Sprintf(`{"eligibility_id":"%d","requested_seconds":3600,"justification":"oncall"}`, elig.ID)
	w := doPOST(r, "/api/v1/portal/access-requests", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPortalCreateRequest_NoUserID_Returns401 proves createRequest defends
// against a missing/zero user_id in context (auth middleware normally
// prevents this) instead of creating a request with requester_id=0.
func TestPortalCreateRequest_NoUserID_Returns401(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(40)
	elig := seedElig(t, fakes, idGen)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/portal")
	// No injectAuth here — user_id is absent from context, so h.userID(c) returns 0.
	rq := grp.Group("/access-requests")
	{
		rq.POST("", h.createRequest)
	}

	body := fmt.Sprintf(`{"eligibility_id":"%d","requested_seconds":3600,"justification":"oncall"}`, elig.ID)
	w := doPOST(r, "/api/v1/portal/access-requests", body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPortalListEligibilities_Returns200(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(5)
	seedElig(t, fakes, idGen)

	r := portalEngine(h)
	w := doGET(r, "/api/v1/portal/access-eligibilities")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPortalListRequests_Returns200(t *testing.T) {
	h, _ := newHandlerWithFakeSvc(t)
	r := portalEngine(h)
	w := doGET(r, "/api/v1/portal/access-requests")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPortalCancelRequest_Returns200(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(6)
	elig := seedElig(t, fakes, idGen)

	// Create a request first via service directly so we have an ID.
	svc := h.svc
	req, err := svc.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    elig.ID,
		RequestedSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	r := portalEngine(h)
	w := doPOST(r, fmt.Sprintf("/api/v1/portal/access-requests/%d/cancel", req.ID), "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConsoleListEligibility_Returns200(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(7)
	seedElig(t, fakes, idGen)

	r := consoleEngine(h)
	w := doGET(r, "/api/v1/console/access-eligibilities")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConsoleDeleteEligibility_Returns204(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(8)
	elig := seedElig(t, fakes, idGen)

	r := consoleEngine(h)
	w := doDELETE(r, fmt.Sprintf("/api/v1/console/access-eligibilities/%d", elig.ID))
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConsoleListRequests_Returns200(t *testing.T) {
	h, _ := newHandlerWithFakeSvc(t)
	r := consoleEngine(h)
	w := doGET(r, "/api/v1/console/access-requests")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}
