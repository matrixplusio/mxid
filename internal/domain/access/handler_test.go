package access

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// fakeStepUp is an in-memory StepUpEnforcer. fresh/hasMFA are mutated
// directly by tests to simulate the approver's session state.
type fakeStepUp struct {
	fresh  bool
	hasMFA bool
	mfaErr error
}

func (f *fakeStepUp) Fresh(_ *gin.Context, _ int64) bool { return f.fresh }

func (f *fakeStepUp) HasMFA(_ context.Context, _ int64) (bool, error) {
	return f.hasMFA, f.mfaErr
}

// ── handler-test helpers ──────────────────────────────────────────────────────

// newHandlerWithFakeSvc constructs a Handler backed by in-memory fakes (no DB).
// It reuses the fakes from service_test.go (same package). The default
// fakeStepUp reports a fresh, MFA-enrolled approver so existing tests (none
// of which exercise require_stepup=true eligibilities) are unaffected; tests
// that care about step-up enforcement mutate fakes.stepUp directly.
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
		stepUp:     &fakeStepUp{fresh: true, hasMFA: true},
	}
	svc := NewService(fakes.repo, idGen, fakes.bus, fakes.cache, fakes.matcher, fakes.terminator)
	h := NewHandler(svc, testTenant, fakes.stepUp)
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

func doPUT(r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, path, bytes.NewBufferString(body))
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
		el.PUT("/:id", h.updateEligibility)
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

// seedEligWithStepUp is seedElig but with RequireStepUp set explicitly —
// used by the approve step-up-enforcement tests below.
func seedEligWithStepUp(t *testing.T, fakes *testFakes, idGen *snowflake.Generator, requireStepUp bool) *Eligibility {
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
		RequireStepUp:        requireStepUp,
		Status:               1,
	}
	if err := fakes.repo.CreateEligibility(testCtx, elig); err != nil {
		t.Fatalf("seedEligWithStepUp: %v", err)
	}
	return elig
}

// seedPendingRequest creates a pending request against elig via the service
// (bypassing HTTP), so approve tests exercise only the approve handler.
func seedPendingRequest(t *testing.T, h *Handler, elig *Eligibility) *Request {
	t.Helper()
	req, err := h.svc.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    elig.ID,
		RequestedSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("seedPendingRequest: %v", err)
	}
	return req
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

// ── require_stepup enforcement ────────────────────────────────────────────────
//
// These prove the PAM guarantee: an eligibility with require_stepup=true
// forces a fresh step-up MFA on the approver regardless of the ambient
// StepUpEnforcer state, using the SAME response codes the platform's global
// StepUpMiddleware already returns (authn.CodeStepUpRequired /
// authn.CodeMFAEnrollRequired) so the console SPA's existing step-up modal
// handles it unchanged.

// TestConsoleApprove_RequireStepUp_NotFresh_Returns403AndDoesNotGrant proves
// that a stale (non-fresh) approver session is rejected with 403
// step_up_required and the request is left pending — no grant is created.
func TestConsoleApprove_RequireStepUp_NotFresh_Returns403AndDoesNotGrant(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(50)
	elig := seedEligWithStepUp(t, fakes, idGen, true)
	req := seedPendingRequest(t, h, elig)

	fakes.stepUp.hasMFA = true // has MFA, but NOT fresh
	fakes.stepUp.fresh = false

	r := consoleEngine(h)
	w := doPOST(r, fmt.Sprintf("/api/v1/console/access-requests/%d/approve", req.ID), "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), fmt.Appendf(nil, `"code":%d`, authn.CodeStepUpRequired)) {
		t.Fatalf("want code=%d (CodeStepUpRequired), got body=%s", authn.CodeStepUpRequired, w.Body.String())
	}

	stored, err := fakes.repo.GetRequest(testCtx, req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if stored.Status != StatusPending {
		t.Fatalf("request must remain pending (no grant created), got status=%s", stored.Status)
	}
}

// TestConsoleApprove_RequireStepUp_Fresh_Succeeds proves that a fresh
// step-up session lets the approval proceed.
func TestConsoleApprove_RequireStepUp_Fresh_Succeeds(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(51)
	elig := seedEligWithStepUp(t, fakes, idGen, true)
	req := seedPendingRequest(t, h, elig)

	fakes.stepUp.fresh = true
	fakes.stepUp.hasMFA = true

	r := consoleEngine(h)
	w := doPOST(r, fmt.Sprintf("/api/v1/console/access-requests/%d/approve", req.ID), "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := fakes.repo.GetRequest(testCtx, req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if stored.Status != StatusApproved {
		t.Fatalf("want approved, got status=%s", stored.Status)
	}
}

// TestConsoleApprove_NoStepUpRequired_ApprovesRegardlessOfFreshness proves
// require_stepup=false leaves behavior unchanged: approval proceeds even
// though the approver's session is stale.
func TestConsoleApprove_NoStepUpRequired_ApprovesRegardlessOfFreshness(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(52)
	elig := seedEligWithStepUp(t, fakes, idGen, false)
	req := seedPendingRequest(t, h, elig)

	fakes.stepUp.fresh = false
	fakes.stepUp.hasMFA = false

	r := consoleEngine(h)
	w := doPOST(r, fmt.Sprintf("/api/v1/console/access-requests/%d/approve", req.ID), "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestConsoleApprove_RequireStepUp_NoMFA_Returns403MFAEnrollRequired proves
// that an approver with no MFA factor enrolled gets the enrollment code
// (40331), not the step-up-challenge code (40330).
func TestConsoleApprove_RequireStepUp_NoMFA_Returns403MFAEnrollRequired(t *testing.T) {
	h, fakes := newHandlerWithFakeSvc(t)
	idGen, _ := snowflake.New(53)
	elig := seedEligWithStepUp(t, fakes, idGen, true)
	req := seedPendingRequest(t, h, elig)

	fakes.stepUp.fresh = false
	fakes.stepUp.hasMFA = false

	r := consoleEngine(h)
	w := doPOST(r, fmt.Sprintf("/api/v1/console/access-requests/%d/approve", req.ID), "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), fmt.Appendf(nil, `"code":%d`, authn.CodeMFAEnrollRequired)) {
		t.Fatalf("want code=%d (CodeMFAEnrollRequired), got body=%s", authn.CodeMFAEnrollRequired, w.Body.String())
	}

	stored, err := fakes.repo.GetRequest(testCtx, req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if stored.Status != StatusPending {
		t.Fatalf("request must remain pending (no grant created), got status=%s", stored.Status)
	}
}
