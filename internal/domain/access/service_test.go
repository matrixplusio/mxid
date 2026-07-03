package access

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

// fakeRepo is an in-memory Repository.
type fakeRepo struct {
	mu            sync.Mutex
	eligibilities map[int64]*Eligibility
	requests      map[int64]*Request
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		eligibilities: make(map[int64]*Eligibility),
		requests:      make(map[int64]*Request),
	}
}

func (r *fakeRepo) CreateEligibility(_ context.Context, e *Eligibility) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *e
	r.eligibilities[e.ID] = &cp
	return nil
}

func (r *fakeRepo) GetEligibility(_ context.Context, id, tenantID int64) (*Eligibility, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.eligibilities[id]
	if !ok || e.TenantID != tenantID {
		return nil, errors.New("eligibility not found")
	}
	cp := *e
	return &cp, nil
}

func (r *fakeRepo) ListEligibility(_ context.Context, tenantID int64) ([]*Eligibility, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Eligibility
	for _, e := range r.eligibilities {
		if e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeRepo) DeleteEligibility(_ context.Context, id, _ int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.eligibilities, id)
	return nil
}

func (r *fakeRepo) CreateRequest(_ context.Context, req *Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *req
	r.requests[req.ID] = &cp
	return nil
}

func (r *fakeRepo) GetRequest(_ context.Context, id, tenantID int64) (*Request, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	req, ok := r.requests[id]
	if !ok || req.TenantID != tenantID {
		return nil, errors.New("request not found")
	}
	cp := *req
	return &cp, nil
}

func (r *fakeRepo) ListRequestsByStatus(_ context.Context, tenantID int64, status string) ([]*Request, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Request
	for _, req := range r.requests {
		if req.TenantID == tenantID && req.Status == status {
			cp := *req
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeRepo) ListRequestsByRequester(_ context.Context, requesterID, tenantID int64) ([]*Request, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Request
	for _, req := range r.requests {
		if req.TenantID == tenantID && req.RequesterID == requesterID {
			cp := *req
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *fakeRepo) ApproveAndGrant(_ context.Context, req *Request, approverID int64, expiresAt time.Time, newBindingID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.requests[req.ID]
	if !ok {
		return errors.New("request not found")
	}
	stored.Status = StatusApproved
	stored.ApproverID = &approverID
	stored.ExpiresAt = &expiresAt
	stored.BindingID = &newBindingID
	return nil
}

func (r *fakeRepo) UpdateRequestStatus(_ context.Context, id, tenantID int64, status, reason string, approverID *int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	req, ok := r.requests[id]
	if !ok || req.TenantID != tenantID {
		return errors.New("request not found")
	}
	req.Status = status
	req.DecisionReason = reason
	if approverID != nil {
		req.ApproverID = approverID
	}
	return nil
}

func (r *fakeRepo) EndGrant(_ context.Context, req *Request, finalStatus string, _ int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.requests[req.ID]
	if !ok {
		return errors.New("request not found")
	}
	stored.Status = finalStatus
	return nil
}

func (r *fakeRepo) ListDueGrants(_ context.Context) ([]*Request, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	var out []*Request
	for _, req := range r.requests {
		if req.Status == StatusApproved && req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
			cp := *req
			out = append(out, &cp)
		}
	}
	return out, nil
}

// fakeCache records Invalidate calls.
type fakeCache struct {
	mu      sync.Mutex
	userIDs []int64
}

func (c *fakeCache) Invalidate(_ context.Context, _, userID int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userIDs = append(c.userIDs, userID)
	return nil
}

func (c *fakeCache) invalidatedFor(userID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range c.userIDs {
		if id == userID {
			return true
		}
	}
	return false
}

// fakePublisher records published event types; satisfies EventPublisher.
type fakePublisher struct {
	mu     sync.Mutex
	events []string
}

func (p *fakePublisher) Publish(_ context.Context, evt event.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, evt.Type)
}

func (p *fakePublisher) published(eventType string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.events {
		if e == eventType {
			return true
		}
	}
	return false
}

// fakeMatcher always returns true (any user is eligible for any subject type).
type fakeMatcher struct{}

func (fakeMatcher) UserInGroup(_ context.Context, _, _, _ int64) bool { return true }
func (fakeMatcher) UserInOrg(_ context.Context, _, _, _ int64) bool   { return true }
func (fakeMatcher) UserHasRole(_ context.Context, _, _, _ int64) bool { return true }

// fakeTerminator records TerminateAppSession calls.
type fakeTerminator struct {
	mu    sync.Mutex
	calls []terminateCall
}

type terminateCall struct {
	userID int64
	appID  int64
}

func (f *fakeTerminator) TerminateAppSession(_ context.Context, _, userID, appID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, terminateCall{userID: userID, appID: appID})
}

func (f *fakeTerminator) calledFor(userID, appID int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.userID == userID && c.appID == appID {
			return true
		}
	}
	return false
}

func (f *fakeTerminator) anyCalled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls) > 0
}

// testFakes bundles all fakes for assertion.
type testFakes struct {
	repo       *fakeRepo
	cache      *fakeCache
	bus        *fakePublisher
	matcher    SubjectMatcher
	terminator *fakeTerminator
	// stepUp is only populated by handler tests (newHandlerWithFakeSvc);
	// service-level tests don't go through the handler's step-up gate.
	stepUp *fakeStepUp
}

// ── setup helpers ──────────────────────────────────────────────────────────────

const (
	testTenant    = int64(1)
	testRequester = int64(5001)
	testApprover  = int64(9001)
)

var testCtx = context.Background()

// testEligID holds the ID of the pre-seeded eligibility.
var testEligID int64

// newServiceWithFakes creates a Service wired with in-memory fakes and seeds
// one active console eligibility that allows only [3600] seconds.
func newServiceWithFakes(t *testing.T) (*Service, *testFakes) {
	t.Helper()

	idGen, err := snowflake.New(1)
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

	// Seed one enabled eligibility.
	elig := &Eligibility{
		ID:                   idGen.Generate(),
		TenantID:             testTenant,
		TargetKind:           TargetConsole,
		RoleID:               42,
		RequesterSubjectType: "any",
		AllowedDurations:     IntSlice{3600},
		MaxDurationSeconds:   3600,
		ApproverSubjectType:  ApproverRole,
		ApproverSubjectID:    0,
		RequireJustification: false,
		Status:               1,
	}
	testEligID = elig.ID
	if err := fakes.repo.CreateEligibility(testCtx, elig); err != nil {
		t.Fatalf("seed eligibility: %v", err)
	}

	return svc, fakes
}

func mustCreateRequest(t *testing.T, s *Service, seconds int) *Request {
	t.Helper()
	req, err := s.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    testEligID,
		RequestedSeconds: seconds,
	})
	if err != nil {
		t.Fatalf("mustCreateRequest: %v", err)
	}
	return req
}

func mustApprovedRequest(t *testing.T, s *Service) *Request {
	t.Helper()
	req := mustCreateRequest(t, s, 3600)
	approved, err := s.Approve(testCtx, testTenant, req.ID, testApprover, "ok")
	if err != nil {
		t.Fatalf("mustApprovedRequest: %v", err)
	}
	return approved
}

// ── tests ──────────────────────────────────────────────────────────────────────

func TestCreateRequest_RejectsDurationNotAllowed(t *testing.T) {
	s, _ := newServiceWithFakes(t)
	// eligibility allows only 3600; 7200 is not in the allowed set
	_, err := s.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    testEligID,
		RequestedSeconds: 7200,
	})
	if err == nil {
		t.Fatal("expected error for disallowed duration, got nil")
	}
}

func TestApprove_InsertsGrantInvalidatesCacheAndAudits(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustCreateRequest(t, s, 3600)
	out, err := s.Approve(testCtx, testTenant, req.ID, testApprover, "ok")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != StatusApproved || out.ExpiresAt == nil {
		t.Fatalf("not approved: status=%s expiresAt=%v", out.Status, out.ExpiresAt)
	}
	if !fakes.cache.invalidatedFor(out.RequesterID) {
		t.Fatal("cache not invalidated for requester")
	}
	if !fakes.bus.published(EventRequestApproved) || !fakes.bus.published(EventGrantActivated) {
		t.Fatalf("approve/activate events not published; got=%v", fakes.bus.events)
	}
}

func TestRevoke_EndsGrantInvalidatesCacheAndAudits(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustApprovedRequest(t, s)
	if err := s.Revoke(testCtx, testTenant, req.ID, testApprover); err != nil {
		t.Fatal(err)
	}
	if !fakes.cache.invalidatedFor(req.RequesterID) {
		t.Fatal("cache not invalidated after revoke")
	}
	if !fakes.bus.published(EventGrantRevoked) {
		t.Fatalf("revoke event not published; got=%v", fakes.bus.events)
	}
}

func TestReject_TransitionsStatus(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustCreateRequest(t, s, 3600)
	if err := s.Reject(testCtx, testTenant, req.ID, testApprover, "denied"); err != nil {
		t.Fatal(err)
	}
	if !fakes.bus.published(EventRequestRejected) {
		t.Fatalf("rejected event not published; got=%v", fakes.bus.events)
	}
}

func TestCancel_ByRequester(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustCreateRequest(t, s, 3600)
	if err := s.Cancel(testCtx, testTenant, req.ID, testRequester); err != nil {
		t.Fatal(err)
	}
	if !fakes.bus.published(EventRequestCancelled) {
		t.Fatalf("cancelled event not published; got=%v", fakes.bus.events)
	}
}

func TestCancel_ByNonRequester_Fails(t *testing.T) {
	s, _ := newServiceWithFakes(t)
	req := mustCreateRequest(t, s, 3600)
	// Wrong requester ID
	if err := s.Cancel(testCtx, testTenant, req.ID, 9999); err == nil {
		t.Fatal("expected error when non-requester cancels, got nil")
	}
}

func TestExpire_EndsGrantAndInvalidatesCache(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustApprovedRequest(t, s)
	if err := s.Expire(testCtx, req); err != nil {
		t.Fatal(err)
	}
	if !fakes.cache.invalidatedFor(req.RequesterID) {
		t.Fatal("cache not invalidated after expire")
	}
	if !fakes.bus.published(EventGrantExpired) {
		t.Fatalf("expire event not published; got=%v", fakes.bus.events)
	}
}

// mustApprovedAppRequest seeds an app-target eligibility with the given appID,
// creates a request against it, and approves it. Uses a separate eligibility
// from testEligID (which is console-target).
func mustApprovedAppRequest(t *testing.T, s *Service, fakes *testFakes, appID int64) *Request {
	t.Helper()
	idGen, err := snowflake.New(2)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}
	elig := &Eligibility{
		ID:                   idGen.Generate(),
		TenantID:             testTenant,
		TargetKind:           TargetApp,
		AppID:                &appID,
		RoleID:               99,
		RequesterSubjectType: "any",
		AllowedDurations:     IntSlice{3600},
		MaxDurationSeconds:   3600,
		ApproverSubjectType:  ApproverRole,
		RequireJustification: false,
		Status:               1,
	}
	if err := fakes.repo.CreateEligibility(testCtx, elig); err != nil {
		t.Fatalf("mustApprovedAppRequest seed elig: %v", err)
	}
	req, err := s.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    elig.ID,
		RequestedSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("mustApprovedAppRequest CreateRequest: %v", err)
	}
	approved, err := s.Approve(testCtx, testTenant, req.ID, testApprover, "ok")
	if err != nil {
		t.Fatalf("mustApprovedAppRequest Approve: %v", err)
	}
	return approved
}

// mustApprovedConsoleRequest uses the pre-seeded console eligibility.
func mustApprovedConsoleRequest(t *testing.T, s *Service) *Request {
	t.Helper()
	return mustApprovedRequest(t, s)
}

func TestRevoke_AppGrant_TerminatesDownstream(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustApprovedAppRequest(t, s, fakes, 7777)
	if err := s.Revoke(testCtx, testTenant, req.ID, testApprover); err != nil {
		t.Fatal(err)
	}
	if !fakes.terminator.calledFor(req.RequesterID, 7777) {
		t.Fatal("expected downstream terminate for the app grant")
	}
}

func TestExpire_ConsoleGrant_DoesNotTerminate(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustApprovedConsoleRequest(t, s)
	if err := s.Expire(testCtx, req); err != nil {
		t.Fatal(err)
	}
	if fakes.terminator.anyCalled() {
		t.Fatal("console grant must not trigger downstream terminate")
	}
}
