package access

import (
	"context"
	"errors"
	"slices"
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
		// Mirror the real repo, which translates gorm's not-found to the domain
		// sentinel so handlers 404 cleanly instead of leaking the ORM's text.
		return nil, ErrEligibilityNotFound
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

func (r *fakeRepo) UpdateEligibility(_ context.Context, e *Eligibility) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.eligibilities[e.ID]
	if !ok || existing.TenantID != e.TenantID {
		return errors.New("eligibility not found")
	}
	cp := *e
	r.eligibilities[e.ID] = &cp
	return nil
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
		return nil, ErrRequestNotFound
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
	return slices.Contains(c.userIDs, userID)
}

// fakePublisher records published event types and payloads; satisfies EventPublisher.
type fakePublisher struct {
	mu       sync.Mutex
	events   []string
	payloads []map[string]any
}

func (p *fakePublisher) Publish(_ context.Context, evt event.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, evt.Type)
	if m, ok := evt.Payload.(map[string]any); ok {
		p.payloads = append(p.payloads, m)
	} else {
		p.payloads = append(p.payloads, nil)
	}
}

func (p *fakePublisher) published(eventType string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.events, eventType)
}

// payloadFor returns the payload of the last published event matching
// eventType, or nil if it was never published.
func (p *fakePublisher) payloadFor(eventType string) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.events) - 1; i >= 0; i-- {
		if p.events[i] == eventType {
			return p.payloads[i]
		}
	}
	return nil
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
	tenantID int64
	userID   int64
	appID    int64
}

func (f *fakeTerminator) TerminateAppSession(_ context.Context, tenantID, userID, appID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, terminateCall{tenantID: tenantID, userID: userID, appID: appID})
}

// calledFor reports whether TerminateAppSession was invoked with the exact
// (tenantID, userID, appID) triple.
func (f *fakeTerminator) calledFor(tenantID, userID, appID int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.tenantID == tenantID && c.userID == userID && c.appID == appID {
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

// TestApprove_RejectsSelfApproval locks the separation-of-duties guard: a
// requester approving their own request is refused with ErrSelfApproval and the
// request stays pending (no grant activated).
func TestApprove_RejectsSelfApproval(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustCreateRequest(t, s, 3600)

	_, err := s.Approve(testCtx, testTenant, req.ID, testRequester, "self")
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("want ErrSelfApproval, got %v", err)
	}

	got, err := fakes.repo.GetRequest(testCtx, req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.Status != StatusPending {
		t.Errorf("status = %s, want pending (self-approval must not grant)", got.Status)
	}
}

// TestApprove_AutoApprovalNotBlockedBySoD proves the SoD guard does not break
// explicit auto-approval: that path calls Approve with approverID=0 (system),
// which never equals the requester's id, so a self-service request against an
// auto-approve eligibility still activates.
func TestApprove_AutoApprovalNotBlockedBySoD(t *testing.T) {
	s, fakes := newServiceWithFakes(t)

	autoElig := &Eligibility{
		ID:                   999999,
		TenantID:             testTenant,
		TargetKind:           TargetConsole,
		RoleID:               7,
		RequesterSubjectType: "any",
		AllowedDurations:     IntSlice{3600},
		MaxDurationSeconds:   3600,
		ApproverSubjectType:  ApproverAuto,
		RequireJustification: false,
		Status:               1,
	}
	if err := fakes.repo.CreateEligibility(testCtx, autoElig); err != nil {
		t.Fatalf("seed auto eligibility: %v", err)
	}

	req, err := s.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    autoElig.ID,
		RequestedSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateRequest (auto): %v", err)
	}
	if req.Status != StatusApproved {
		t.Errorf("status = %s, want approved (auto-approval must not be blocked by SoD)", req.Status)
	}
}

// seedApproverUserElig seeds an eligibility whose approver_subject is a specific
// user id, so approver-scoping can be exercised without the always-true matcher.
func seedApproverUserElig(t *testing.T, s *Service, fakes *testFakes, approverUserID int64) *Eligibility {
	t.Helper()
	e := &Eligibility{
		ID:                   700000000000000001,
		TenantID:             testTenant,
		TargetKind:           TargetConsole,
		RoleID:               42,
		RequesterSubjectType: "any",
		AllowedDurations:     IntSlice{3600},
		MaxDurationSeconds:   3600,
		ApproverSubjectType:  ApproverUser,
		ApproverSubjectID:    approverUserID,
		RequireJustification: false,
		Status:               1,
	}
	if err := fakes.repo.CreateEligibility(testCtx, e); err != nil {
		t.Fatalf("seed approver-user eligibility: %v", err)
	}
	return e
}

// TestApprove_RejectsApproverNotInSubject locks per-eligibility approver
// scoping: an approver who is not the designated approver_subject (and not a
// super-admin) is refused, and the request stays pending.
func TestApprove_RejectsApproverNotInSubject(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	elig := seedApproverUserElig(t, s, fakes, 555) // only user 555 may approve
	req, err := s.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    elig.ID,
		RequestedSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	// testApprover (not 555, not super-admin) must be refused.
	_, err = s.Approve(testCtx, testTenant, req.ID, testApprover, "ok")
	if !errors.Is(err, ErrApproverNotEligible) {
		t.Fatalf("want ErrApproverNotEligible, got %v", err)
	}
	got, _ := fakes.repo.GetRequest(testCtx, req.ID, testTenant)
	if got.Status != StatusPending {
		t.Errorf("status = %s, want pending", got.Status)
	}
}

// TestApprove_SuperAdminBypassesApproverScoping proves the break-glass
// exemption: a super-admin approves even when not the designated approver.
func TestApprove_SuperAdminBypassesApproverScoping(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	s.SetSuperAdminChecker(func(_ context.Context, uid int64) bool { return uid == testApprover })
	elig := seedApproverUserElig(t, s, fakes, 555) // designated approver is 555
	req, err := s.CreateRequest(testCtx, testTenant, testRequester, CreateAccessRequest{
		EligibilityID:    elig.ID,
		RequestedSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	out, err := s.Approve(testCtx, testTenant, req.ID, testApprover, "break-glass")
	if err != nil {
		t.Fatalf("super-admin approve should succeed, got %v", err)
	}
	if out.Status != StatusApproved {
		t.Errorf("status = %s, want approved", out.Status)
	}
}

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

// TestPublish_PayloadHasNoAmbiguousActorID asserts the access event payloads
// never carry a misleading "actor_id" key. The audit row's actor COLUMN is
// owned exclusively by the audit subsystem's enrich() (the request-scoped
// caller: approver / admin / system) — a payload "actor_id" naming the
// requester instead would contradict that column. requester_id is the
// beneficiary; grant.activated additionally names the approver explicitly
// via approver_id, never via the ambiguous actor_id key.
func TestPublish_PayloadHasNoAmbiguousActorID(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustCreateRequest(t, s, 3600)
	out, err := s.Approve(testCtx, testTenant, req.ID, testApprover, "ok")
	if err != nil {
		t.Fatal(err)
	}

	for _, eventType := range []string{EventRequestCreated, EventRequestApproved, EventGrantActivated} {
		payload := fakes.bus.payloadFor(eventType)
		if payload == nil {
			t.Fatalf("no payload captured for %s", eventType)
		}
		if _, ok := payload["actor_id"]; ok {
			t.Errorf("%s payload must not contain ambiguous actor_id key: %v", eventType, payload)
		}
		if got, ok := payload["requester_id"]; !ok || got != out.RequesterID {
			t.Errorf("%s payload requester_id = %v, want %d", eventType, got, out.RequesterID)
		}
	}

	activated := fakes.bus.payloadFor(EventGrantActivated)
	if got, ok := activated["approver_id"]; !ok || got != testApprover {
		t.Errorf("grant.activated payload approver_id = %v, want %d", got, testApprover)
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
	if !fakes.terminator.calledFor(testTenant, req.RequesterID, 7777) {
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

// TestExpire_AppGrant_TerminatesDownstream is the positive counterpart to
// TestExpire_ConsoleGrant_DoesNotTerminate: an approved app-target grant
// expiring via the sweeper path must still fire the downstream terminator,
// with the correct tenantID (not just requester + app).
func TestExpire_AppGrant_TerminatesDownstream(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustApprovedAppRequest(t, s, fakes, 8888)
	if err := s.Expire(testCtx, req); err != nil {
		t.Fatal(err)
	}
	if !fakes.terminator.calledFor(testTenant, req.RequesterID, 8888) {
		t.Fatal("expected downstream terminate for the app grant on expire")
	}
}

// ── UpdateEligibility ──────────────────────────────────────────────────────────

// TestUpdateEligibility_ValidatesLikeCreate proves UpdateEligibility rejects
// the same invalid shapes CreateEligibility does: bad target_kind, missing
// app_id for an app target, empty allowed_durations, max_duration_seconds
// outside (0, 7d], and an allowed duration exceeding max_duration_seconds.
func TestUpdateEligibility_ValidatesLikeCreate(t *testing.T) {
	s, fakes := newServiceWithFakes(t)

	cases := map[string]CreateEligibilityRequest{
		"bad target_kind": {
			TargetKind: "bogus", RoleID: 1, RequesterSubjectType: "any",
			AllowedDurations: []int{3600}, MaxDurationSeconds: 3600,
		},
		"app target missing app_id": {
			TargetKind: TargetApp, RoleID: 1, RequesterSubjectType: "any",
			AllowedDurations: []int{3600}, MaxDurationSeconds: 3600,
		},
		"empty allowed_durations": {
			TargetKind: TargetConsole, RoleID: 1, RequesterSubjectType: "any",
			AllowedDurations: nil, MaxDurationSeconds: 3600,
		},
		"max_duration_seconds over 7d ceiling": {
			TargetKind: TargetConsole, RoleID: 1, RequesterSubjectType: "any",
			AllowedDurations: []int{3600}, MaxDurationSeconds: maxEligibilityTTL + 1,
		},
		"max_duration_seconds zero": {
			TargetKind: TargetConsole, RoleID: 1, RequesterSubjectType: "any",
			AllowedDurations: []int{3600}, MaxDurationSeconds: 0,
		},
		"allowed duration exceeds max": {
			TargetKind: TargetConsole, RoleID: 1, RequesterSubjectType: "any",
			AllowedDurations: []int{7200}, MaxDurationSeconds: 3600,
		},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.UpdateEligibility(testCtx, testTenant, testEligID, req); err == nil {
				t.Fatalf("%s: expected validation error, got nil", name)
			}
			// The seeded eligibility must be untouched by a rejected update.
			got, gerr := fakes.repo.GetEligibility(testCtx, testEligID, testTenant)
			if gerr != nil {
				t.Fatalf("GetEligibility: %v", gerr)
			}
			if got.RoleID != 42 || got.MaxDurationSeconds != 3600 {
				t.Fatalf("%s: rejected update must not mutate the stored row, got %+v", name, got)
			}
		})
	}
}

// TestUpdateEligibility_PersistsChangesAndPreservesStatus proves a valid
// update overwrites the editable fields while leaving TenantID, Status, and
// CreatedBy exactly as they were (edit changes shape, not lifecycle state or
// ownership).
func TestUpdateEligibility_PersistsChangesAndPreservesStatus(t *testing.T) {
	s, fakes := newServiceWithFakes(t)

	before, err := fakes.repo.GetEligibility(testCtx, testEligID, testTenant)
	if err != nil {
		t.Fatalf("GetEligibility (before): %v", err)
	}

	updated, err := s.UpdateEligibility(testCtx, testTenant, testEligID, CreateEligibilityRequest{
		TargetKind:           TargetConsole,
		RoleID:               99,
		RequesterSubjectType: "group",
		RequesterSubjectID:   555,
		AllowedDurations:     []int{1800, 3600},
		MaxDurationSeconds:   3600,
		ApproverSubjectType:  ApproverAuto,
	})
	if err != nil {
		t.Fatalf("UpdateEligibility: %v", err)
	}
	if updated.RoleID != 99 || updated.RequesterSubjectType != "group" || updated.RequesterSubjectID != 555 {
		t.Fatalf("update did not apply new fields: %+v", updated)
	}
	if updated.ApproverSubjectType != ApproverAuto {
		t.Fatalf("approver_subject_type not updated: %+v", updated)
	}
	if updated.TenantID != before.TenantID || updated.Status != before.Status {
		t.Fatalf("update must preserve tenant_id/status, got tenant_id=%d status=%d", updated.TenantID, updated.Status)
	}

	got, err := fakes.repo.GetEligibility(testCtx, testEligID, testTenant)
	if err != nil {
		t.Fatalf("GetEligibility (after): %v", err)
	}
	if got.RoleID != 99 {
		t.Fatalf("repo row not persisted: role_id=%d", got.RoleID)
	}
}

// TestUpdateEligibility_UnknownID_Fails proves an id/tenant mismatch (or a
// nonexistent id) surfaces as an error rather than silently no-op'ing.
func TestUpdateEligibility_UnknownID_Fails(t *testing.T) {
	s, _ := newServiceWithFakes(t)
	_, err := s.UpdateEligibility(testCtx, testTenant, 999999999, CreateEligibilityRequest{
		TargetKind:           TargetConsole,
		RoleID:               1,
		RequesterSubjectType: "any",
		AllowedDurations:     []int{3600},
		MaxDurationSeconds:   3600,
	})
	if err == nil {
		t.Fatal("expected error for unknown eligibility id, got nil")
	}
}

// TestReject_DoesNotInvalidateCache locks in that Reject never busts the
// authz cache: a pending request has no live binding yet, so there is
// nothing for the cache to evict. Only approve/revoke/expire touch it.
func TestReject_DoesNotInvalidateCache(t *testing.T) {
	s, fakes := newServiceWithFakes(t)
	req := mustCreateRequest(t, s, 3600)
	if err := s.Reject(testCtx, testTenant, req.ID, testApprover, "denied"); err != nil {
		t.Fatal(err)
	}
	if fakes.cache.invalidatedFor(req.RequesterID) {
		t.Fatal("reject must not invalidate the authz cache")
	}
}
