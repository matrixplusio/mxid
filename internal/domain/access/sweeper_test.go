package access

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
)

// TestSweepOnce_ExpiresDueGrants_InMemory tests the sweeper using in-memory fakes.
// This test is always runnable (no DB required).
func TestSweepOnce_ExpiresDueGrants_InMemory(t *testing.T) {
	svc, fakes := newServiceWithFakes(t)
	repo := fakes.repo

	// Seed a console-target approved request with expires_at already in the past.
	idGen, err := snowflake.New(3)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}

	past := time.Now().Add(-5 * time.Minute)
	reqID := idGen.Generate()
	bindingID := idGen.Generate()

	req := &Request{
		ID:               reqID,
		TenantID:         testTenant,
		RequesterID:      8001,
		EligibilityID:    testEligID,
		TargetKind:       TargetConsole,
		RoleID:           42,
		RequestedSeconds: 300,
		Status:           StatusApproved,
		ExpiresAt:        &past,
		BindingID:        &bindingID,
	}
	if err := repo.CreateRequest(testCtx, req); err != nil {
		t.Fatalf("seed approved+expired request: %v", err)
	}

	n := sweepOnce(context.Background(), svc, repo, zap.NewNop())
	if n != 1 {
		t.Fatalf("want 1 expired, got %d", n)
	}

	got, err := repo.GetRequest(context.Background(), req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest after sweep: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("want status=%s, got %s", StatusExpired, got.Status)
	}
}

// TestSweepOnce_SkipsNotDue verifies that a future-expiring grant is not expired.
func TestSweepOnce_SkipsNotDue(t *testing.T) {
	svc, fakes := newServiceWithFakes(t)
	repo := fakes.repo

	idGen, err := snowflake.New(4)
	if err != nil {
		t.Fatalf("snowflake.New: %v", err)
	}

	future := time.Now().Add(time.Hour)
	reqID := idGen.Generate()
	bindingID := idGen.Generate()

	req := &Request{
		ID:               reqID,
		TenantID:         testTenant,
		RequesterID:      8002,
		EligibilityID:    testEligID,
		TargetKind:       TargetConsole,
		RoleID:           42,
		RequestedSeconds: 3600,
		Status:           StatusApproved,
		ExpiresAt:        &future,
		BindingID:        &bindingID,
	}
	if err := repo.CreateRequest(testCtx, req); err != nil {
		t.Fatalf("seed not-due request: %v", err)
	}

	n := sweepOnce(context.Background(), svc, repo, zap.NewNop())
	if n != 0 {
		t.Fatalf("want 0 expired (grant not due), got %d", n)
	}

	got, err := repo.GetRequest(context.Background(), req.ID, testTenant)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.Status != StatusApproved {
		t.Fatalf("want status still=%s, got %s", StatusApproved, got.Status)
	}
}

// TestSweepOnce_ExpiresDueGrants is the DB-backed integration test.
// Requires TEST_DATABASE_URL; otherwise skipped.
func TestSweepOnce_ExpiresDueGrants(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	// Insert an approved request already past expiry with a live binding.
	reqID := idGen.Generate()
	bindID := idGen.Generate()
	past := time.Now().Add(-5 * time.Minute)

	if err := db.Exec(`
		INSERT INTO mxid_access_request
			(id, tenant_id, requester_id, eligibility_id, target_kind, role_id,
			 requested_seconds, status, binding_id, expires_at, created_at, updated_at)
		VALUES (?, ?, 5010, ?, 'console', ?, 3600, ?, ?, ?, NOW(), NOW())`,
		reqID, tenantID, eligID, roleID, StatusApproved, bindID, past).Error; err != nil {
		t.Fatalf("seed expired approved request: %v", err)
	}

	// Insert a console binding row so EndGrant can delete it. Note:
	// mxid_role_binding has NO tenant_id column — tenancy is derived via
	// role_id -> mxid_role.tenant_id.
	if err := db.Exec(`
		INSERT INTO mxid_role_binding
			(id, role_id, subject_type, subject_id, expires_at, status, created_at)
		VALUES (?, ?, 'user', 5010, ?, 1, NOW())`,
		bindID, roleID, past).Error; err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// Build a real service with a noop terminator and a no-op cache (console grant
	// needs no cache invalidation to pass the test, but CacheInvalidator is required).
	svcIdGen, err := snowflake.New(5)
	if err != nil {
		t.Fatalf("snowflake.New for svc: %v", err)
	}
	cache := &fakeCache{}
	bus := &fakePublisher{}
	svc := NewService(repo, svcIdGen, bus, cache, fakeMatcher{}, NoopTerminator())

	n := sweepOnce(context.Background(), svc, repo, zap.NewNop())
	if n != 1 {
		t.Fatalf("want 1 expired, got %d", n)
	}

	got, err := repo.GetRequest(context.Background(), reqID, tenantID)
	if err != nil {
		t.Fatalf("GetRequest after sweep: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("want status=%s, got %s", StatusExpired, got.Status)
	}
}

// signalingRepo wraps a Repository and rendezvous-blocks each ListDueGrants
// call on a channel pair: it reports the call arrived (called), then waits
// for the test to say "go" (release). This lets a test deterministically
// synchronize with the sweeper's background goroutine instead of guessing
// timing with time.Sleep.
type signalingRepo struct {
	Repository
	called  chan struct{}
	release chan struct{}
}

func (r *signalingRepo) ListDueGrants(ctx context.Context) ([]*Request, error) {
	r.called <- struct{}{}
	<-r.release
	return r.Repository.ListDueGrants(ctx)
}

// TestStartSweeper_StopsOnCtxCancel deterministically proves the sweeper
// goroutine both runs its loop body and actually exits after ctx is
// cancelled — not just "doesn't deadlock".
//
// Strategy: the ticker interval is set generously long (200ms) relative to
// the microseconds it takes the test to react to a signal, so once the test
// observes the first ListDueGrants call, cancels the context, and releases
// the call, the for-loop's next select is guaranteed to see ctx.Done()
// ready and t.C NOT yet ready (the next real tick is ~200ms away) — so it
// deterministically takes the return path. We then confirm the goroutine
// truly stopped by asserting no further ListDueGrants calls arrive even
// after waiting past where the next tick would have fired.
func TestStartSweeper_StopsOnCtxCancel(t *testing.T) {
	svc, fakes := newServiceWithFakes(t)

	repo := &signalingRepo{
		Repository: fakes.repo,
		called:     make(chan struct{}),
		release:    make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	StartSweeper(ctx, svc, repo, 200*time.Millisecond, zap.NewNop())

	// Wait for the sweeper's first tick to prove the loop actually ran.
	select {
	case <-repo.called:
	case <-time.After(5 * time.Second):
		t.Fatal("sweeper never called ListDueGrants; loop did not run")
	}

	// Cancel while the goroutine is parked inside ListDueGrants, then let it
	// proceed: sweepOnce will return promptly and the for-loop's next select
	// must observe ctx.Done() already closed.
	cancel()
	repo.release <- struct{}{}

	// Prove the goroutine actually exited (not just idle): if it were still
	// alive, the next tick (~200ms out) would drive another ListDueGrants
	// call, which would block trying to send on `called` since nothing
	// receives after this point except this failure path.
	select {
	case <-repo.called:
		t.Fatal("sweeper called ListDueGrants again after ctx cancellation; goroutine did not exit")
	case <-time.After(500 * time.Millisecond):
		// No further calls past two tick intervals — the goroutine returned.
	}
}
