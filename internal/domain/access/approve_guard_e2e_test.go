package access

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ApproveAndGrant must NOT commit the binding when the request is no longer
// pending (concurrent double-approve / double-submit): the guarded UPDATE
// (WHERE status='pending') matches zero rows, so it must return
// ErrRequestNotPending and roll the binding INSERT back — otherwise an orphan,
// never-expiring privileged binding is left behind. Set MXID_E2E_DSN to run.
func TestApproveAndGrant_RejectsNonPending_E2E(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("MXID_E2E_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	gen, _ := snowflake.New(11)
	repo := NewRepository(db, gen)

	const reqID = int64(9100000000000000501)
	const bindID = int64(9100000000000000502)
	clean := func() {
		db.Exec("DELETE FROM mxid_access_request WHERE id = ?", reqID)
		db.Exec("DELETE FROM mxid_role_binding WHERE id = ?", bindID)
	}
	clean()
	t.Cleanup(clean)

	// A request that is ALREADY approved. TargetKind=console maps role_id -> the
	// seeded role 1 and the binding -> mxid_role_binding (subject_id has no FK, so
	// the synthetic requester is fine); the FK is satisfiable so the INSERT would
	// succeed and only the pending-guard rolls it back.
	if err := db.Exec(
		"INSERT INTO mxid_access_request (id, tenant_id, requester_id, eligibility_id, target_kind, role_id, requested_seconds, status) VALUES (?, 1, ?, ?, 'console', 1, 3600, 'approved')",
		reqID, int64(111), int64(222),
	).Error; err != nil {
		t.Fatalf("seed request: %v", err)
	}

	req := &Request{ID: reqID, TenantID: 1, RequesterID: 111, EligibilityID: 222, TargetKind: TargetConsole, RoleID: 1, RequestedSeconds: 3600, Status: StatusPending}
	err = repo.ApproveAndGrant(context.Background(), req, 999, time.Now().Add(time.Hour), bindID)
	if !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("approving a non-pending request must return ErrRequestNotPending, got %v", err)
	}

	var n int64
	db.Raw("SELECT count(*) FROM mxid_role_binding WHERE id = ?", bindID).Scan(&n)
	if n != 0 {
		t.Fatal("binding was committed despite the request not being pending (orphan grant)")
	}
}
