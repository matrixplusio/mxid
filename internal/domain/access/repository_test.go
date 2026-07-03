package access

// DB-backed integration tests for the access Repository.
//
// Requires a live PostgreSQL instance with the full migration set applied.
// Set TEST_DATABASE_URL to a connstring, e.g.:
//
//	host=localhost user=postgres password=12345 dbname=mxid sslmode=disable
//
// If the env var is absent the tests are skipped.
// Each test runs inside a transaction rolled back on completion.

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// accessTestIDSeq generates unique monotonic IDs for seeding.
var accessTestIDSeq atomic.Int64

func accessNextID() int64 {
	return time.Now().UnixMicro()*1000 + accessTestIDSeq.Add(1)
}

// openAccessTestDB opens a postgres connection from TEST_DATABASE_URL or skips.
func openAccessTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping Postgres-backed access repository test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	return db
}

// setupAccessRepo opens DB, begins a rollback-on-cleanup transaction, and
// returns (repo, tx, idGen, tenantID).
func setupAccessRepo(t *testing.T) (Repository, *gorm.DB, *snowflake.Generator, int64) {
	t.Helper()
	db := openAccessTestDB(t)

	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin tx: %v", tx.Error)
	}
	t.Cleanup(func() { _ = tx.Rollback() })

	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}

	const tenantID = int64(1) // default system tenant
	return NewRepository(tx, idGen), tx, idGen, tenantID
}

// seedConsoleRole inserts a minimal mxid_role row for the test and returns its id.
func seedConsoleRole(t *testing.T, db *gorm.DB, tenantID int64) int64 {
	t.Helper()
	id := accessNextID()
	code := fmt.Sprintf("jit-test-role-%d", id)
	if err := db.Exec(`
		INSERT INTO mxid_role (id, tenant_id, name, code, type, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, NOW(), NOW())`,
		id, tenantID, code, code).Error; err != nil {
		t.Fatalf("seed console role: %v", err)
	}
	return id
}

// seedEligibility inserts a minimal mxid_access_eligibility row and returns its id.
func seedEligibility(t *testing.T, db *gorm.DB, tenantID, roleID int64) int64 {
	t.Helper()
	id := accessNextID()
	if err := db.Exec(`
		INSERT INTO mxid_access_eligibility
			(id, tenant_id, target_kind, role_id, requester_subject_type, requester_subject_id,
			 allowed_durations, max_duration_seconds, approver_subject_type, approver_subject_id,
			 require_justification, require_stepup, status, created_at, updated_at)
		VALUES (?, ?, 'console', ?, 'any', 0, '[3600]', 3600, 'auto', 0, FALSE, FALSE, 1, NOW(), NOW())`,
		id, tenantID, roleID).Error; err != nil {
		t.Fatalf("seed eligibility: %v", err)
	}
	return id
}

// TestApproveAndGrant_InsertsConsoleBinding verifies the happy path:
// ApproveAndGrant atomically marks the request approved and inserts a
// time-bound row in mxid_role_binding.
func TestApproveAndGrant_InsertsConsoleBinding(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	req := &Request{
		ID:               idGen.Generate(),
		TenantID:         tenantID,
		RequesterID:      5001,
		EligibilityID:    eligID,
		TargetKind:       TargetConsole,
		RoleID:           roleID,
		RequestedSeconds: 3600,
		Status:           StatusPending,
	}
	if err := repo.CreateRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	bindingID := idGen.Generate()
	exp := time.Now().Add(time.Hour)
	if err := repo.ApproveAndGrant(context.Background(), req, 9001, exp, bindingID); err != nil {
		t.Fatalf("ApproveAndGrant: %v", err)
	}

	// Request must be marked approved with binding_id set.
	got, err := repo.GetRequest(context.Background(), req.ID, tenantID)
	if err != nil {
		t.Fatalf("GetRequest after approve: %v", err)
	}
	if got.Status != StatusApproved {
		t.Fatalf("want status=%s, got %s", StatusApproved, got.Status)
	}
	if got.BindingID == nil || *got.BindingID != bindingID {
		t.Fatalf("request not linked to binding: binding_id=%v", got.BindingID)
	}

	// A time-bound row must exist in mxid_role_binding.
	var n int64
	db.Raw(`SELECT count(*) FROM mxid_role_binding
		WHERE id = ? AND subject_type = 'user' AND subject_id = ? AND role_id = ? AND status = 1 AND expires_at IS NOT NULL`,
		bindingID, req.RequesterID, roleID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 time-bound console binding, got %d", n)
	}
}

// TestEndGrant_RemovesBinding verifies that EndGrant hard-deletes the binding
// row and transitions the request to the given final status.
func TestEndGrant_RemovesBinding(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	req := &Request{
		ID:               idGen.Generate(),
		TenantID:         tenantID,
		RequesterID:      5002,
		EligibilityID:    eligID,
		TargetKind:       TargetConsole,
		RoleID:           roleID,
		RequestedSeconds: 3600,
		Status:           StatusPending,
	}
	if err := repo.CreateRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	bindingID := idGen.Generate()
	if err := repo.ApproveAndGrant(context.Background(), req, 9001, time.Now().Add(time.Hour), bindingID); err != nil {
		t.Fatalf("ApproveAndGrant: %v", err)
	}

	// Reload so req.BindingID is populated.
	approved, _ := repo.GetRequest(context.Background(), req.ID, tenantID)

	if err := repo.EndGrant(context.Background(), approved, StatusRevoked, BindingRevoked); err != nil {
		t.Fatalf("EndGrant: %v", err)
	}

	// Binding row must be gone.
	var n int64
	db.Raw(`SELECT count(*) FROM mxid_role_binding WHERE id = ?`, bindingID).Scan(&n)
	if n != 0 {
		t.Fatalf("binding should be deleted, found %d", n)
	}

	// Request status must be revoked.
	got, _ := repo.GetRequest(context.Background(), req.ID, tenantID)
	if got.Status != StatusRevoked {
		t.Fatalf("want status=%s, got %s", StatusRevoked, got.Status)
	}
}

// TestListDueGrants returns approved requests past their expires_at.
func TestListDueGrants_ReturnsExpiredApproved(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	// Insert a request already approved+expired directly via raw SQL.
	reqID := idGen.Generate()
	bindID := idGen.Generate()
	past := time.Now().Add(-5 * time.Minute)
	if err := db.Exec(`
		INSERT INTO mxid_access_request
			(id, tenant_id, requester_id, eligibility_id, target_kind, role_id,
			 requested_seconds, status, binding_id, expires_at, created_at, updated_at)
		VALUES (?, ?, 5003, ?, 'console', ?, 3600, ?, ?, ?, NOW(), NOW())`,
		reqID, tenantID, eligID, roleID, StatusApproved, bindID, past).Error; err != nil {
		t.Fatalf("seed expired request: %v", err)
	}

	// Also insert a pending one that should NOT appear.
	pendingID := idGen.Generate()
	if err := db.Exec(`
		INSERT INTO mxid_access_request
			(id, tenant_id, requester_id, eligibility_id, target_kind, role_id,
			 requested_seconds, status, created_at, updated_at)
		VALUES (?, ?, 5004, ?, 'console', ?, 3600, ?, NOW(), NOW())`,
		pendingID, tenantID, eligID, roleID, StatusPending).Error; err != nil {
		t.Fatalf("seed pending request: %v", err)
	}

	due, err := repo.ListDueGrants(context.Background())
	if err != nil {
		t.Fatalf("ListDueGrants: %v", err)
	}

	found := false
	for _, r := range due {
		if r.ID == reqID {
			found = true
		}
		if r.ID == pendingID {
			t.Fatalf("pending request should not appear in ListDueGrants")
		}
	}
	if !found {
		t.Fatalf("expired approved request %d not found in ListDueGrants", reqID)
	}
}

// TestCreateAndListEligibility exercises the basic CRUD path.
func TestCreateAndListEligibility(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)

	e := &Eligibility{
		ID:                   idGen.Generate(),
		TenantID:             tenantID,
		TargetKind:           TargetConsole,
		RoleID:               roleID,
		RequesterSubjectType: "any",
		RequesterSubjectID:   0,
		AllowedDurations:     IntSlice{3600},
		MaxDurationSeconds:   3600,
		ApproverSubjectType:  ApproverAuto,
		ApproverSubjectID:    0,
		RequireJustification: false,
		RequireStepUp:        false,
		Status:               1,
	}
	if err := repo.CreateEligibility(context.Background(), e); err != nil {
		t.Fatalf("CreateEligibility: %v", err)
	}

	got, err := repo.GetEligibility(context.Background(), e.ID, tenantID)
	if err != nil {
		t.Fatalf("GetEligibility: %v", err)
	}
	if got.RoleID != roleID {
		t.Fatalf("want role_id=%d, got %d", roleID, got.RoleID)
	}

	list, err := repo.ListEligibility(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListEligibility: %v", err)
	}
	found := false
	for _, row := range list {
		if row.ID == e.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("created eligibility not found in ListEligibility")
	}

	if err := repo.DeleteEligibility(context.Background(), e.ID, tenantID); err != nil {
		t.Fatalf("DeleteEligibility: %v", err)
	}
	// DB is rolled back by cleanup — soft-delete check skipped.
}

// TestListRequestsByStatus verifies the filter path.
func TestListRequestsByStatus(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	req := &Request{
		ID: idGen.Generate(), TenantID: tenantID, RequesterID: 6001,
		EligibilityID: eligID, TargetKind: TargetConsole, RoleID: roleID,
		RequestedSeconds: 3600, Status: StatusPending,
	}
	if err := repo.CreateRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	rows, err := repo.ListRequestsByStatus(context.Background(), tenantID, StatusPending)
	if err != nil {
		t.Fatalf("ListRequestsByStatus: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.ID == req.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("created pending request not found")
	}

	rows2, _ := repo.ListRequestsByRequester(context.Background(), 6001, tenantID)
	if len(rows2) == 0 {
		t.Fatal("ListRequestsByRequester returned empty")
	}
}

// seedUser inserts a minimal mxid_user row and returns its id.
func seedUser(t *testing.T, db *gorm.DB, tenantID int64, username string, displayName *string) int64 {
	t.Helper()
	id := accessNextID()
	if err := db.Exec(`
		INSERT INTO mxid_user (id, tenant_id, username, display_name, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, NOW(), NOW())`,
		id, tenantID, username, displayName).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// TestListRequestsByStatus_PopulatesRequesterName verifies the console
// approvals list resolves the requester's display_name (fixes the raw
// snowflake-id-only display).
func TestListRequestsByStatus_PopulatesRequesterName(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	displayName := "Alice Requester"
	userID := seedUser(t, db, tenantID, fmt.Sprintf("alice-%d", accessNextID()), &displayName)

	req := &Request{
		ID: idGen.Generate(), TenantID: tenantID, RequesterID: userID,
		EligibilityID: eligID, TargetKind: TargetConsole, RoleID: roleID,
		RequestedSeconds: 3600, Status: StatusPending,
	}
	if err := repo.CreateRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	rows, err := repo.ListRequestsByStatus(context.Background(), tenantID, StatusPending)
	if err != nil {
		t.Fatalf("ListRequestsByStatus: %v", err)
	}
	var found *Request
	for _, r := range rows {
		if r.ID == req.ID {
			found = r
		}
	}
	if found == nil {
		t.Fatal("created request not found in ListRequestsByStatus")
	}
	if found.RequesterName != displayName {
		t.Fatalf("want requester_name=%q, got %q", displayName, found.RequesterName)
	}
}

// TestListRequestsByStatus_RequesterNameFallsBackToUsername verifies the
// username fallback when the user has no display_name set.
func TestListRequestsByStatus_RequesterNameFallsBackToUsername(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	eligID := seedEligibility(t, db, tenantID, roleID)

	username := fmt.Sprintf("bob-%d", accessNextID())
	userID := seedUser(t, db, tenantID, username, nil)

	req := &Request{
		ID: idGen.Generate(), TenantID: tenantID, RequesterID: userID,
		EligibilityID: eligID, TargetKind: TargetConsole, RoleID: roleID,
		RequestedSeconds: 3600, Status: StatusPending,
	}
	if err := repo.CreateRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	rows, err := repo.ListRequestsByStatus(context.Background(), tenantID, StatusPending)
	if err != nil {
		t.Fatalf("ListRequestsByStatus: %v", err)
	}
	var found *Request
	for _, r := range rows {
		if r.ID == req.ID {
			found = r
		}
	}
	if found == nil {
		t.Fatal("created request not found in ListRequestsByStatus")
	}
	if found.RequesterName != username {
		t.Fatalf("want requester_name to fall back to username=%q, got %q", username, found.RequesterName)
	}
}

// TestCreateEligibility_RequireStepUpZeroValueHonored reproduces and proves
// fixed a GORM footgun: Create() treats a Go zero value (false) on a field
// carrying a gorm "default" tag as "not set" and lets the DB column default
// (TRUE) apply instead, silently turning an explicit require_stepup:false
// into true. Exercises the real Service (not the in-memory fakeRepo, which
// doesn't touch GORM and can't reproduce this) end-to-end: DTO -> the
// service's boolOrDefault -> repo.CreateEligibility (real GORM INSERT) -> a
// fresh SELECT via GetEligibility.
func TestCreateEligibility_RequireStepUpZeroValueHonored(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	roleID := seedConsoleRole(t, db, tenantID)
	svc := NewService(repo, idGen, nil, &fakeCache{}, fakeMatcher{}, nil)

	falseVal := false
	e, err := svc.CreateEligibility(context.Background(), tenantID, nil, CreateEligibilityRequest{
		TargetKind:           TargetConsole,
		RoleID:               roleID,
		RequesterSubjectType: "any",
		AllowedDurations:     []int{3600},
		MaxDurationSeconds:   3600,
		RequireStepUp:        &falseVal,
	})
	if err != nil {
		t.Fatalf("CreateEligibility (explicit false): %v", err)
	}
	got, err := repo.GetEligibility(context.Background(), e.ID, tenantID)
	if err != nil {
		t.Fatalf("GetEligibility: %v", err)
	}
	if got.RequireStepUp != false {
		t.Fatalf("explicit require_stepup:false must persist as false, got %v", got.RequireStepUp)
	}

	// Omitted (nil) must still default to true.
	e2, err := svc.CreateEligibility(context.Background(), tenantID, nil, CreateEligibilityRequest{
		TargetKind:           TargetConsole,
		RoleID:               roleID,
		RequesterSubjectType: "any",
		AllowedDurations:     []int{3600},
		MaxDurationSeconds:   3600,
		RequireStepUp:        nil,
	})
	if err != nil {
		t.Fatalf("CreateEligibility (omitted): %v", err)
	}
	got2, err := repo.GetEligibility(context.Background(), e2.ID, tenantID)
	if err != nil {
		t.Fatalf("GetEligibility (omitted): %v", err)
	}
	if got2.RequireStepUp != true {
		t.Fatalf("omitted require_stepup must default to true, got %v", got2.RequireStepUp)
	}
}

// ─── App-target helpers ───────────────────────────────────────────────────────

// seedApp inserts a minimal mxid_app row (protocol='saml' satisfies the
// chk_app_secret_presence CHECK constraint which only requires a secret for
// non-SAML protocols) and returns its id.
func seedApp(t *testing.T, db *gorm.DB, tenantID int64) int64 {
	t.Helper()
	id := accessNextID()
	code := fmt.Sprintf("jit-test-app-%d", id)
	if err := db.Exec(`
		INSERT INTO mxid_app (id, tenant_id, name, code, protocol, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'saml', 1, NOW(), NOW())`,
		id, tenantID, code, code).Error; err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return id
}

// seedAppRole inserts a minimal mxid_app_role row and returns its id.
func seedAppRole(t *testing.T, db *gorm.DB, tenantID, appID int64) int64 {
	t.Helper()
	id := accessNextID()
	code := fmt.Sprintf("jit-test-approle-%d", id)
	if err := db.Exec(`
		INSERT INTO mxid_app_role (id, app_id, tenant_id, code, name, is_default, sort_order, created_at)
		VALUES (?, ?, ?, ?, ?, FALSE, 0, NOW())`,
		id, appID, tenantID, code, code).Error; err != nil {
		t.Fatalf("seed app role: %v", err)
	}
	return id
}

// TestApproveAndGrant_InsertsAppBinding verifies that ApproveAndGrant atomically
// marks the request approved and inserts a time-bound row in mxid_app_role_binding
// when TargetKind == TargetApp — the primary SSO app-role elevation path.
func TestApproveAndGrant_InsertsAppBinding(t *testing.T) {
	repo, db, idGen, tenantID := setupAccessRepo(t)
	appID := seedApp(t, db, tenantID)
	appRoleID := seedAppRole(t, db, tenantID, appID)

	// Seed an eligibility row linked to the app role so the FK is satisfied.
	eligID := accessNextID()
	if err := db.Exec(`
		INSERT INTO mxid_access_eligibility
			(id, tenant_id, target_kind, role_id, requester_subject_type, requester_subject_id,
			 allowed_durations, max_duration_seconds, approver_subject_type, approver_subject_id,
			 require_justification, require_stepup, status, created_at, updated_at)
		VALUES (?, ?, 'app', ?, 'any', 0, '[3600]', 3600, 'auto', 0, FALSE, FALSE, 1, NOW(), NOW())`,
		eligID, tenantID, appRoleID).Error; err != nil {
		t.Fatalf("seed app eligibility: %v", err)
	}

	req := &Request{
		ID:               idGen.Generate(),
		TenantID:         tenantID,
		RequesterID:      7001,
		EligibilityID:    eligID,
		TargetKind:       TargetApp,
		RoleID:           appRoleID,
		AppID:            &appID,
		RequestedSeconds: 3600,
		Status:           StatusPending,
	}
	if err := repo.CreateRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	bindingID := idGen.Generate()
	exp := time.Now().Add(time.Hour)
	if err := repo.ApproveAndGrant(context.Background(), req, 9002, exp, bindingID); err != nil {
		t.Fatalf("ApproveAndGrant (app target): %v", err)
	}

	// Request must be marked approved with binding_id set.
	got, err := repo.GetRequest(context.Background(), req.ID, tenantID)
	if err != nil {
		t.Fatalf("GetRequest after approve: %v", err)
	}
	if got.Status != StatusApproved {
		t.Fatalf("want status=%s, got %s", StatusApproved, got.Status)
	}
	if got.BindingID == nil || *got.BindingID != bindingID {
		t.Fatalf("request not linked to binding: binding_id=%v", got.BindingID)
	}

	// A time-bound row must exist in mxid_app_role_binding with all expected columns.
	var n int64
	db.Raw(`
		SELECT count(*) FROM mxid_app_role_binding
		WHERE id = ?
		  AND subject_type = 'user'
		  AND subject_id = ?
		  AND app_role_id = ?
		  AND app_id = ?
		  AND status = 1
		  AND expires_at IS NOT NULL
		  AND grant_id = ?`,
		bindingID, req.RequesterID, appRoleID, appID, req.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 time-bound app-role binding, got %d", n)
	}
}
