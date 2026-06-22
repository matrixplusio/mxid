package approle

// DB-backed integration test for ResolveCodesForUser — verifies that expired
// and revoked time-bound app-role bindings are excluded from SSO claim resolution.
//
// Requires a live PostgreSQL instance with the full migration set applied.
// Set TEST_DATABASE_URL to a connstring, e.g.:
//
//	host=localhost user=postgres password=12345 dbname=mxid sslmode=disable
//
// If the env var is absent the tests are skipped.
// Each test runs inside a transaction that is rolled back on completion.

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// resolveTestIDSeq generates unique IDs for this test file.
var resolveTestIDSeq atomic.Int64

func resolveNextID() int64 {
	return time.Now().UnixMicro()*1000 + resolveTestIDSeq.Add(1)
}

// openResolveTestDB opens a postgres connection from TEST_DATABASE_URL or skips.
func openResolveTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping Postgres-backed approle resolver test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	return db
}

// seedResolveApp inserts a minimal mxid_app row and returns its ID.
// Uses protocol='saml' to avoid the oidc client_type/client_secret check constraint.
func seedResolveApp(t *testing.T, db *gorm.DB, tenantID int64) int64 {
	t.Helper()
	id := resolveNextID()
	code := fmt.Sprintf("test-jit-app-%d", id)
	if err := db.Exec(`
		INSERT INTO mxid_app (id, tenant_id, name, code, protocol, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'saml', 1, NOW(), NOW())`,
		id, tenantID, code, code).Error; err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return id
}

// seedResolveAppRole inserts a mxid_app_role row and returns its ID.
func seedResolveAppRole(t *testing.T, db *gorm.DB, tenantID, appID int64, code string) int64 {
	t.Helper()
	id := resolveNextID()
	if err := db.Exec(`
		INSERT INTO mxid_app_role (id, app_id, tenant_id, code, name, is_default, sort_order, created_at)
		VALUES (?, ?, ?, ?, ?, FALSE, 0, NOW())`,
		id, appID, tenantID, code, code).Error; err != nil {
		t.Fatalf("seed app role %q: %v", code, err)
	}
	return id
}

// seedResolveBinding inserts a mxid_app_role_binding for a user subject.
// expiresAt=nil means permanent; status defaults to 1 (active).
func seedResolveBinding(t *testing.T, db *gorm.DB, tenantID, appID, appRoleID, userID int64, expiresAt *time.Time) int64 {
	t.Helper()
	id := resolveNextID()
	if expiresAt == nil {
		if err := db.Exec(`
			INSERT INTO mxid_app_role_binding
				(id, app_id, tenant_id, app_role_id, subject_type, subject_id, status, created_at)
			VALUES (?, ?, ?, ?, 'user', ?, 1, NOW())`,
			id, appID, tenantID, appRoleID, userID).Error; err != nil {
			t.Fatalf("seed permanent app-role binding: %v", err)
		}
	} else {
		if err := db.Exec(`
			INSERT INTO mxid_app_role_binding
				(id, app_id, tenant_id, app_role_id, subject_type, subject_id, expires_at, status, created_at)
			VALUES (?, ?, ?, ?, 'user', ?, ?, 1, NOW())`,
			id, appID, tenantID, appRoleID, userID, *expiresAt).Error; err != nil {
			t.Fatalf("seed timed app-role binding: %v", err)
		}
	}
	return id
}

// assertResolveContains fails if code is not in codes.
func assertResolveContains(t *testing.T, codes []string, code string) {
	t.Helper()
	for _, c := range codes {
		if c == code {
			return
		}
	}
	t.Errorf("expected code %q in resolved codes %v", code, codes)
}

// assertResolveNotContains fails if code IS in codes.
func assertResolveNotContains(t *testing.T, codes []string, code string) {
	t.Helper()
	for _, c := range codes {
		if c == code {
			t.Errorf("code %q should NOT be in resolved codes %v (expired/revoked binding)", code, codes)
			return
		}
	}
}

// TestResolveCodesForUser_ExcludesExpiredAppRoleGrant verifies that:
//   - A permanent binding (expires_at=NULL, status=1) resolves its code.
//   - A future-expiring binding (expires_at > NOW(), status=1) resolves its code.
//   - An already-expired binding (expires_at < NOW(), status=1) does NOT resolve.
//   - A revoked binding (status=3, expires_at=NULL) does NOT resolve.
func TestResolveCodesForUser_ExcludesExpiredAppRoleGrant(t *testing.T) {
	db := openResolveTestDB(t)

	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin tx: %v", tx.Error)
	}
	t.Cleanup(func() { _ = tx.Rollback() })

	const tenantID = int64(1) // default system tenant (always exists post-migration)
	userID := resolveNextID()

	// Seed a user row (mxid_user FK on app_id is not enforced here; we just need the app).
	if err := tx.Exec(`
		INSERT INTO mxid_user (id, tenant_id, username, password_hash, is_super_admin, status, created_at, updated_at)
		VALUES (?, ?, ?, '', FALSE, 1, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		userID, tenantID, fmt.Sprintf("jit-artest-%d", userID)).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	appID := seedResolveApp(t, tx, tenantID)

	// Four roles — one per scenario.
	permanentRoleID := seedResolveAppRole(t, tx, tenantID, appID, fmt.Sprintf("perm-%d", resolveNextID()))
	futureRoleID := seedResolveAppRole(t, tx, tenantID, appID, fmt.Sprintf("future-%d", resolveNextID()))
	expiredRoleID := seedResolveAppRole(t, tx, tenantID, appID, fmt.Sprintf("expired-%d", resolveNextID()))
	revokedRoleID := seedResolveAppRole(t, tx, tenantID, appID, fmt.Sprintf("revoked-%d", resolveNextID()))

	// Permanent binding (expires_at=NULL, status=1).
	seedResolveBinding(t, tx, tenantID, appID, permanentRoleID, userID, nil)

	// Active future grant (expires_at > NOW(), status=1).
	future := time.Now().Add(1 * time.Hour)
	seedResolveBinding(t, tx, tenantID, appID, futureRoleID, userID, &future)

	// Expired grant (expires_at < NOW(), status=1).
	past := time.Now().Add(-1 * time.Minute)
	seedResolveBinding(t, tx, tenantID, appID, expiredRoleID, userID, &past)

	// Revoked binding (expires_at=NULL, status=3).
	seedResolveBinding(t, tx, tenantID, appID, revokedRoleID, userID, nil)
	if err := tx.Exec(`UPDATE mxid_app_role_binding SET status = 3 WHERE app_role_id = ?`, revokedRoleID).Error; err != nil {
		t.Fatalf("revoke binding: %v", err)
	}

	repo := NewRepository(tx)

	// Fetch role codes for the user.
	// Use Exec to get code strings via role IDs for comparison.
	permanentCode := getRoleCode(t, tx, permanentRoleID)
	futureCode := getRoleCode(t, tx, futureRoleID)
	expiredCode := getRoleCode(t, tx, expiredRoleID)
	revokedCode := getRoleCode(t, tx, revokedRoleID)

	codes, err := repo.ResolveCodesForUser(context.Background(), userID, appID, tenantID)
	if err != nil {
		t.Fatalf("ResolveCodesForUser: %v", err)
	}

	assertResolveContains(t, codes, permanentCode)
	assertResolveContains(t, codes, futureCode)
	assertResolveNotContains(t, codes, expiredCode)
	assertResolveNotContains(t, codes, revokedCode)
}

func getRoleCode(t *testing.T, db *gorm.DB, roleID int64) string {
	t.Helper()
	var code string
	if err := db.Raw(`SELECT code FROM mxid_app_role WHERE id = ?`, roleID).Scan(&code).Error; err != nil {
		t.Fatalf("get role code for %d: %v", roleID, err)
	}
	return code
}
