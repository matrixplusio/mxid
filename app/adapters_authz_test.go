package app

// DB-backed integration test for authzBindingProvider.EffectiveBindingsForUser.
//
// Requires a live PostgreSQL instance with the full migration set applied.
// Set TEST_DATABASE_URL to a connstring, e.g.:
//
//	host=localhost user=postgres password=12345 dbname=mxid sslmode=disable
//
// If the env var is absent the tests are skipped (local dev / CI must set it).
//
// Each test runs inside a transaction that is rolled back on completion, so no
// permanent state is left in the target DB.

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/group"
	"github.com/imkerbos/mxid/internal/domain/org"
	"github.com/imkerbos/mxid/internal/domain/permission"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openTestDB opens a postgres connection from TEST_DATABASE_URL or skips.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping Postgres-backed authz test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	return db
}

// idSeq generates unique int64 IDs without snowflake (avoids node-id setup).
var idSeq atomic.Int64

func nextID() int64 {
	// base on unix-micro so parallel test runs don't collide
	return time.Now().UnixMicro()*1000 + idSeq.Add(1)
}

// buildAuthzProvider constructs an authzBindingProvider backed by the given DB.
// The group/org repos are the real GORM-backed ones; since we seed no group or
// org memberships for the test user, their lookups will return empty slices.
func buildAuthzProvider(db *gorm.DB) *authzBindingProvider {
	a := &bootstrap.App{DB: db}
	grpMod := &group.Module{Repo: group.NewRepository(db)}
	orgMod := &org.Module{Service: org.NewService(org.NewRepository(db), nil, nil)}
	permMod := &permission.Module{}
	return newAuthzBindingProvider(a, permMod, grpMod, orgMod)
}

// seedTestRole inserts a minimal mxid_role row and returns its ID.
// The name/code are derived from the ID to avoid unique-constraint collisions
// when multiple roles are seeded in the same test.
func seedTestRole(t *testing.T, db *gorm.DB, tenantID int64) int64 {
	t.Helper()
	id := nextID()
	code := fmt.Sprintf("test-jit-role-%d", id)
	if err := db.Exec(`
		INSERT INTO mxid_role (id, tenant_id, name, code, type, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, NOW(), NOW())`,
		id, tenantID, code, code).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	return id
}

// seedTestUser inserts a minimal mxid_user row (non-super-admin).
func seedTestUser(t *testing.T, db *gorm.DB, tenantID, userID int64) {
	t.Helper()
	if err := db.Exec(`
		INSERT INTO mxid_user (id, tenant_id, username, password_hash, is_super_admin, status, created_at, updated_at)
		VALUES (?, ?, ?, '', FALSE, 1, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		userID, tenantID, fmt.Sprintf("user-%d", userID)).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// seedTestBinding inserts a mxid_role_binding row. expiresAt=nil means permanent.
// mxid_role_binding has no tenant_id column; tenancy is derived from the role.
func seedTestBinding(t *testing.T, db *gorm.DB, roleID, userID int64, expiresAt *time.Time) {
	t.Helper()
	id := nextID()
	if expiresAt == nil {
		if err := db.Exec(`
			INSERT INTO mxid_role_binding (id, role_id, subject_type, subject_id, status, created_at)
			VALUES (?, ?, 'user', ?, 1, NOW())`,
			id, roleID, userID).Error; err != nil {
			t.Fatalf("seed permanent binding: %v", err)
		}
	} else {
		if err := db.Exec(`
			INSERT INTO mxid_role_binding (id, role_id, subject_type, subject_id, expires_at, status, created_at)
			VALUES (?, ?, 'user', ?, ?, 1, NOW())`,
			id, roleID, userID, *expiresAt).Error; err != nil {
			t.Fatalf("seed timed binding: %v", err)
		}
	}
}

// TestEffectiveBindingsForUser_ExcludesExpiredGrant verifies that:
//   - A permanent binding (expires_at=NULL, status=1) is included.
//   - A future-expiring binding (expires_at > NOW(), status=1) is included.
//   - An already-expired binding (expires_at < NOW(), status=1) is excluded.
//
// Three distinct roles are used because the unique index on mxid_role_binding
// is (role_id, subject_type, subject_id, scope_type, scope_id) — the same
// (role, user) pair cannot appear twice in the table.
func TestEffectiveBindingsForUser_ExcludesExpiredGrant(t *testing.T) {
	db := openTestDB(t)

	// Wrap everything in a transaction; roll back at the end so the test DB
	// stays clean regardless of pass/fail.
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin tx: %v", tx.Error)
	}
	t.Cleanup(func() { _ = tx.Rollback() })

	const tenantID = int64(1) // default system tenant (always exists post-migration)
	userID := nextID()

	seedTestUser(t, tx, tenantID, userID)

	// Three roles — one per binding scenario — to satisfy the unique constraint
	// on (role_id, subject_type, subject_id).
	permanentRoleID := seedTestRole(t, tx, tenantID)
	futureRoleID := seedTestRole(t, tx, tenantID)
	expiredRoleID := seedTestRole(t, tx, tenantID)

	// Permanent binding (expires_at=NULL) — must be returned.
	seedTestBinding(t, tx, permanentRoleID, userID, nil)

	// Active future grant — must be returned.
	future := time.Now().Add(1 * time.Hour)
	seedTestBinding(t, tx, futureRoleID, userID, &future)

	// Expired grant — must NOT be returned.
	past := time.Now().Add(-1 * time.Minute)
	seedTestBinding(t, tx, expiredRoleID, userID, &past)

	p := buildAuthzProvider(tx)
	got, err := p.EffectiveBindingsForUser(context.Background(), tenantID, userID)
	if err != nil {
		t.Fatalf("EffectiveBindingsForUser: %v", err)
	}

	// permanentRoleID and futureRoleID bindings must be present.
	hasPermRole, hasFutureRole, hasExpiredRole := false, false, false
	for _, b := range got {
		switch b.RoleID {
		case permanentRoleID:
			hasPermRole = true
		case futureRoleID:
			hasFutureRole = true
		case expiredRoleID:
			hasExpiredRole = true
		}
	}
	if !hasPermRole {
		t.Fatalf("permanent binding (roleID=%d) was not returned", permanentRoleID)
	}
	if !hasFutureRole {
		t.Fatalf("future binding (roleID=%d) was not returned", futureRoleID)
	}
	if hasExpiredRole {
		t.Fatalf("expired binding (roleID=%d) leaked into results", expiredRoleID)
	}

	// Belt-and-suspenders: no returned binding should have an ExpiresAt in the past.
	for _, b := range got {
		if b.ExpiresAt != nil && b.ExpiresAt.Before(time.Now()) {
			t.Fatalf("expired binding leaked: roleID=%d expiresAt=%v", b.RoleID, *b.ExpiresAt)
		}
	}
}
