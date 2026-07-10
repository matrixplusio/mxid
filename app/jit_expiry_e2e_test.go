package app

import (
	"context"
	"os"
	"testing"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Role-based app access must count ONLY active, unexpired bindings. An expired
// JIT elevation must not keep matching role-subject access policies. Runs
// against a real Postgres (schema already migrated) — the query uses NOW() so
// SQLite can't stand in. Set MXID_E2E_DSN to run.
func TestJIT_ExpiredBindingNotGranted_E2E(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("MXID_E2E_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// role_id has a FK to mxid_role — reuse the seeded role 1. subject_id is a
	// bare column (no FK), so synthetic subject ids are fine and let us clean up
	// without touching real bindings on the shared role.
	const (
		roleID    = int64(1)
		uActive   = int64(9100000000000000311)
		uExpired  = int64(9100000000000000312)
		uDisabled = int64(9100000000000000313)
	)
	clean := func() {
		db.Exec("DELETE FROM mxid_role_binding WHERE subject_id IN (?,?,?)", uActive, uExpired, uDisabled)
	}
	clean()
	t.Cleanup(clean)

	// active (no expiry), expired (past expires_at), disabled (status=2)
	db.Exec("INSERT INTO mxid_role_binding (id, role_id, subject_type, subject_id, status) VALUES (?,?, 'user', ?, 1)", int64(9100000000000000321), roleID, uActive)
	db.Exec("INSERT INTO mxid_role_binding (id, role_id, subject_type, subject_id, status, expires_at) VALUES (?,?, 'user', ?, 1, NOW() - INTERVAL '1 hour')", int64(9100000000000000322), roleID, uExpired)
	db.Exec("INSERT INTO mxid_role_binding (id, role_id, subject_type, subject_id, status) VALUES (?,?, 'user', ?, 2)", int64(9100000000000000323), roleID, uDisabled)

	m := newAccessMatcher(&bootstrap.App{DB: db})
	ctx := context.Background()

	if ok, err := m.UserHasRole(ctx, uActive, roleID); err != nil || !ok {
		t.Fatalf("active binding must grant: ok=%v err=%v", ok, err)
	}
	if ok, _ := m.UserHasRole(ctx, uExpired, roleID); ok {
		t.Fatal("EXPIRED binding must NOT grant role-based access")
	}
	if ok, _ := m.UserHasRole(ctx, uDisabled, roleID); ok {
		t.Fatal("DISABLED (status!=1) binding must NOT grant role-based access")
	}
}
