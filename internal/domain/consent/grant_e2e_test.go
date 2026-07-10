package consent

import (
	"context"
	"os"
	"testing"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Re-consenting after a revoke must NOT resurrect the previously-revoked scopes.
// Uses Postgres because scopes is a text[] array column SQLite can't model. Set
// MXID_E2E_DSN to run.
func TestGrant_RevokedScopesNotResurrected_E2E(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("MXID_E2E_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	gen, _ := snowflake.New(9)
	svc := NewService(db, gen)

	// user_id + app_id have FKs — reuse a real user + app from the dev DB.
	var uid, aid int64
	if err := db.Raw("SELECT id FROM mxid_user WHERE deleted_at IS NULL LIMIT 1").Scan(&uid).Error; err != nil || uid == 0 {
		t.Skipf("no seed user in dev db: %v", err)
	}
	if err := db.Raw("SELECT id FROM mxid_app WHERE deleted_at IS NULL LIMIT 1").Scan(&aid).Error; err != nil || aid == 0 {
		t.Skipf("no seed app in dev db: %v", err)
	}
	const tid = int64(1)
	clean := func() { db.Exec("DELETE FROM mxid_user_app_consent WHERE user_id = ? AND app_id = ?", uid, aid) }
	clean()
	t.Cleanup(clean)

	// Existing row is REVOKED and previously held {openid, profile, email}.
	db.Exec(
		"INSERT INTO mxid_user_app_consent (id, tenant_id, user_id, app_id, scopes, granted_at, revoked_at) VALUES (?,?,?,?,?, NOW(), NOW())",
		int64(9100000000000000403), tid, uid, aid, pq.Array([]string{"openid", "profile", "email"}),
	)

	ctx := tenantscope.WithTenant(context.Background(), tid)
	row, err := svc.Grant(ctx, tid, uid, aid, []string{"openid"})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}

	got := map[string]bool{}
	for _, s := range row.Scopes {
		got[s] = true
	}
	if !got["openid"] {
		t.Fatalf("re-consented scope openid missing: %v", row.Scopes)
	}
	if got["profile"] || got["email"] {
		t.Fatalf("REVOKED scopes resurrected on re-consent: %v", row.Scopes)
	}
	if row.RevokedAt != nil {
		t.Fatalf("re-consent must clear revoked_at, got %v", row.RevokedAt)
	}
}
