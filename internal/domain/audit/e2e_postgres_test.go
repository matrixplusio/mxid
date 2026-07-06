package audit

// Postgres end-to-end integration test. Skipped unless MXID_E2E_DSN points at a
// THROWAWAY database (it writes to mxid_audit_entry, which the append-only
// trigger makes undeletable — never point it at a real DB). Proves the full
// stack on real Postgres: ORM capture -> pending -> chainer -> append-only entry
// -> verify, plus secret redaction and the append-only trigger. Guards the
// jsonb-vs-text payload regression that sqlite unit tests cannot catch (jsonb
// normalizes bytes on read-back and breaks VerifyChain; the column must be TEXT).

import (
	"context"
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type e2eWidget struct {
	ID           int64  `gorm:"column:id;primaryKey"`
	Name         string `gorm:"column:name"`
	PasswordHash string `gorm:"column:password_hash"`
}

func (e2eWidget) TableName() string     { return "e2e_widget" }
func (e2eWidget) AuditResource() string { return "e2e_widget" }

const e2eTrigger = `
CREATE OR REPLACE FUNCTION mxid_audit_entry_append_only() RETURNS TRIGGER AS $$
BEGIN RAISE EXCEPTION 'mxid_audit_entry is append-only: % is not permitted', TG_OP; END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_audit_entry_append_only ON mxid_audit_entry;
CREATE TRIGGER trg_audit_entry_append_only BEFORE UPDATE OR DELETE ON mxid_audit_entry
FOR EACH ROW EXECUTE FUNCTION mxid_audit_entry_append_only();`

func TestZZ_E2E_Postgres(t *testing.T) {
	dsn := os.Getenv("MXID_E2E_DSN")
	if dsn == "" {
		t.Skip("MXID_E2E_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&e2eWidget{}, &AuditPending{}, &AuditEntry{}, &ChainHead{}, &AuditAnchor{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(e2eTrigger).Error; err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	if err := db.Use(NewCapturePlugin(NewCapturer(newTestIDGen(t)))); err != nil {
		t.Fatal(err)
	}
	key := []byte("e2e-key")
	chainer := NewChainer(db, key, "default", zap.NewNop())
	ctx := auditctx.With(context.Background(), auditctx.Actor{TenantID: 7, ActorID: 42, ActorType: "admin"})

	// CREATE (with a secret field to prove redaction on the real driver)
	if err := db.WithContext(ctx).Create(&e2eWidget{ID: 1, Name: "alpha", PasswordHash: "SECRET"}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	// UPDATE
	if err := db.WithContext(ctx).Model(&e2eWidget{}).Where("id = ?", 1).Update("name", "beta").Error; err != nil {
		t.Fatalf("update: %v", err)
	}
	// DELETE
	if err := db.WithContext(ctx).Delete(&e2eWidget{}, 1).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}

	// pending should have 3 data events
	var nPend int64
	db.Model(&AuditPending{}).Where("chain_class = ?", "data").Count(&nPend)
	if nPend != 3 {
		t.Fatalf("want 3 pending data events (create/update/delete), got %d", nPend)
	}

	// chain them
	n, err := chainer.ProcessBatch(ctx, 100)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if n != 3 {
		t.Fatalf("chained %d, want 3", n)
	}

	// verify the data chain
	res, err := VerifyChain(ctx, db, key, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.VerifiedThrough != 3 {
		t.Fatalf("verify failed: %+v", res)
	}

	// redaction on real driver: no SECRET / password_hash in any entry payload
	var entries []AuditEntry
	db.Where("chain_class = ?", "data").Find(&entries)
	for _, e := range entries {
		p := string(e.Payload)
		if containsStrE2E(p, "SECRET") || containsStrE2E(p, "password_hash") {
			t.Fatalf("secret leaked into entry payload: %s", p)
		}
	}
	// event types present (payload is BYTEA -> decode to jsonb for the query)
	var evtypes []string
	db.Model(&AuditEntry{}).Where("chain_class = ?", "data").Order("seq").
		Pluck("convert_from(payload,'UTF8')::jsonb->>'event_type'", &evtypes)
	t.Logf("E2E chained event_types: %v", evtypes)
	if len(evtypes) != 3 {
		t.Fatalf("want 3 event types, got %v", evtypes)
	}

	// ---- Phase 3: external Merkle + Ed25519 anchoring on real Postgres ----
	anchorPriv := testKey(t)
	anchorPub := anchorPriv.Public().(ed25519.PublicKey)
	anchorer := NewAnchorer(db, anchorPriv, NewFileSink(t.TempDir()+"/anchors.log"), newTestIDGen(t), zap.NewNop())
	anch, err := anchorer.AnchorChain(ctx, 7, "data")
	if err != nil || anch == nil || anch.FromSeq != 1 || anch.ToSeq != 3 {
		t.Fatalf("anchor create failed: anch=%+v err=%v", anch, err)
	}
	ares, err := VerifyAnchors(ctx, db, anchorPub, 7, "data")
	if err != nil || !ares.OK || ares.AnchoredThrough != 3 {
		t.Fatalf("anchor verify failed: %+v err=%v", ares, err)
	}
	t.Logf("E2E anchor OK: verified through seq %d", ares.AnchoredThrough)
	// tamper the anchor's stored merkle_root (audit_anchor has no trigger) -> the
	// signature no longer matches the recomputed message -> caught.
	if err := db.Exec("UPDATE mxid_audit_anchor SET merkle_root = ? WHERE tenant_id = 7 AND chain_class = 'data'", []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")).Error; err != nil {
		t.Fatal(err)
	}
	bad, _ := VerifyAnchors(ctx, db, anchorPub, 7, "data")
	if bad.OK {
		t.Fatal("tampered anchor root not caught by VerifyAnchors")
	}
	t.Logf("E2E anchor tamper caught: reason=%q", bad.Reason)

	// ---- Phase 4: an auth event bridged into the chain, on real Postgres ----
	svc := NewService(&captureRepo{}, newTestIDGen(t), nil, zap.NewNop(), 0)
	// nil event bus is fine; we call bridgeToChain directly (SubscribeEvents not needed).
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))
	aid := int64(42)
	svc.bridgeToChain(ctx, &AuditLog{TenantID: 7, ActorID: &aid, ActorType: "user", EventType: "login.success"})
	// chain the auth pending row
	nAuth, err := chainer.ProcessBatch(ctx, 100)
	if err != nil || nAuth < 1 {
		t.Fatalf("auth chain: n=%d err=%v", nAuth, err)
	}
	authRes, err := VerifyChain(ctx, db, key, 7, "auth")
	if err != nil || !authRes.OK || authRes.VerifiedThrough < 1 {
		t.Fatalf("auth chain verify failed: %+v err=%v", authRes, err)
	}
	t.Logf("E2E auth event chained + verified: through seq %d", authRes.VerifiedThrough)

	// append-only trigger blocks UPDATE + DELETE on entry
	updErr := db.Exec("UPDATE mxid_audit_entry SET key_id = 'x' WHERE tenant_id = 7 AND chain_class = 'data'").Error
	if updErr == nil {
		t.Fatal("trigger did NOT block UPDATE on mxid_audit_entry")
	}
	t.Logf("E2E trigger blocked UPDATE as expected: %v", updErr)
	delErr := db.Exec("DELETE FROM mxid_audit_entry WHERE tenant_id = 7 AND chain_class = 'data'").Error
	if delErr == nil {
		t.Fatal("trigger did NOT block DELETE on mxid_audit_entry")
	}
	t.Logf("E2E trigger blocked DELETE as expected: %v", delErr)

	t.Logf("E2E PASS: real Postgres capture->chain->verify->trigger all confirmed (pending=%d chained=%d verifiedThrough=%d)", nPend, n, res.VerifiedThrough)
}

func containsStrE2E(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
