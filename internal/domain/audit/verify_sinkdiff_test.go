package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func TestVerifyAnchorsWithSink_DeletedDBRowDetected(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	an := NewAnchorer(db, priv, sink, gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))

	// clean: sink and DB agree
	res, err := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if err != nil || !res.OK {
		t.Fatalf("clean sink-diff should pass: %+v err=%v", res, err)
	}
	// delete the DB anchor row (attacker with DB access) — sink copy survives
	db.Where("tenant_id = ? AND chain_class = ?", 7, "data").Delete(&AuditAnchor{})
	bad, _ := VerifyAnchorsWithSink(context.Background(), db, sink, reg, 7, "data")
	if bad.OK || bad.Reason != "sink mismatch" {
		t.Fatalf("deleted DB anchor row not detected via sink: %+v", bad)
	}
}
