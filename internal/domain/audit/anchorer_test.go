// internal/domain/audit/anchorer_test.go
package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func TestAnchorer_AnchorsAndIsIncremental(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	// chain 3 entries into (7,"data")
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)

	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	an := NewAnchorer(db, priv, sink, gen, zap.NewNop())

	got, err := an.AnchorChain(context.Background(), 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.FromSeq != 1 || got.ToSeq != 3 {
		t.Fatalf("anchor range wrong: %+v", got)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !VerifyAnchorSig(pub, got) {
		t.Fatal("anchor sig invalid")
	}
	// second call: nothing new
	again, err := an.AnchorChain(context.Background(), 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if again != nil {
		t.Fatalf("expected no new anchor, got %+v", again)
	}
	// add one more entry -> incremental anchor from seq 4
	seedPending(t, db, gen, 7, "data", "e")
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	inc, err := an.AnchorChain(context.Background(), 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if inc == nil || inc.FromSeq != 4 || inc.ToSeq != 4 {
		t.Fatalf("incremental anchor wrong: %+v", inc)
	}
}
