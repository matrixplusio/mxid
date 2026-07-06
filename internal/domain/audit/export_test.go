package audit

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestBuildAndWriteExport(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	an.AnchorChain(context.Background(), 7, "data")
	reg := NewKeyRegistry(priv.Public().(ed25519.PublicKey))

	b, err := BuildExport(context.Background(), db, reg, 7, "data", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Entries) != 3 || len(b.Anchors) != 1 || len(b.PubKeys) != 1 {
		t.Fatalf("bundle wrong: entries=%d anchors=%d keys=%d", len(b.Entries), len(b.Anchors), len(b.PubKeys))
	}
	dir := t.TempDir()
	if err := WriteExport(dir, b); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"entries.jsonl", "proof.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
}
