// internal/domain/audit/anchorer_run_test.go
package audit

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestAnchorer_RunAnchorsThenStops(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 2; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	an := NewAnchorer(db, testKey(t), NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { an.Run(ctx, 5*time.Millisecond); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
	var n int64
	db.Model(&AuditAnchor{}).Count(&n)
	if n < 1 {
		t.Fatalf("expected at least one anchor, got %d", n)
	}
}
