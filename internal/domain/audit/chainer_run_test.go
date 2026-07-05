package audit

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestChainer_RunDrainsThenStops(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	seedPending(t, db, gen, 7, "data", "e1")

	c := NewChainer(db, []byte("key"), "default", zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, 5*time.Millisecond); close(done) }()

	// Give it a few ticks to drain.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop on cancel")
	}

	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 0 {
		t.Fatalf("Run left %d pending", n)
	}
}
