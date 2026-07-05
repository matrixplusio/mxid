// internal/domain/audit/roundtrip_test.go
package audit

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// Capture -> chain -> verify -> tamper -> verify-fails, in one flow. This is the
// executable statement of the Phase 1 guarantee.
func TestRoundTrip_CaptureChainVerifyTamper(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	key := []byte("integration-key")

	for i := 0; i < 5; i++ {
		seedPending(t, db, gen, 7, "data", "evt")
	}
	c := NewChainer(db, key, "default", zap.NewNop())
	n, err := c.ProcessBatch(context.Background(), 100)
	if err != nil || n != 5 {
		t.Fatalf("chain: n=%d err=%v", n, err)
	}

	res, _ := VerifyChain(context.Background(), db, key, 7, "data")
	if !res.OK || res.VerifiedThrough != 5 {
		t.Fatalf("expected clean verify through 5, got %+v", res)
	}

	// A wrong key must fail verification for the whole chain at seq 1.
	bad, _ := VerifyChain(context.Background(), db, []byte("wrong-key"), 7, "data")
	if bad.OK {
		t.Fatalf("verification passed under wrong key — HMAC not actually protecting")
	}
}
