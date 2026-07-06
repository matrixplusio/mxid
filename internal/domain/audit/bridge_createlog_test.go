package audit

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

// captureRepoBridge counts Create calls to verify the legacy repo receives all
// events (both auth and data), while the chain receives only allowlisted events.
type captureRepoBridge struct {
	n int
}

func (c *captureRepoBridge) Create(_ context.Context, log *AuditLog) error {
	c.n++
	return nil
}
func (c *captureRepoBridge) List(context.Context, ListParams) ([]*AuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureRepoBridge) GetStats(context.Context, int64, time.Time, time.Time) (*AuditStatsResponse, error) {
	return nil, nil
}
func (c *captureRepoBridge) PurgeOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}

// TestCreateLog_FansAuthToChainNotData verifies that createLog sends all events
// to the legacy repo (both auth and data) but only auth events to the chain.
func TestCreateLog_FansAuthToChainNotData(t *testing.T) {
	db := newTestDB(t)
	rec := &captureRepoBridge{}
	svc := NewService(rec, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))

	actorID := int64(9)
	svc.createLog(context.Background(), &AuditLog{ID: 1, TenantID: 7, ActorID: &actorID, ActorType: "user", EventType: "login.success"})
	svc.createLog(context.Background(), &AuditLog{ID: 2, TenantID: 7, ActorID: &actorID, ActorType: "admin", EventType: "user.created"})

	if rec.n != 2 {
		t.Fatalf("legacy repo should get BOTH events, got %d", rec.n)
	}
	var chained []AuditPending
	db.Find(&chained)
	if len(chained) != 1 || chained[0].EventType != "login.success" || chained[0].ChainClass != "auth" {
		t.Fatalf("chain should have ONLY the auth event: %+v", chained)
	}
}
