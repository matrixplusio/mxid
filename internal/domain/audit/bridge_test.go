package audit

import (
	"context"
	"testing"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

func TestBridge_AuthEventChained(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(&captureRepo{}, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))

	actorID := int64(42)
	name := "alice"
	svc.bridgeToChain(context.Background(), &AuditLog{
		TenantID: 7, ActorID: &actorID, ActorName: &name, ActorType: "user",
		EventType: "login.success", EventStatus: EventStatusSuccess,
	})

	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("auth event not chained: %v", err)
	}
	if p.ChainClass != "auth" || p.EventType != "login.success" || p.TenantID != 7 || p.ActorID != 42 {
		t.Fatalf("bad chained event: %+v", p)
	}
}

func TestBridge_DataEventNotChained(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(&captureRepo{}, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))

	svc.bridgeToChain(context.Background(), &AuditLog{TenantID: 7, EventType: "user.created"})
	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 0 {
		t.Fatalf("data event was bridged (double-capture): %d rows", n)
	}
}

func TestBridge_NilWhenUnwired(t *testing.T) {
	svc := NewService(&captureRepo{}, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	// no SetChainBridge -> bridgeToChain must be a safe no-op (no panic)
	svc.bridgeToChain(context.Background(), &AuditLog{EventType: "login.success"})
}

func TestBridge_SurvivesCanceledContext(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(&captureRepo{}, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate the request ctx already canceled when the async handler runs
	actorID := int64(42)
	svc.bridgeToChain(ctx, &AuditLog{TenantID: 7, ActorID: &actorID, ActorType: "user", EventType: "login.success"})

	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("auth event not chained under a canceled ctx (WithoutCancel missing?): %v", err)
	}
	if p.ChainClass != "auth" || p.TenantID != 7 {
		t.Fatalf("bad chained event: %+v", p)
	}
}
