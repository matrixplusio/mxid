package audit

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&AuditPending{}, &AuditEntry{}, &ChainHead{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func newTestIDGen(t *testing.T) *snowflake.Generator {
	t.Helper()
	g, err := snowflake.New(1)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestCapture_WritesPendingWithActor(t *testing.T) {
	db := newTestDB(t)
	cap := NewCapturer(newTestIDGen(t))

	ctx := auditctx.With(context.Background(), auditctx.Actor{
		ActorID: 42, ActorType: "admin", TenantID: 7,
		SessionID: "sess-1", IP: "1.2.3.4", UserAgent: "curl",
	})

	err := cap.Capture(ctx, db, Event{
		ChainClass: "data", EventType: "app.deleted",
		ResourceType: "app", ResourceID: 99,
		Before: map[string]any{"name": "old"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var got AuditPending
	if err := db.First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.TenantID != 7 || got.ActorID != 42 || got.EventType != "app.deleted" {
		t.Fatalf("actor/event not stamped: %+v", got)
	}
	if got.IP != "1.2.3.4" || got.SessionID != "sess-1" {
		t.Fatalf("network context not stamped: %+v", got)
	}
	if len(got.Before) == 0 {
		t.Fatalf("before not persisted")
	}
}

func TestCapture_RollbackDropsPending(t *testing.T) {
	db := newTestDB(t)
	cap := NewCapturer(newTestIDGen(t))
	ctx := auditctx.With(context.Background(), auditctx.Actor{TenantID: 7})

	tx := db.Begin()
	if err := cap.Capture(ctx, tx, Event{ChainClass: "data", EventType: "x"}); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()

	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 0 {
		t.Fatalf("rollback left %d pending rows, want 0 (atomicity broken)", n)
	}
}
