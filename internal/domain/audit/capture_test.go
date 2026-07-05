package audit

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// testDBSeq gives every newTestDB call a distinct shared-cache database name
// so tests don't leak rows into each other (see DSN comment below).
var testDBSeq int64

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	// Plain ":memory:" gives each *connection* its own database. database/sql
	// discards a connection whose in-flight query context was cancelled and
	// opens a fresh one on next use — which, for a bare in-memory sqlite,
	// means a brand-new empty database (every subsequent query then fails
	// with "no such table"). Tests exercising Chainer.Run() cancel a ctx
	// while a query may be in flight, so use a shared-cache DSN: all
	// connections (including replacements) see the same in-memory database.
	// The cache is process-wide and keyed by name, so each test gets its own
	// unique name — otherwise every test in the package would share one
	// global database and see each other's rows.
	name := fmt.Sprintf("testdb%d", atomic.AddInt64(&testDBSeq, 1))
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", name)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&AuditPending{}, &AuditEntry{}, &ChainHead{}); err != nil {
		t.Fatal(err)
	}
	// A shared-cache in-memory sqlite database is destroyed the instant its
	// last open connection closes. database/sql discards a connection whose
	// in-flight query context was cancelled, so a lone connection (pool size
	// 1) can transiently hit zero open connections and silently reset the
	// database — exactly what happens when a test cancels ctx while
	// Chainer.Run has a query in flight. Pin a dedicated keepalive
	// connection open for the test's lifetime so the shared cache always
	// has at least one live holder.
	if sqlDB, err := db.DB(); err == nil {
		keepalive, kaErr := sqlDB.Conn(context.Background())
		if kaErr == nil {
			t.Cleanup(func() { _ = keepalive.Close() })
		}
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
