package audit

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"gorm.io/gorm"
)

// widget is an audited test model living only in this test.
type widget struct {
	ID           int64  `gorm:"column:id;primaryKey"`
	Name         string `gorm:"column:name"`
	PasswordHash string `gorm:"column:password_hash"`
}

func (widget) TableName() string     { return "widget" }
func (widget) AuditResource() string { return "widget" }

// plainRow is NOT audited.
type plainRow struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Note string `gorm:"column:note"`
}

func (plainRow) TableName() string { return "plain_row" }

func newPluginDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&widget{}, &plainRow{}, &AuditPending{}, &AuditEntry{}, &ChainHead{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Use(NewCapturePlugin(NewCapturer(newTestIDGen(t)))); err != nil {
		t.Fatal(err)
	}
	return db
}

func actorCtx() context.Context {
	return auditctx.With(context.Background(), auditctx.Actor{TenantID: 7, ActorID: 42, ActorType: "admin"})
}

func TestPlugin_CaptureCreate(t *testing.T) {
	db := newPluginDB(t)
	if err := db.WithContext(actorCtx()).Create(&widget{ID: 1, Name: "w", PasswordHash: "SECRET"}).Error; err != nil {
		t.Fatal(err)
	}
	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("no pending row captured: %v", err)
	}
	if p.EventType != "widget.created" || p.ResourceType != "widget" || p.ResourceID != 1 {
		t.Fatalf("bad event: %+v", p)
	}
	if p.TenantID != 7 || p.ActorID != 42 {
		t.Fatalf("actor not attributed: %+v", p)
	}
	// redaction: password_hash must not appear in after
	if got := string(p.After); got == "" || containsStr(got, "SECRET") || containsStr(got, "password_hash") {
		t.Fatalf("secret leaked into after: %s", got)
	}
}

func TestPlugin_NonAuditedModelSkipped(t *testing.T) {
	db := newPluginDB(t)
	if err := db.WithContext(actorCtx()).Create(&plainRow{ID: 1, Note: "x"}).Error; err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 0 {
		t.Fatalf("non-audited model produced %d audit rows, want 0", n)
	}
}

func TestPlugin_CaptureFailureAbortsWrite(t *testing.T) {
	db := newPluginDB(t)
	// Drop the pending table so the capture INSERT fails -> the business
	// create must abort (no widget row).
	db.Migrator().DropTable(&AuditPending{})
	err := db.WithContext(actorCtx()).Create(&widget{ID: 2, Name: "w2"}).Error
	if err == nil {
		t.Fatal("expected create to fail when audit capture fails")
	}
	var w widget
	if db.First(&w, 2).Error == nil {
		t.Fatal("widget was inserted despite audit capture failure — abort broken")
	}
}

func TestPlugin_CaptureCreateWithOmitDoesNotLeak(t *testing.T) {
	db := newPluginDB(t)
	// Omit a column on the business write; the nested audit INSERT must NOT
	// inherit that Omit (it would drop a NOT-NULL audit column and fail).
	err := db.WithContext(actorCtx()).Omit("name").Create(&widget{ID: 5, PasswordHash: "x"}).Error
	if err != nil {
		t.Fatalf("audit capture leaked the business Omit onto the pending insert: %v", err)
	}
	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("no pending row: %v", err)
	}
	if p.EventType != "widget.created" {
		t.Fatalf("bad event: %+v", p)
	}
}

func containsStr(h, n string) bool {
	return len(n) > 0 && len(h) >= len(n) && (func() bool {
		for i := 0; i+len(n) <= len(h); i++ {
			if h[i:i+len(n)] == n {
				return true
			}
		}
		return false
	})()
}
