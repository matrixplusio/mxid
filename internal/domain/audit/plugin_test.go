package audit

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/tenantscope"
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

func TestPlugin_CaptureUpdate(t *testing.T) {
	db := newPluginDB(t)
	ctx := actorCtx()
	if err := db.WithContext(ctx).Create(&widget{ID: 1, Name: "old"}).Error; err != nil {
		t.Fatal(err)
	}
	// clear the create event so we assert only the update
	db.Where("1=1").Delete(&AuditPending{})

	if err := db.WithContext(ctx).Model(&widget{}).Where("id = ?", 1).
		Update("name", "new").Error; err != nil {
		t.Fatal(err)
	}
	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("no update event: %v", err)
	}
	if p.EventType != "widget.updated" || p.ResourceType != "widget" {
		t.Fatalf("bad update event: %+v", p)
	}
	if len(p.Before) == 0 || !containsStr(string(p.Before), "old") {
		t.Fatalf("before-state not captured: %s", p.Before)
	}
	if len(p.After) == 0 || !containsStr(string(p.After), "new") {
		t.Fatalf("after delta not captured: %s", p.After)
	}
}

func TestPlugin_CaptureDelete(t *testing.T) {
	db := newPluginDB(t)
	ctx := actorCtx()
	if err := db.WithContext(ctx).Create(&widget{ID: 1, Name: "doomed"}).Error; err != nil {
		t.Fatal(err)
	}
	db.Where("1=1").Delete(&AuditPending{}) // clear create event

	if err := db.WithContext(ctx).Delete(&widget{}, 1).Error; err != nil {
		t.Fatal(err)
	}
	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("no delete event: %v", err)
	}
	if p.EventType != "widget.deleted" || p.ResourceType != "widget" {
		t.Fatalf("bad delete event: %+v", p)
	}
	if len(p.Before) == 0 || !containsStr(string(p.Before), "doomed") {
		t.Fatalf("before-state not captured on delete: %s", p.Before)
	}
	if len(p.After) != 0 {
		t.Fatalf("delete must have no after-state: %s", p.After)
	}
}

func TestPlugin_UpdateResourceIDFromWhere(t *testing.T) {
	db := newPluginDB(t)
	ctx := actorCtx()
	if err := db.WithContext(ctx).Create(&widget{ID: 1, Name: "old"}).Error; err != nil {
		t.Fatal(err)
	}
	// clear the create event so we assert only the update
	db.Where("1=1").Delete(&AuditPending{})

	if err := db.WithContext(ctx).Model(&widget{}).Where("id = ?", 1).
		Update("name", "new").Error; err != nil {
		t.Fatal(err)
	}
	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("no update event: %v", err)
	}
	if p.EventType != "widget.updated" {
		t.Fatalf("bad update event: %+v", p)
	}
	if p.ResourceID != 1 {
		t.Fatalf("resource_id not resolved from before-snapshot: got %d, want 1", p.ResourceID)
	}
}

func TestPlugin_DeleteResourceIDFromWhere(t *testing.T) {
	db := newPluginDB(t)
	ctx := actorCtx()
	if err := db.WithContext(ctx).Create(&widget{ID: 1, Name: "doomed"}).Error; err != nil {
		t.Fatal(err)
	}
	// clear the create event so we assert only the delete
	db.Where("1=1").Delete(&AuditPending{})

	if err := db.WithContext(ctx).Where("id = ?", 1).Delete(&widget{}).Error; err != nil {
		t.Fatal(err)
	}
	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("no delete event: %v", err)
	}
	if p.EventType != "widget.deleted" {
		t.Fatalf("bad delete event: %+v", p)
	}
	if p.ResourceID != 1 {
		t.Fatalf("resource_id not resolved from before-snapshot: got %d, want 1", p.ResourceID)
	}
}

// TestPlugin_CoexistsWithTenantscope verifies the audit capture plugin and
// the tenant-isolation plugin can both be registered on the same *gorm.DB
// without one clobbering the other's callbacks. widget does not implement
// tenantscope.Tenanted, so tenantscope is a no-op here; the point of this
// test is that db.Use() with both plugins installed doesn't error and the
// audit capture still fires normally.
func TestPlugin_CoexistsWithTenantscope(t *testing.T) {
	db := newPluginDB(t) // already has the audit capture plugin
	if err := db.Use(tenantscope.NewPlugin()); err != nil {
		t.Fatal(err)
	}
	if err := db.WithContext(actorCtx()).Create(&widget{ID: 77, Name: "w"}).Error; err != nil {
		t.Fatalf("coexistence create failed: %v", err)
	}
	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 1 {
		t.Fatalf("want 1 audit row with both plugins, got %d", n)
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
