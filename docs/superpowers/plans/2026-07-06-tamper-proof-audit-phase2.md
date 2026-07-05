# Tamper-Proof Audit — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make audit capture unbypassable and the chained log physically append-only: a gorm plugin auto-captures before/after for every write to an audited-model whitelist (in the caller's transaction, aborting the write if capture fails), and a Postgres trigger rejects UPDATE/DELETE on `mxid_audit_entry` for all roles.

**Architecture:** A gorm plugin registers `Before` callbacks on Create/Update/Delete. For any model implementing the `audit.Audited` marker, the callback snapshots before-state (Model-based re-query with the statement's WHERE) and after-state (create → the Dest struct; update → the SET delta; delete → nil), redacts secrets, and writes an `AuditPending` row via a `NewDB` session on the SAME connection (same transaction, no recursion). Capturing in `Before` means a capture error aborts the mutation via `db.AddError`. A Postgres RULE/trigger on `mxid_audit_entry` blocks UPDATE/DELETE regardless of DB role — the append-only hard floor (defense beyond the app-role GRANT deferred to later ops hardening).

**Tech Stack:** Go 1.25, gorm (glebarez/sqlite for unit tests, Postgres in prod + one dev-pg integration test), reflect, `internal/domain/audit` (Phase 1 Capturer), `pkg/tenantscope` (sibling plugin pattern).

## Verified gorm mechanics (prototyped 2026-07-06 — these WORK, use them verbatim)

- **Before-callback abort:** `cb.AddError(err)` in a `Before("gorm:create|update|delete")` callback prevents the mutation (gorm skips the mutation processor). Confirmed: erroring before-create → row NOT inserted.
- **Same-tx nested write, no recursion:** write the pending row via `cb.Session(&gorm.Session{NewDB: true})`. NewDB gives a fresh statement (so it does not reuse/recurse the business statement); the ConnPool is unchanged, so it shares the caller's transaction. Confirmed: business rollback → pending row gone; commit → pending present.
- **before-snapshot (update & delete):** re-query on a NewDB session using the schema's model and the statement's WHERE *expression*:
  ```go
  sess := cb.Session(&gorm.Session{NewDB: true})
  mdl := reflect.New(cb.Statement.Schema.ModelType).Interface()
  q := sess.Model(mdl)
  if wh, ok := cb.Statement.Clauses["WHERE"]; ok {
      q = q.Clauses(wh.Expression) // the inner clause.Where, NOT the wrapping clause.Clause
  }
  var before []map[string]any
  err := q.Find(&before).Error
  ```
  Passing `wh.Expression` (not `wh`) is required — passing the whole `clause.Clause` produces a `near "WHERE": syntax error`. `Model(...)` (not `Table(...)`) is required for DELETE — `Table` yields `model value required`. Model-based also returns typed values (bool not 1).
- **after-state:** on create, `cb.Statement.Dest` is the full row (mxid assigns Snowflake IDs before insert, so the PK is present in `Before`). On update, `cb.Statement.Dest` holds only the SET fields (the delta). On delete, there is no after.

## Global Constraints

- Module `github.com/imkerbos/mxid`. Snowflake `int64` IDs.
- Capture happens in `Before` callbacks. A capture failure MUST `cb.AddError(...)` so the business write aborts — never let a write proceed unaudited.
- The pending write MUST use `cb.Session(&gorm.Session{NewDB: true})` (same tx, no recursion).
- Only models implementing `audit.Audited` are captured. `AuditPending`/`AuditEntry`/`ChainHead` do NOT implement it (no self-capture).
- before/after maps MUST be redacted through the existing `isSensitiveKey` (schema.go) — never store `password_hash`, `secret`, `token`, etc.
- chain_class for data mutations = `"data"`. event_type = `<resource>.created|updated|deleted`.
- The audited whitelist is the sensitive-model set; a coverage test asserts each is `Audited` so nobody silently drops one.
- New migration is `000050` (latest is `000049`).
- Actor attribution comes from `auditctx` on `cb.Statement.Context`; services already thread it via `db.WithContext(ctx)` (same dependency tenantscope relies on). A missing actor yields a system-attributed row (Phase 1 Capture behavior) — never a failed write.

## File Structure

- `internal/domain/audit/audited.go` — `Audited` marker interface + `auditedResourceOf(schema)` detector + `redactMap`. (create)
- `internal/domain/audit/plugin.go` — `CapturePlugin` (gorm.Plugin): Create/Update/Delete before-callbacks. (create)
- `internal/domain/audit/plugin_test.go` — plugin behavior (create/update/delete capture, abort-on-failure, redaction, non-audited skip). (create)
- `internal/domain/audit/audited_marker_test.go` — whitelist coverage test. (create)
- `internal/domain/<model>/*.go` — add `AuditResource()` to the sensitive models. (modify)
- `internal/bootstrap/database.go:50` — `db.Use(audit.NewCapturePlugin(capturer))` after tenantscope. (modify)
- `migrations/000050_audit_entry_append_only.up.sql` / `.down.sql` — trigger. (create)

---

### Task 1: `Audited` marker + resource detector + redaction

**Files:**
- Create: `internal/domain/audit/audited.go`
- Test: `internal/domain/audit/audited_test.go`

**Interfaces:**
- Produces:
  - `type Audited interface { AuditResource() string }`
  - `func auditedResourceOf(s *schema.Schema) (string, bool)` — reflects the schema's model type, returns its `AuditResource()` and true if it implements `Audited`.
  - `func redactMap(m map[string]any) map[string]any` — drops keys where `isSensitiveKey` is true (reuses schema.go).

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/audited_test.go
package audit

import (
	"testing"

	"gorm.io/gorm/schema"
	"sync"
)

type auditedThing struct {
	ID int64 `gorm:"column:id;primaryKey"`
}

func (auditedThing) AuditResource() string { return "thing" }

type plainThing struct {
	ID int64 `gorm:"column:id;primaryKey"`
}

func parseSchema(t *testing.T, model any) *schema.Schema {
	t.Helper()
	s, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuditedResourceOf(t *testing.T) {
	res, ok := auditedResourceOf(parseSchema(t, &auditedThing{}))
	if !ok || res != "thing" {
		t.Fatalf("audited model: got (%q,%v), want (thing,true)", res, ok)
	}
	_, ok = auditedResourceOf(parseSchema(t, &plainThing{}))
	if ok {
		t.Fatalf("plain model should not be audited")
	}
}

func TestRedactMap(t *testing.T) {
	in := map[string]any{"name": "a", "password_hash": "x", "secret": "y"}
	out := redactMap(in)
	if _, ok := out["password_hash"]; ok {
		t.Fatal("password_hash not redacted")
	}
	if _, ok := out["secret"]; ok {
		t.Fatal("secret not redacted")
	}
	if out["name"] != "a" {
		t.Fatal("non-sensitive dropped")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run 'TestAuditedResourceOf|TestRedactMap' -v`
Expected: FAIL — `undefined: auditedResourceOf` / `redactMap`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/audited.go
package audit

import (
	"reflect"

	"gorm.io/gorm/schema"
)

// Audited is the marker interface a model implements to opt INTO automatic
// before/after audit capture. AuditResource returns the resource_type label
// used in event_type (e.g. "user" -> "user.created"). Presence of the method
// is the opt-in; the returned string is the label.
type Audited interface {
	AuditResource() string
}

// auditedResourceOf reports whether the schema's model implements Audited and,
// if so, its resource label. A fresh zero value is built from the model type so
// slice/pointer destinations still resolve the marker.
func auditedResourceOf(s *schema.Schema) (string, bool) {
	if s == nil || s.ModelType == nil {
		return "", false
	}
	zv := reflect.New(s.ModelType).Interface()
	if a, ok := zv.(Audited); ok {
		return a.AuditResource(), true
	}
	return "", false
}

// redactMap returns a copy of m with sensitive keys (isSensitiveKey, schema.go)
// removed, so secrets never land in an audit before/after snapshot.
func redactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveKey(k) {
			continue
		}
		out[k] = v
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run 'TestAuditedResourceOf|TestRedactMap' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/audited.go internal/domain/audit/audited_test.go
git commit -m "feat(audit): Audited marker interface + resource detector + redaction"
```

---

### Task 2: Capture plugin — Create capture + abort-on-failure

**Files:**
- Create: `internal/domain/audit/plugin.go`
- Test: `internal/domain/audit/plugin_test.go`

**Interfaces:**
- Consumes: `Capturer` (Phase 1), `auditedResourceOf`, `redactMap`, `Event`.
- Produces:
  - `type CapturePlugin struct { ... }`
  - `func NewCapturePlugin(c *Capturer) *CapturePlugin`
  - `func (p *CapturePlugin) Name() string` → `"mxid:auditcapture"`
  - `func (p *CapturePlugin) Initialize(db *gorm.DB) error` (Task 2 registers only Create; Tasks 3-4 add Update/Delete)
  - internal: `func modelToMap(cb *gorm.DB) map[string]any`, `func primaryKeyOf(cb *gorm.DB) int64`

**Note:** The plugin writes the pending row by calling `p.capturer.Capture(ctx, nested, ev)` where `nested = cb.Session(&gorm.Session{NewDB: true})` and `ctx = cb.Statement.Context`. On error it calls `cb.AddError(err)`.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/plugin_test.go
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

func (widget) TableName() string      { return "widget" }
func (widget) AuditResource() string  { return "widget" }

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestPlugin -v`
Expected: FAIL — `undefined: NewCapturePlugin`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/plugin.go
package audit

import (
	"fmt"
	"reflect"

	"gorm.io/gorm"
)

// CapturePlugin is a gorm plugin that captures a tamper-evident audit event for
// every write to a model implementing Audited. It runs in Before callbacks so a
// capture failure aborts the business write (cb.AddError), and writes the
// pending row on the caller's transaction (a NewDB session over the same
// ConnPool) so capture is atomic with the state change.
type CapturePlugin struct {
	capturer *Capturer
}

func NewCapturePlugin(c *Capturer) *CapturePlugin { return &CapturePlugin{capturer: c} }

func (p *CapturePlugin) Name() string { return "mxid:auditcapture" }

func (p *CapturePlugin) Initialize(db *gorm.DB) error {
	return db.Callback().Create().Before("gorm:create").Register("mxid:audit:create", p.captureCreate)
}

// captureCreate records a <resource>.created event with the full new row as
// after-state. mxid assigns Snowflake IDs before insert, so Dest already holds
// the PK in the Before callback.
func (p *CapturePlugin) captureCreate(cb *gorm.DB) {
	if cb.Statement == nil || cb.Statement.Schema == nil {
		return
	}
	res, ok := auditedResourceOf(cb.Statement.Schema)
	if !ok {
		return
	}
	after := redactMap(modelToMap(cb))
	ev := Event{
		ChainClass:   "data",
		EventType:    res + ".created",
		ResourceType: res,
		ResourceID:   primaryKeyOf(cb),
		After:        after,
	}
	if err := p.emit(cb, ev); err != nil {
		cb.AddError(err)
	}
}

// emit writes the pending row on the caller's tx via a NewDB session (fresh
// statement -> no recursion; same ConnPool -> same transaction).
func (p *CapturePlugin) emit(cb *gorm.DB, ev Event) error {
	nested := cb.Session(&gorm.Session{NewDB: true})
	if err := p.capturer.Capture(cb.Statement.Context, nested, ev); err != nil {
		return fmt.Errorf("audit capture %s: %w", ev.EventType, err)
	}
	return nil
}

// modelToMap renders the statement's model as a COLUMN-keyed map by iterating the
// schema fields and reading each value by DBName. Column keys (snake_case) are
// what redactMap and the sensitiveKeys set expect — a JSON round-trip would key
// by Go field name and silently defeat redaction.
func modelToMap(cb *gorm.DB) map[string]any {
	s := cb.Statement.Schema
	if s == nil {
		return nil
	}
	rv := cb.Statement.ReflectValue
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		if rv.Len() == 0 {
			return nil
		}
		rv = rv.Index(0) // single-entity dominant; batch fan-out is a Phase 3 refinement
	}
	out := make(map[string]any, len(s.Fields))
	for _, f := range s.Fields {
		if f.DBName == "" {
			continue
		}
		v, _ := f.ValueOf(cb.Statement.Context, rv)
		out[f.DBName] = v
	}
	return out
}

// primaryKeyOf reads the schema's primary key value from the statement.
func primaryKeyOf(cb *gorm.DB) int64 {
	if cb.Statement.Schema == nil || cb.Statement.Schema.PrioritizedPrimaryField == nil {
		return 0
	}
	f := cb.Statement.Schema.PrioritizedPrimaryField
	v, zero := f.ValueOf(cb.Statement.Context, cb.Statement.ReflectValue)
	if zero {
		return 0
	}
	if id, ok := v.(int64); ok {
		return id
	}
	return 0
}
```

Note: `modelToMap` keys by `field.DBName` (column name), so redaction by `isSensitiveKey` (which uses snake_case column names like `password_hash`) is reliable. `field.ValueOf` returns the typed Go value; when serialized into `AuditPending.After`/`Before` jsonb it round-trips fine.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestPlugin -v`
Expected: PASS (create captured, non-audited skipped, capture-failure aborts)

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/plugin.go internal/domain/audit/plugin_test.go
git commit -m "feat(audit): gorm capture plugin for create, aborts write on capture failure"
```

---

### Task 3: Update capture (before-snapshot + SET delta)

**Files:**
- Modify: `internal/domain/audit/plugin.go`
- Test: `internal/domain/audit/plugin_test.go` (add `TestPlugin_CaptureUpdate`)

**Interfaces:**
- Consumes: Task 2. Produces: `beforeSnapshot(cb) ([]map[string]any, error)` + `p.captureUpdate`.

- [ ] **Step 1: Write the failing test**

```go
// add to plugin_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestPlugin_CaptureUpdate -v`
Expected: FAIL — no update event captured (only Create is registered)

- [ ] **Step 3: Write minimal implementation**

Add the Update registration in `Initialize` (append after the Create line, before the `return`):

```go
	if err := db.Callback().Create().Before("gorm:create").Register("mxid:audit:create", p.captureCreate); err != nil {
		return err
	}
	return db.Callback().Update().Before("gorm:update").Register("mxid:audit:update", p.captureUpdate)
```

(Replace the single-`return` Initialize from Task 2 with the two-statement form above.)

Add to `plugin.go` (`reflect` is already imported from Task 2):

```go
// beforeSnapshot re-queries the rows the current Update/Delete statement targets,
// BEFORE the mutation runs, using the statement's WHERE. Verified incantation:
// Model-based NewDB session + the WHERE clause's inner Expression.
func beforeSnapshot(cb *gorm.DB) ([]map[string]any, error) {
	if cb.Statement.Schema == nil || cb.Statement.Schema.ModelType == nil {
		return nil, nil
	}
	sess := cb.Session(&gorm.Session{NewDB: true})
	mdl := reflect.New(cb.Statement.Schema.ModelType).Interface()
	q := sess.Model(mdl)
	if wh, ok := cb.Statement.Clauses["WHERE"]; ok {
		q = q.Clauses(wh.Expression)
	}
	var before []map[string]any
	if err := q.Find(&before).Error; err != nil {
		return nil, err
	}
	return before, nil
}

// captureUpdate records a <resource>.updated event: before = the full prior row(s),
// after = the SET delta (Dest holds only the changed fields in an update).
func (p *CapturePlugin) captureUpdate(cb *gorm.DB) {
	if cb.Statement == nil || cb.Statement.Schema == nil {
		return
	}
	res, ok := auditedResourceOf(cb.Statement.Schema)
	if !ok {
		return
	}
	before, err := beforeSnapshot(cb)
	if err != nil {
		cb.AddError(fmt.Errorf("audit before-snapshot %s: %w", res, err))
		return
	}
	ev := Event{
		ChainClass:   "data",
		EventType:    res + ".updated",
		ResourceType: res,
		ResourceID:   primaryKeyOf(cb),
		Before:       redactMap(firstRow(before)),
		After:        redactMap(updateDelta(cb)),
	}
	if err := p.emit(cb, ev); err != nil {
		cb.AddError(err)
	}
}

// firstRow returns the first snapshot row (single-entity updates/deletes are the
// dominant case). Batch writes affecting many rows still record one event with
// the first row's before-state; see the plan's batch note.
func firstRow(rows []map[string]any) map[string]any {
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

// updateDelta renders the update's SET fields (Dest) as a column map. For a map
// update Dest is already the map; for a struct update it round-trips via JSON.
func updateDelta(cb *gorm.DB) map[string]any {
	if m, ok := cb.Statement.Dest.(map[string]any); ok {
		return m
	}
	return modelToMap(cb)
}
```

Note: `primaryKeyOf` may return 0 for a `Where("id = ?", 1)` update where the model struct has no ID set; that is acceptable for Phase 2 (the before-snapshot carries the real id). If a reviewer wants the id populated, read it from `firstRow(before)["id"]`. Keep simple unless flagged.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestPlugin -v`
Expected: PASS (create + update + prior tests)

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/plugin.go internal/domain/audit/plugin_test.go
git commit -m "feat(audit): capture updates with before-snapshot and SET delta"
```

---

### Task 4: Delete capture

**Files:**
- Modify: `internal/domain/audit/plugin.go`
- Test: `internal/domain/audit/plugin_test.go` (add `TestPlugin_CaptureDelete`)

**Interfaces:**
- Consumes: Task 3 (`beforeSnapshot`). Produces: `p.captureDelete`.

- [ ] **Step 1: Write the failing test**

```go
// add to plugin_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestPlugin_CaptureDelete -v`
Expected: FAIL — no delete event (Delete not registered)

- [ ] **Step 3: Write minimal implementation**

Extend `Initialize` to register Delete (make it the final `return`):

```go
	if err := db.Callback().Update().Before("gorm:update").Register("mxid:audit:update", p.captureUpdate); err != nil {
		return err
	}
	return db.Callback().Delete().Before("gorm:delete").Register("mxid:audit:delete", p.captureDelete)
```

Add:

```go
// captureDelete records a <resource>.deleted event: before = the full prior
// row(s), no after.
func (p *CapturePlugin) captureDelete(cb *gorm.DB) {
	if cb.Statement == nil || cb.Statement.Schema == nil {
		return
	}
	res, ok := auditedResourceOf(cb.Statement.Schema)
	if !ok {
		return
	}
	before, err := beforeSnapshot(cb)
	if err != nil {
		cb.AddError(fmt.Errorf("audit before-snapshot %s: %w", res, err))
		return
	}
	ev := Event{
		ChainClass:   "data",
		EventType:    res + ".deleted",
		ResourceType: res,
		ResourceID:   primaryKeyOf(cb),
		Before:       redactMap(firstRow(before)),
	}
	if err := p.emit(cb, ev); err != nil {
		cb.AddError(err)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestPlugin -v`
Expected: PASS (create + update + delete + abort + skip + redaction)

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/plugin.go internal/domain/audit/plugin_test.go
git commit -m "feat(audit): capture deletes with before-snapshot"
```

---

### Task 5: Mark sensitive models Audited + whitelist coverage test

**Files:**
- Modify: the sensitive-model files (add `func (M) AuditResource() string { return "<res>" }` next to each model's existing `TableName()`).
- Test: `internal/domain/audit/audited_marker_test.go`

**Whitelist (initial):** `user`→"user", `app`→"app", `approle`→"role", `permission`→"permission", `access`(grant)→"access_grant", `tenant`→"tenant", `oidckey`→"oidc_key", `apitoken`→"api_token", `setting`→"setting", `conditionalaccess`→"conditional_access".

**Interfaces:**
- Consumes: `Audited`. Produces: a test that fails if any listed model type stops implementing `Audited`.

- [ ] **Step 1: Write the failing test**

The coverage test imports the domain model packages and asserts each implements `Audited`. It fails NOW (models don't implement it yet), guarding against a future silent drop.

```go
// internal/domain/audit/audited_marker_test.go
package audit_test

import (
	"testing"

	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/apitoken"
	"github.com/imkerbos/mxid/internal/domain/approle"
	"github.com/imkerbos/mxid/internal/domain/conditionalaccess"
	"github.com/imkerbos/mxid/internal/domain/oidckey"
	"github.com/imkerbos/mxid/internal/domain/permission"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/domain/tenant"
	"github.com/imkerbos/mxid/internal/domain/user"
	// NOTE: import paths/type names below are placeholders to resolve during
	// implementation — Step 3 says how to find the exact gorm model type per pkg.
)

func TestSensitiveModelsAreAudited(t *testing.T) {
	models := []any{
		&user.User{},
		&app.App{},
		&approle.AppRole{},
		&permission.Permission{},
		&tenant.Tenant{},
		&oidckey.OIDCKey{},
		&apitoken.APIToken{},
		&setting.Setting{},
		&conditionalaccess.Policy{},
		// access grant model added once its type name is confirmed
	}
	for _, m := range models {
		if _, ok := m.(audit.Audited); !ok {
			t.Errorf("%T must implement audit.Audited (sensitive write table not audited)", m)
		}
	}
}
```

- [ ] **Step 2: Resolve the exact model types + run to confirm it fails**

The struct names above are best-guesses. For each package, find the gorm model (the struct with `TableName()` for the primary table):

Run: `grep -rl "func (.*) TableName() string" internal/domain/{user,app,approle,permission,tenant,oidckey,apitoken,setting,conditionalaccess,access}` then read each hit to get the exact exported type. Fix the test's type list to the real names.

Run: `go test ./internal/domain/audit/ -run TestSensitiveModelsAreAudited -v`
Expected: FAIL — each `%T must implement audit.Audited`

- [ ] **Step 3: Add `AuditResource()` to each model**

For each model file, next to its `TableName()`:

```go
func (User) AuditResource() string { return "user" }
```
(analogously: `app`→"app", `AppRole`→"role", `Permission`→"permission", grant→"access_grant", `Tenant`→"tenant", `OIDCKey`→"oidc_key", `APIToken`→"api_token", `Setting`→"setting", `Policy`→"conditional_access").

Import cycle check: the marker is a bare interface satisfied structurally — a model implements `AuditResource()` WITHOUT importing package `audit`. Do NOT add an `audit` import to the domain model files.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestSensitiveModelsAreAudited -v && go build ./...`
Expected: PASS + build clean

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/audited_marker_test.go internal/domain/
git commit -m "feat(audit): mark sensitive models Audited + coverage test"
```

---

### Task 6: Wire the plugin into the DB init

**Files:**
- Modify: `internal/bootstrap/database.go` (after the tenantscope `db.Use`)
- Modify: whatever builds the app DB so a `*audit.Capturer` is available (the Capturer needs the snowflake generator; `internal/bootstrap/app.go:103` already builds `idGen`).
- Test: `internal/bootstrap` integration — a focused test that a create through the app DB writes an audit_pending row (or, if bootstrap has no test DB harness, verify via the dev-container smoke in Step 4).

**Interfaces:**
- Consumes: `audit.NewCapturePlugin`, `audit.NewCapturer`.

- [ ] **Step 1: Add the plugin registration**

`InitDatabase` currently does `db.Use(tenantscope.NewPlugin())`. The audit plugin needs a `*audit.Capturer`, which needs the `*snowflake.Generator`. `InitDatabase(cfg, logger)` does not currently receive the idGen. Thread it in: change the signature to `InitDatabase(cfg *DatabaseConfig, idGen *snowflake.Generator, logger *zap.Logger)` and update the one caller (find it: `grep -rn "InitDatabase(" internal app cmd`). Then, right after the tenantscope block:

```go
	if err := db.Use(audit.NewCapturePlugin(audit.NewCapturer(idGen))); err != nil {
		return nil, fmt.Errorf("install audit capture plugin: %w", err)
	}
```

Add the imports `github.com/imkerbos/mxid/internal/domain/audit` and `github.com/imkerbos/mxid/pkg/snowflake`.

If the caller builds `idGen` AFTER the DB (check `app.go` ordering — idGen is at :103, DB likely before), reorder so `idGen` is constructed before `InitDatabase`. If that reordering is non-trivial, STOP and report BLOCKED with the ordering constraint.

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: clean (fix the caller's argument list).

- [ ] **Step 3: Unit-verify plugin order vs tenantscope**

Both plugins register Before callbacks. Confirm no conflict: tenantscope's Create callback stamps tenant_id; the audit capture reads Dest/PK. Add a focused test in `internal/domain/audit/plugin_test.go` that installs BOTH plugins on a sqlite DB with a tenant-scoped + audited model and asserts a create still produces exactly one audit_pending row with the tenant stamped. (If a tenant-scoped+audited test model is heavy, assert ordering by installing tenantscope then audit and creating the existing `widget` — widget is not Tenanted, so this at least proves coexistence doesn't error.)

Run: `go test ./internal/domain/audit/ -run TestPlugin -v`
Expected: PASS

- [ ] **Step 4: Dev-container smoke**

Run (inside the dev container, where the app DB is reachable):
`docker exec mxid-dev sh -c 'cd /app && go run ./cmd/server -config=configs verify-audit'`
Then exercise one real write via the app and re-run `verify-audit` — expect a `data` chain to appear and verify OK. (If wiring a full write is heavy, at minimum confirm the server boots with the plugin installed: it should log "database connected" and start without error.)

- [ ] **Step 5: Commit**

```bash
git add internal/bootstrap/database.go internal/bootstrap/app.go internal/domain/audit/plugin_test.go
git commit -m "feat(audit): install capture plugin in DB init"
```

---

### Task 7: Postgres append-only trigger on mxid_audit_entry

**Files:**
- Create: `migrations/000050_audit_entry_append_only.up.sql`
- Create: `migrations/000050_audit_entry_append_only.down.sql`

**Interfaces:**
- Produces: a trigger that raises on UPDATE or DELETE of `mxid_audit_entry`, for every role.

- [ ] **Step 1: Write the up migration**

```sql
-- migrations/000050_audit_entry_append_only.up.sql
-- Append-only hard floor for the chained audit log. A BEFORE UPDATE/DELETE
-- trigger raises unconditionally, so no code path (or DBA, short of dropping
-- the trigger) can rewrite or remove a chained entry. This is the DB-level
-- complement to the HMAC hash chain: the chain DETECTS tampering; this trigger
-- PREVENTS the mutation outright. Role-based GRANT hardening (a restricted app
-- role) is deferred to ops setup; this trigger binds regardless of role.

CREATE OR REPLACE FUNCTION mxid_audit_entry_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'mxid_audit_entry is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_entry_append_only ON mxid_audit_entry;
CREATE TRIGGER trg_audit_entry_append_only
    BEFORE UPDATE OR DELETE ON mxid_audit_entry
    FOR EACH ROW EXECUTE FUNCTION mxid_audit_entry_append_only();
```

- [ ] **Step 2: Write the down migration**

```sql
-- migrations/000050_audit_entry_append_only.down.sql
DROP TRIGGER IF EXISTS trg_audit_entry_append_only ON mxid_audit_entry;
DROP FUNCTION IF EXISTS mxid_audit_entry_append_only();
```

- [ ] **Step 3: Apply + verify against dev Postgres**

Run: `make migrate-up` (DSN from `.env`; do not print secrets).
Then verify the trigger blocks UPDATE and DELETE but allows INSERT. Using the dev DSN:
```sql
-- expect: INSERT ok
INSERT INTO mxid_audit_entry (tenant_id, chain_class, seq, prev_hash, entry_hash, key_id, payload, imported, created_at)
VALUES (0, 'test', 1, '\x00', '\x01', 'default', '{}', false, NOW());
-- expect: ERROR append-only
UPDATE mxid_audit_entry SET key_id = 'x' WHERE tenant_id = 0 AND chain_class = 'test';
-- expect: ERROR append-only
DELETE FROM mxid_audit_entry WHERE tenant_id = 0 AND chain_class = 'test';
```
Confirm the INSERT succeeded and both UPDATE and DELETE raised `append-only`. Then clean the probe row is IMPOSSIBLE by design (that's the point) — instead run `make migrate-down` on this migration to drop the trigger, delete the probe row, and `make migrate-up` again; OR leave the probe row (it is a `test` chain, harmless, and verify-audit only walks real chains). Document which you did in the report.

- [ ] **Step 4: Commit**

```bash
git add migrations/000050_audit_entry_append_only.up.sql migrations/000050_audit_entry_append_only.down.sql
git commit -m "feat(audit): append-only trigger on mxid_audit_entry"
```

---

## Self-Review

**Spec coverage (design §4 ORM enforcement + §5 append-only):**
- §4 "ORM 层强制,消灭绕过点" — capture in gorm Before callbacks over the Audited whitelist: Tasks 1-4, 6. No write to an audited model can skip capture (structural, at the ORM write primitive). ✅
- §4 "受审白名单,漏登记测试报警" — Task 5 coverage test. ✅
- §4 "同事务" — `emit` uses NewDB session over the same ConnPool; capture-failure aborts the write (Before + AddError). Tasks 2-4 tested. ✅
- §5 "append-only 落到 DB" — Task 7 trigger blocks UPDATE/DELETE for all roles. (Deviation from spec's role-GRANT approach: a trigger is strictly stronger — role-independent — and simpler; role GRANT hardening deferred to ops. Documented in Task 7.) ✅
- Secret redaction (§ general) — `redactMap` via existing `isSensitiveKey`: Tasks 1-4. ✅
- **Deferred to Phase 3+ (not this plan):** sensitive-read capture, app-event migration onto Capture, external Merkle anchoring, export, UI. Batch-update multi-row before-state records only the first row (noted in `firstRow`) — acceptable for the single-entity-dominant IAM write pattern; a multi-row event fan-out is a Phase 3 refinement.

**Placeholder scan:** Task 5's model type names are explicitly flagged as resolve-during-implementation with the exact grep to find them — not a silent placeholder. All code steps carry full code. No TBD/"handle errors".

**Type consistency:** `CapturePlugin`, `NewCapturePlugin`, `emit`, `beforeSnapshot`, `modelToMap`, `primaryKeyOf`, `firstRow`, `updateDelta`, `auditedResourceOf`, `redactMap`, `Audited.AuditResource()` are consistent across Tasks 1-6. `Event` fields (ChainClass/EventType/ResourceType/ResourceID/Before/After) match the Phase 1 `Event` struct.

## Risks / follow-ups

- **Actor attribution requires `db.WithContext(ctx)`**: services that write without threading the request context produce system-attributed rows. Not a failure, but Phase 3 should audit which write paths omit WithContext.
- **Plugin ↔ tenantscope callback order**: both register Before callbacks; Task 6 Step 3 verifies coexistence. If a real tenant-scoped+audited write misbehaves, register the audit callback explicitly After the tenantscope one.
