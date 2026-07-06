package audit

import (
	"fmt"
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	if err := db.Callback().Create().Before("gorm:create").Register("mxid:audit:create", p.captureCreate); err != nil {
		return err
	}
	if err := db.Callback().Update().Before("gorm:update").Register("mxid:audit:update", p.captureUpdate); err != nil {
		return err
	}
	return db.Callback().Delete().Before("gorm:delete").Register("mxid:audit:delete", p.captureDelete)
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

// captureUpdate records one <resource>.updated event PER row the statement's
// WHERE targets: before = that row's full prior state, after = the SET delta
// (Dest holds only the changed fields in an update, shared by every affected
// row in a batch). A batch UPDATE ... WHERE hitting N rows must produce N
// audit events, not one — otherwise N-1 mutations go unrecorded. If any emit
// fails, abort immediately (cb.AddError) rather than emit a partial set.
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
	after := redactMap(updateDelta(cb))
	for _, beforeRow := range before {
		ev := Event{
			ChainClass:   "data",
			EventType:    res + ".updated",
			ResourceType: res,
			ResourceID:   resourceIDOf(cb, beforeRow),
			Before:       redactMap(beforeRow),
			After:        after,
		}
		if err := p.emit(cb, ev); err != nil {
			cb.AddError(err)
			return
		}
	}
}

// captureDelete records one <resource>.deleted event PER row the statement's
// WHERE targets: before = that row's full prior state, no after. Same
// per-row rationale as captureUpdate — a batch DELETE must not collapse to a
// single event. If any emit fails, abort immediately.
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
	for _, beforeRow := range before {
		ev := Event{
			ChainClass:   "data",
			EventType:    res + ".deleted",
			ResourceType: res,
			ResourceID:   resourceIDOf(cb, beforeRow),
			Before:       redactMap(beforeRow),
		}
		if err := p.emit(cb, ev); err != nil {
			cb.AddError(err)
			return
		}
	}
}

// updateDelta renders the update's SET fields (Dest) as a column map. For a map
// update Dest is already the map; for a struct update it round-trips via JSON.
func updateDelta(cb *gorm.DB) map[string]any {
	if m, ok := cb.Statement.Dest.(map[string]any); ok {
		return m
	}
	return modelToMap(cb)
}

// emit writes the pending row on the caller's tx via a NewDB session (fresh
// statement -> no recursion; same ConnPool -> same transaction).
//
// gorm's Session only clones Statement when Context/PrepareStmt/SkipHooks is
// also set (NewDB alone leaves it aliased to cb.Statement, the in-flight
// parent statement). Passing Context here forces that clone into an
// independent Statement, and clearing Model/Dest on the clone is then safe
// (it does not touch the parent's Statement). Without this, Capturer.Capture's
// tx.WithContext(ctx).Create(row) would inherit the parent's leftover
// Model (e.g. *widget) — gorm.(*DB).Create only assigns Model from Dest when
// Model is nil — so the pending-row insert would re-resolve the OUTER
// model's schema, re-match Audited, and recurse into captureCreate forever.
//
// gorm's clone() also forwards Selects, Omits, and re-populates Clauses from
// the parent statement's clauses. Left uncleared, a business write done via
// .Select(...)/.Omit(...)/.Clauses(clause.OnConflict{...}) would leak those
// column restrictions onto the nested AuditPending INSERT — e.g. an Omit that
// drops a NOT-NULL audit column, breaking the insert. ConnPool is
// deliberately NOT cleared: it is the shared transaction that makes the
// business write and the audit capture atomic.
func (p *CapturePlugin) emit(cb *gorm.DB, ev Event) error {
	ctx := cb.Statement.Context
	nested := cb.Session(&gorm.Session{NewDB: true, Context: ctx})
	nested.Statement.Model = nil
	nested.Statement.Dest = nil
	nested.Statement.Schema = nil
	nested.Statement.Table = ""
	nested.Statement.TableExpr = nil
	nested.Statement.ReflectValue = reflect.Value{}
	nested.Statement.Selects = nil
	nested.Statement.Omits = nil
	nested.Statement.Clauses = map[string]clause.Clause{}
	if err := p.capturer.Capture(ctx, nested, ev); err != nil {
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

// resourceIDOf returns the statement's primary key, falling back to the id from
// the before-snapshot when the model struct carried no PK (the common
// Where("id = ?", id) update/delete idiom).
func resourceIDOf(cb *gorm.DB, before map[string]any) int64 {
	if id := primaryKeyOf(cb); id != 0 {
		return id
	}
	if before == nil {
		return 0
	}
	switch v := before["id"].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case int:
		return int64(v)
	}
	return 0
}
