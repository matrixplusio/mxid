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
