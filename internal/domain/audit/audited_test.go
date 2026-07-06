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
