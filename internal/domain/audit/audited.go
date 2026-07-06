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
