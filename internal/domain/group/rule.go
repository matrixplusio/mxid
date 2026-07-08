package group

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Rule errors.
var (
	ErrRuleEmpty            = errors.New("rule must contain at least one condition")
	ErrRuleUnknownField     = errors.New("unknown rule field")
	ErrRuleUnknownCmp       = errors.New("unknown comparison operator")
	ErrRuleInvalidValue     = errors.New("invalid rule value for this field")
	ErrRuleNestedNotSupported = errors.New("nested (and/or) rules are not supported yet")
)

// RuleExpr is the on-the-wire JSON shape of a dynamic group rule.
//
// MVP grammar — a single flat list of conditions, all AND-ed together:
//
//	{
//	  "op": "and",
//	  "conditions": [
//	    {"field": "status",            "cmp": "eq",        "value": 1},
//	    {"field": "org_id",            "cmp": "in_subtree","value": "1"},
//	    {"field": "detail.department", "cmp": "eq",        "value": "engineering"},
//	    {"field": "email",             "cmp": "endswith",  "value": "@mxid.io"}
//	  ]
//	}
//
// Nested OR / NOT will fit later by promoting Conditions to a recursive []RuleExpr.
type RuleExpr struct {
	Op         string          `json:"op"` // currently always "and"
	Conditions []RuleCondition `json:"conditions"`
}

// RuleCondition is one field/op/value triple.
type RuleCondition struct {
	Field string `json:"field"`
	Cmp   string `json:"cmp"`
	Value any    `json:"value"`
}

// ruleField describes one allowed field: where to find it (SQL column /
// joined table) and what comparisons it supports. Keeping this in code
// rather than the DB lets the validator enforce a tight allow-list — the
// rule engine must never assemble arbitrary SQL from user input.
type ruleField struct {
	SQL          string   // SQL column path including any JOIN alias prefix
	AllowedCmps  []string // cmp operators valid for this field
	ValueKind    string   // "string", "int", "id"
	NeedsDetail  bool     // true if the column lives in mxid_user_detail
	NeedsOrgPath bool     // true if cmp uses ltree subtree matching
}

var ruleFields = map[string]ruleField{
	"username": {
		SQL:         "u.username",
		AllowedCmps: []string{"eq", "ne", "contains", "startswith", "endswith"},
		ValueKind:   "string",
	},
	"email": {
		SQL:         "u.email",
		AllowedCmps: []string{"eq", "ne", "contains", "startswith", "endswith"},
		ValueKind:   "string",
	},
	"display_name": {
		SQL:         "u.display_name",
		AllowedCmps: []string{"eq", "contains", "startswith", "endswith"},
		ValueKind:   "string",
	},
	"status": {
		SQL:         "u.status",
		AllowedCmps: []string{"eq", "ne", "in"},
		ValueKind:   "int",
	},
	"org_id": {
		SQL:          "uo.org_id",
		AllowedCmps:  []string{"eq", "in", "in_subtree"},
		ValueKind:    "id",
		NeedsOrgPath: false, // in_subtree handled specially via ltree join
	},
	"detail.department": {
		SQL:         "d.department",
		AllowedCmps: []string{"eq", "ne", "contains"},
		ValueKind:   "string",
		NeedsDetail: true,
	},
	"detail.job_title": {
		SQL:         "d.job_title",
		AllowedCmps: []string{"eq", "ne", "contains"},
		ValueKind:   "string",
		NeedsDetail: true,
	},
	"detail.employee_no": {
		SQL:         "d.employee_no",
		AllowedCmps: []string{"eq", "ne", "startswith"},
		ValueKind:   "string",
		NeedsDetail: true,
	},
}

// AllowedRuleFields returns the field allow-list. Used by the API for the
// UI's field dropdown — keep API and engine in lock-step.
func AllowedRuleFields() map[string][]string {
	out := make(map[string][]string, len(ruleFields))
	for f, def := range ruleFields {
		out[f] = append([]string(nil), def.AllowedCmps...)
	}
	return out
}

// ValidateRule parses + validates a serialised rule payload (the JSON column
// from the DB or a request body). Returns ErrRuleEmpty etc. on misuse so the
// API can map to 4xx.
func ValidateRule(raw []byte) (*RuleExpr, error) {
	if len(raw) == 0 {
		return nil, ErrRuleEmpty
	}
	var expr RuleExpr
	if err := json.Unmarshal(raw, &expr); err != nil {
		return nil, fmt.Errorf("decode rule: %w", err)
	}
	if expr.Op == "" {
		expr.Op = "and"
	}
	if expr.Op != "and" {
		return nil, ErrRuleNestedNotSupported
	}
	if len(expr.Conditions) == 0 {
		return nil, ErrRuleEmpty
	}
	for i, c := range expr.Conditions {
		def, ok := ruleFields[c.Field]
		if !ok {
			return nil, fmt.Errorf("%w: %s (condition %d)", ErrRuleUnknownField, c.Field, i)
		}
		if !sliceContains(def.AllowedCmps, c.Cmp) {
			return nil, fmt.Errorf("%w: %s on %s (condition %d)", ErrRuleUnknownCmp, c.Cmp, c.Field, i)
		}
		if err := validateValue(def, c.Cmp, c.Value); err != nil {
			return nil, fmt.Errorf("%w (condition %d): %v", ErrRuleInvalidValue, i, err)
		}
	}
	return &expr, nil
}

func validateValue(def ruleField, cmp string, v any) error {
	switch cmp {
	case "in":
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("value must be array for `in`")
		}
		for _, e := range arr {
			if err := validateScalar(def, e); err != nil {
				return err
			}
		}
		return nil
	default:
		return validateScalar(def, v)
	}
}

func validateScalar(def ruleField, v any) error {
	switch def.ValueKind {
	case "string":
		if _, ok := v.(string); !ok {
			return fmt.Errorf("expected string")
		}
	case "int":
		// JSON numbers decode as float64; accept anything numerically integral.
		switch x := v.(type) {
		case float64:
			if x != float64(int(x)) {
				return fmt.Errorf("expected integer")
			}
		case int, int64:
			// ok
		default:
			return fmt.Errorf("expected integer")
		}
	case "id":
		// IDs travel as strings (snowflake) but the engine also accepts numbers
		// for ergonomics.
		switch x := v.(type) {
		case string:
			if _, err := strconv.ParseInt(x, 10, 64); err != nil {
				return fmt.Errorf("invalid id string")
			}
		case float64:
			if x != float64(int64(x)) {
				return fmt.Errorf("expected integer id")
			}
		default:
			return fmt.Errorf("expected id (string or number)")
		}
	}
	return nil
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// CompiledRule is the SQL fragments the sync engine assembles into the full
// SELECT statement. Splitting joins from where lets us deduplicate JOIN
// clauses (the detail table is joined at most once per rule).
type CompiledRule struct {
	JoinDetail bool
	JoinOrgFor map[string]bool // org_id condition needs uo (user_org) and optional o (organization) for in_subtree
	WhereSQL   string
	Args       []any
}

// Compile turns a validated rule into a CompiledRule the sync engine can use
// to build a parameterised query against mxid_user.
func Compile(expr *RuleExpr) (*CompiledRule, error) {
	cr := &CompiledRule{
		JoinOrgFor: map[string]bool{},
	}
	parts := make([]string, 0, len(expr.Conditions))
	for _, c := range expr.Conditions {
		def := ruleFields[c.Field]
		if def.NeedsDetail {
			cr.JoinDetail = true
		}
		if c.Field == "org_id" {
			cr.JoinOrgFor[c.Cmp] = true
		}
		frag, args, err := compileCondition(def, c)
		if err != nil {
			return nil, err
		}
		parts = append(parts, frag)
		cr.Args = append(cr.Args, args...)
	}
	cr.WhereSQL = strings.Join(parts, " AND ")
	return cr, nil
}

func compileCondition(def ruleField, c RuleCondition) (string, []any, error) {
	switch c.Cmp {
	case "eq":
		return def.SQL + " = ?", []any{toScalar(c.Value, def)}, nil
	case "ne":
		return def.SQL + " <> ?", []any{toScalar(c.Value, def)}, nil
	case "in":
		arr := c.Value.([]any)
		vals := make([]any, len(arr))
		for i, v := range arr {
			vals[i] = toScalar(v, def)
		}
		return def.SQL + " IN ?", []any{vals}, nil
	case "contains":
		return def.SQL + " ILIKE ?", []any{"%" + toString(c.Value) + "%"}, nil
	case "startswith":
		return def.SQL + " ILIKE ?", []any{toString(c.Value) + "%"}, nil
	case "endswith":
		return def.SQL + " ILIKE ?", []any{"%" + toString(c.Value)}, nil
	case "in_subtree":
		// org_id ∈ subtree(rootOrgID). Uses ltree GIST: o.path <@ root.path.
		// Implemented by a sub-select to avoid yet another join.
		//
		// Both root and child are fenced to the querying tenant by correlating
		// to the outer mxid_user alias (u.tenant_id) — defence in depth so a
		// rule value naming another tenant's org id can never pull that tenant's
		// subtree into the match set.
		rootID := toInt64(c.Value)
		return "uo.org_id IN (SELECT child.id FROM mxid_organization child, mxid_organization root " +
				"WHERE root.id = ? AND child.path <@ root.path " +
				"AND child.deleted_at IS NULL AND root.deleted_at IS NULL " +
				"AND root.tenant_id = u.tenant_id AND child.tenant_id = u.tenant_id)",
			[]any{rootID}, nil
	}
	return "", nil, fmt.Errorf("compileCondition: unhandled cmp %q", c.Cmp)
}

func toScalar(v any, def ruleField) any {
	if def.ValueKind == "id" {
		return toInt64(v)
	}
	return v
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	}
	return 0
}
