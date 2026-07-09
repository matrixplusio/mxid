// Command gormtaglint fails the build when a GORM read scans into a struct
// whose exported fields lack an explicit `gorm:"column:..."` tag.
//
// WHY THIS EXISTS
//
// The EE distribution is built with `garble`, which renames Go struct FIELD
// names for anti-tamper. GORM maps a DB column to a struct field by:
//
//	(1) the explicit `gorm:"column:xxx"` tag, if present  — a string literal,
//	    which garble preserves → SAFE; or
//	(2) otherwise the field NAME lowered to snake_case      — which garble
//	    renames → the column no longer matches → the field is silently left
//	    at its zero value.
//
// So an untagged scan struct works in CE (`go build`) but returns EMPTY in EE
// (`garble build`). That shipped as the "access policy shows (未知)" prod bug.
// This linter makes that class of mistake fail locally, before an EE tag/push.
//
// It flags calls of the form  db.Scan(&x) / .Take / .First / .Find / .Last
// where the receiver is a *gorm.io/gorm.DB and x (a struct, or a slice/array
// of structs) has at least one EXPORTED field without a gorm column tag.
// Fields tagged `gorm:"-"` (ignored) or embedded models are treated as fine.
package main

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/analysis/singlechecker"
	"golang.org/x/tools/go/ast/inspector"
)

// scanMethods are the GORM finisher methods that materialise rows into the
// destination passed as their first argument.
var scanMethods = map[string]bool{
	"Scan": true, "Take": true, "First": true, "Find": true, "Last": true,
}

const gormDBType = "gorm.io/gorm.DB"

var analyzer = &analysis.Analyzer{
	Name:     "gormtaglint",
	Doc:      "flags GORM scans into structs with untagged exported fields (breaks under garble field-name obfuscation)",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func main() { singlechecker.Main(analyzer) }

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !scanMethods[sel.Sel.Name] || len(call.Args) == 0 {
			return
		}
		// Receiver must be a *gorm.DB so we only touch GORM chains.
		if !isGormDB(pass, sel.X) {
			return
		}
		st, tname := destStruct(pass, call.Args[0])
		if st == nil {
			return
		}
		if bad := untaggedExportedField(st); bad != "" {
			pass.Reportf(call.Args[0].Pos(),
				"gormtaglint: GORM %s scans into %s whose field %q has no `gorm:\"column:...\"` tag; "+
					"garble renames field names in EE builds → this column reads empty. "+
					"Add an explicit gorm column tag (or scan into a tagged model).",
				sel.Sel.Name, tname, bad)
		}
	})
	return nil, nil
}

// isGormDB reports whether expr has static type *gorm.DB or gorm.DB (the whole
// builder chain shares that type, so checking the immediate receiver suffices).
func isGormDB(pass *analysis.Pass, expr ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(expr)
	if t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path()+"."+obj.Name() == gormDBType
}

// destStruct unwraps the scan destination (a &x, where x is a struct or a
// slice/array/map/pointer chain bottoming out in a struct) and returns the
// underlying struct type plus a printable name. Non-struct destinations
// (primitives, maps of primitives) return nil.
func destStruct(pass *analysis.Pass, arg ast.Expr) (*types.Struct, string) {
	t := pass.TypesInfo.TypeOf(arg)
	if t == nil {
		return nil, ""
	}
	name := t.String()
	for i := 0; i < 8; i++ { // bounded unwrap: *[]*T etc.
		switch u := t.(type) {
		case *types.Pointer:
			t = u.Elem()
		case *types.Slice:
			t = u.Elem()
		case *types.Array:
			t = u.Elem()
		case *types.Named:
			// A named type that is itself a struct: only inspect it when it is
			// declared locally (models in domain/*/model.go are audited to carry
			// tags; re-flagging every use would be noise). We inspect the
			// underlying struct regardless — a named local scan struct without
			// tags is exactly the bug we want.
			if s, ok := u.Underlying().(*types.Struct); ok {
				return s, name
			}
			t = u.Underlying()
		case *types.Struct:
			return u, name
		default:
			return nil, ""
		}
	}
	return nil, ""
}

// untaggedExportedField returns the name of the first exported field that lacks
// a gorm column tag (and is not gorm:"-"), or "" if every exported field is
// safe. Embedded fields are skipped (GORM flattens them; their own fields get
// checked where declared).
func untaggedExportedField(st *types.Struct) string {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() || f.Embedded() {
			continue
		}
		tag := reflectTag(st.Tag(i), "gorm")
		if tag == "" {
			return f.Name()
		}
		if tag == "-" || strings.Contains(tag, "column:") {
			continue
		}
		// A gorm tag without a column: directive still relies on the field
		// name for the column → unsafe under garble.
		return f.Name()
	}
	return ""
}

// reflectTag extracts the value for key from a raw struct tag string, matching
// the semantics of reflect.StructTag.Get without importing reflect on a string
// we already hold.
func reflectTag(raw, key string) string {
	for raw != "" {
		i := 0
		for i < len(raw) && raw[i] == ' ' {
			i++
		}
		raw = raw[i:]
		if raw == "" {
			break
		}
		i = 0
		for i < len(raw) && raw[i] > ' ' && raw[i] != ':' && raw[i] != '"' {
			i++
		}
		if i == 0 || i+1 >= len(raw) || raw[i] != ':' || raw[i+1] != '"' {
			break
		}
		name := raw[:i]
		raw = raw[i+1:]
		i = 1
		for i < len(raw) && raw[i] != '"' {
			if raw[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(raw) {
			break
		}
		val := raw[1:i]
		raw = raw[i+1:]
		if name == key {
			return val
		}
	}
	return ""
}
