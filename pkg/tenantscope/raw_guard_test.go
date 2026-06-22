package tenantscope_test

// This test is a cross-tenant-leak regression guard for raw SQL.
//
// The gorm tenant-isolation plugin (pkg/tenantscope) only rewrites the
// STRUCTURED query builder (Model/Where/Find/...). Raw SQL submitted through
// db.Raw(...) / db.Exec(...) bypasses the plugin entirely, so a Raw/Exec
// against a tenant-scoped table that forgets an inline `tenant_id = ?`
// (or `tenant_id IN (...)`) predicate silently returns/mutates rows across
// tenant boundaries.
//
// The guard walks internal/domain + internal/repository and, for every
// `.Raw(` / `.Exec(` occurrence, inspects a window of source lines around the
// call. The window is wide enough to capture the SQL string literal — whether
// it is inlined at the call or assigned to a const/var just above it. If the
// window contains a tenant predicate token the call passes; otherwise the file
// + line MUST appear in allowedCalls WITH a justification (audited-safe paths
// that legitimately have no tenant column: junction tables, ltree path moves,
// etc.). Anything new that trips this without a predicate or an allow-list
// entry fails the test, forcing a human to prove the call is tenant-safe.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rawExecMarkers are the gorm entry points that bypass the tenantscope plugin.
var rawExecMarkers = []string{".Raw(", ".Exec("}

// tenantPredicateTokens — presence of any of these in the inspection window is
// accepted as evidence the raw statement is tenant-scoped. Kept broad on
// purpose: the goal is to flag the obvious "no tenant filter at all" mistake,
// not to parse SQL.
var tenantPredicateTokens = []string{
	"tenant_id =",
	"tenant_id=",
	"tenant_id IN",
	"tenant_id  IN",
	".tenant_id =", // aliased: b.tenant_id = ?
	".tenant_id IN",
}

// scannedDirs are the tenant-scoped source roots walked by the guard.
var scannedDirs = []string{
	"internal/domain",
	"internal/repository",
}

// allowedCalls lists call sites that legitimately issue Raw/Exec without an
// inline tenant predicate. Key is "<module-relative-path>:<line>", value is the
// justification. Each entry has been hand-audited as tenant-safe.
var allowedCalls = map[string]string{
	// Junction/relation table with no tenant_id column; the relation is
	// pre-scoped by the (app_id, group_id) pair whose parents are already
	// tenant-checked at the service layer before insert.
	"internal/domain/app/repository_impl.go:245": "mxid_app_group_rel junction has no tenant_id column; scoped by app_id+group_id",
	// ltree subtree path rewrite scoped by the path LIKE prefix + id; operates
	// within a single org subtree already resolved under the caller's tenant.
	"internal/domain/org/repository_impl.go:112": "ltree descendant path move scoped by path prefix + id, single resolved subtree",
	// mxid_role_binding console insert: table has no tenant_id column; tenant is
	// carried via the joined mxid_role; the parent access_request was already
	// loaded tenant-scoped before the grant.
	"internal/domain/access/repository.go:149": "mxid_role_binding has no tenant_id column; tenant carried via joined mxid_role; parent request loaded tenant-scoped before insert",
	// mxid_app_role_binding app insert: tenant_id is explicitly set as an INSERT
	// value (from the tenant-scoped request); it is a value not a WHERE predicate.
	"internal/domain/access/repository.go:167": "mxid_app_role_binding INSERT sets tenant_id explicitly from the tenant-scoped request; value not predicate",
}

// windowRadius is how many source lines on each side of a Raw/Exec marker the
// guard inspects for a tenant predicate or the backing SQL const. Wide enough
// to reach a const SQL string declared just above the call (the audited authz
// join queries in approle/appaccess sit ~24 lines from their Raw call).
const windowRadius = 30

func TestNoUnscopedRawSQL(t *testing.T) {
	root := moduleRootTS(t)

	for _, d := range scannedDirs {
		dir := filepath.Join(root, d)
		if _, err := os.Stat(dir); err != nil {
			continue // optional dir not present in this layout
		}
		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)

			lines, readErr := readLines(path)
			if readErr != nil {
				return readErr
			}

			for i, line := range lines {
				if !containsAny(line, rawExecMarkers) {
					continue
				}
				lineNo := i + 1
				key := rel + ":" + itoa(lineNo)
				if _, ok := allowedCalls[key]; ok {
					continue
				}
				if windowHasTenantPredicate(lines, i) {
					continue
				}
				t.Errorf("%s:%d issues a raw .Raw()/.Exec() with no inline tenant predicate "+
					"in the surrounding %d-line window. Raw SQL bypasses the tenantscope plugin — add a "+
					"`tenant_id = ?` (or `tenant_id IN (...)`) clause to the statement, or if the table has "+
					"no tenant column / is otherwise audited-safe add %q to allowedCalls in raw_guard_test.go "+
					"with a justification.", rel, lineNo, 2*windowRadius+1, key)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", dir, walkErr)
		}
	}
}

func windowHasTenantPredicate(lines []string, idx int) bool {
	start := idx - windowRadius
	if start < 0 {
		start = 0
	}
	end := idx + windowRadius
	if end >= len(lines) {
		end = len(lines) - 1
	}
	for j := start; j <= end; j++ {
		if containsAny(lines[j], tenantPredicateTokens) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// moduleRootTS ascends from the cwd to the dir holding go.mod (module root).
func moduleRootTS(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod from %s", dir)
		}
		dir = parent
	}
}
