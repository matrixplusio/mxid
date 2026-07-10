package authz

import (
	"context"
	"errors"
	"testing"
)

type scriptedLoader struct {
	policies []RolePolicy
	supers   []int64
	err      error
}

func (s scriptedLoader) LoadPolicies(context.Context) ([]RolePolicy, []int64, error) {
	return s.policies, s.supers, s.err
}

// The periodic casbin reconcile (runCasbinReconcile) calls Sync on a ticker. If a
// tick hits a DB blip, Sync must NOT wipe the live policy — a stale-but-correct
// enforcer is far safer than one that suddenly denies every grant. This locks in
// that fail-safe: a failing loader returns an error and leaves the prior policy
// intact.
func TestSync_LoaderErrorKeepsExistingPolicy(t *testing.T) {
	engine, err := NewCasbinEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	ctx := context.Background()

	good := scriptedLoader{policies: []RolePolicy{{TenantID: 1, RoleID: roleUserManager, Permission: "user.read"}}}
	if err := engine.Sync(ctx, good); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if !engine.RoleHasPermission(1, roleSubject(roleUserManager), "user.read") {
		t.Fatal("policy not loaded after initial sync")
	}

	// A tick that fails to read the DB must error AND preserve the grant.
	if err := engine.Sync(ctx, scriptedLoader{err: errors.New("db down")}); err == nil {
		t.Fatal("Sync must surface the loader error")
	}
	if !engine.RoleHasPermission(1, roleSubject(roleUserManager), "user.read") {
		t.Fatal("existing policy was wiped on loader error — reconcile would flap access on a DB blip")
	}
}
