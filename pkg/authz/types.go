// Package authz is the runtime permission engine: it resolves a caller's
// effective bindings (across user / group / org membership and across the
// role's scope), checks whether a requested permission is allowed for a
// given resource target, and exposes a gin middleware so handlers can drop
// in `authz.Require(perm, scopeFn)` to enforce the result.
//
// The package is deliberately decoupled from the domain modules: it
// consumes the data it needs through narrow interfaces (BindingProvider /
// GroupLookup / OrgLookup) so the domain package wiring stays uni-directional.
package authz

import (
	"context"
	"time"
)

// ScopeKind enumerates the resource container kinds a binding can target.
// "" (empty) means a global binding — applies regardless of resource.
type ScopeKind string

const (
	ScopeGlobal ScopeKind = ""
	ScopeOrg    ScopeKind = "org"
	ScopeGroup  ScopeKind = "group"
)

// ScopeTarget is the resource the caller is acting on. Pass nil to Check
// when the operation has no inherent target (e.g. listing roles globally) —
// the check then degrades to "any non-empty permission match wins".
//
// Kind decides which scope dimension the check folds in:
//   - ScopeOrg:   covered by any binding whose scope is global, or whose
//                 scope_type=org and ID is an ancestor of (or equal to) the
//                 target in the ltree.
//   - ScopeGroup: covered by global or scope_type=group with equal ID.
type ScopeTarget struct {
	Kind ScopeKind
	ID   int64
}

// Org/Group helpers to build target objects without sprinkling literals.
func TargetOrg(id int64) *ScopeTarget   { return &ScopeTarget{Kind: ScopeOrg, ID: id} }
func TargetGroup(id int64) *ScopeTarget { return &ScopeTarget{Kind: ScopeGroup, ID: id} }

// EffectiveBinding is the resolved view of one role assignment that pertains
// to a specific user. The same role can appear multiple times (direct +
// group-inherited + org-inherited) with different sources/scopes.
type EffectiveBinding struct {
	RoleID      int64
	Permissions map[string]struct{}
	Source      string // "direct" | "group" | "org"
	SourceID    int64
	ScopeType   ScopeKind
	ScopeID     int64      // 0 when ScopeType == ScopeGlobal
	ExpiresAt   *time.Time // nil = permanent binding; non-nil = time-bound (JIT) grant
}

// BindingProvider is the permission domain's data access surface that the
// authz engine relies on.
type BindingProvider interface {
	// EffectiveBindingsForUser returns every binding a user has — direct
	// (subject_type='user'), inherited from groups they belong to, and
	// inherited from their orgs plus ancestors.
	//
	// Implementations are expected to pre-join role_permission so each
	// returned EffectiveBinding has its Permissions set populated; this
	// keeps the per-check cost O(bindings) rather than O(bindings * roles).
	EffectiveBindingsForUser(ctx context.Context, tenantID, userID int64) ([]EffectiveBinding, error)
}

// OrgAncestry abstracts the ltree relationship between orgs. Used by the
// engine to decide whether a binding's scope org covers a target org.
type OrgAncestry interface {
	// IsAncestorOrSelf reports whether `ancestor` is on the path from the
	// org root down to (and including) `descendant`. Returns false on any
	// repo error so callers err on the side of denying access.
	IsAncestorOrSelf(ctx context.Context, ancestor, descendant int64) (bool, error)
}
