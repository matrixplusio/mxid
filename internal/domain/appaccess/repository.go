package appaccess

import (
	"context"

	"gorm.io/gorm"
)

// Repository is the raw policy storage layer.
type Repository interface {
	// ListByApp returns rules owned directly by an app + rules inherited
	// from any app_group it belongs to. Used by the console "access" tab
	// (own only) and CanAccess (effective).
	ListByApp(ctx context.Context, appID, tenantID int64) ([]*Policy, error)
	// ListOwnByApp returns ONLY rows whose app_id matches — no group
	// inheritance. Used by the console to render the "own rules" list
	// without bleed from groups.
	ListOwnByApp(ctx context.Context, appID, tenantID int64) ([]*Policy, error)
	// ListByAppGroup returns rows owned by an app_group.
	ListByAppGroup(ctx context.Context, appGroupID, tenantID int64) ([]*Policy, error)
	Create(ctx context.Context, p *Policy) error
	GetByID(ctx context.Context, id, tenantID int64) (*Policy, error)
	Delete(ctx context.Context, id int64) error
	// AppsForUser returns the set of app_ids the user is allowed to launch
	// based on combined allow/deny rules across all access subjects (user
	// itself + groups + orgs + roles) AND any app_group the app belongs to.
	AppsForUser(ctx context.Context, userID, tenantID int64) ([]int64, error)
}

type repo struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) Repository { return &repo{db: db} }

// ListByApp returns the effective rule set for an app:
//   - rows where app_id = appID
//   - PLUS rows where app_group_id is any group containing appID
// Used by CanAccess at /authorize time.
func (r *repo) ListByApp(ctx context.Context, appID, tenantID int64) ([]*Policy, error) {
	const q = `
SELECT * FROM mxid_app_access_policy
WHERE tenant_id = ?
  AND (
    app_id = ?
    OR app_group_id IN (
        SELECT group_id FROM mxid_app_group_rel WHERE app_id = ?
    )
  )
ORDER BY created_at DESC`
	var rows []*Policy
	err := r.db.WithContext(ctx).Raw(q, tenantID, appID, appID).Scan(&rows).Error
	return rows, err
}

// ListOwnByApp — only rows whose app_id matches. Console uses this for
// the "rules attached directly to this app" pane (group inheritance is
// shown separately or as a read-only badge).
func (r *repo) ListOwnByApp(ctx context.Context, appID, tenantID int64) ([]*Policy, error) {
	var rows []*Policy
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND tenant_id = ?", appID, tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *repo) ListByAppGroup(ctx context.Context, appGroupID, tenantID int64) ([]*Policy, error) {
	var rows []*Policy
	err := r.db.WithContext(ctx).
		Where("app_group_id = ? AND tenant_id = ?", appGroupID, tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *repo) Create(ctx context.Context, p *Policy) error {
	return r.db.WithContext(ctx).Create(p).Error
}

func (r *repo) GetByID(ctx context.Context, id, tenantID int64) (*Policy, error) {
	var row Policy
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		First(&row).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *repo) Delete(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Delete(&Policy{}, "id = ?", id).Error
}

// AppsForUser implements the SQL-side eval. Computed as:
//
//   allowed = ∃ row with effect=allow that matches the user AND the app
//             (either app_id directly OR app belongs to a group whose
//             app_group_id matches the rule)
//   denied  = ∃ row with effect=deny  same matching
//   final   = allowed AND NOT denied
//
// Matching:
//   public                                  → always matches
//   user / subject_id == userID             → match
//   group / user in member set              → match
//   org   / user in org subtree             → match  (uses ltree path)
//   role  / user has role binding (any scope) → match
//
// We project (effect, app_id) using a UNION ALL between direct app rules
// and group-inherited rules. The portal /apps query joins on the result.
func (r *repo) AppsForUser(ctx context.Context, userID, tenantID int64) ([]int64, error) {
	const subjectMatchSQL = `
    (
      p.subject_type = 'public'
      OR (p.subject_type = 'user'  AND p.subject_id = ?)
      OR (p.subject_type = 'group' AND p.subject_id IN (
          SELECT g.id FROM mxid_user_group g
          INNER JOIN mxid_user_group_member m ON m.group_id = g.id
          WHERE m.user_id = ? AND g.deleted_at IS NULL
      ))
      OR (p.subject_type = 'org' AND EXISTS (
          SELECT 1 FROM mxid_user_org uo
          INNER JOIN mxid_organization o ON o.id = uo.org_id AND o.deleted_at IS NULL
          WHERE uo.user_id = ?
            AND (o.id = p.subject_id OR o.path <@ (
                SELECT path FROM mxid_organization WHERE id = p.subject_id
            ))
      ))
      OR (p.subject_type = 'role' AND EXISTS (
          SELECT 1 FROM mxid_role_binding b
          WHERE b.role_id = p.subject_id
            AND b.subject_type = 'user'
            AND b.subject_id = ?
      ))
    )`

	// Direct app rules + group-inherited rules, separated by UNION ALL so
	// the planner can use both indexes (idx_app_tenant, idx_app_group).
	allowedSQL := `
(
    SELECT DISTINCT p.app_id FROM mxid_app_access_policy p
    WHERE p.tenant_id IN (?, 0) AND p.effect = 'allow' AND p.app_id IS NOT NULL
      AND ` + subjectMatchSQL + `
)
UNION
(
    SELECT DISTINCT rel.app_id FROM mxid_app_access_policy p
    INNER JOIN mxid_app_group_rel rel ON rel.group_id = p.app_group_id
    WHERE p.tenant_id IN (?, 0) AND p.effect = 'allow' AND p.app_group_id IS NOT NULL
      AND ` + subjectMatchSQL + `
)`

	deniedSQL := `
(
    SELECT DISTINCT p.app_id FROM mxid_app_access_policy p
    WHERE p.tenant_id IN (?, 0) AND p.effect = 'deny' AND p.app_id IS NOT NULL
      AND ` + subjectMatchSQL + `
)
UNION
(
    SELECT DISTINCT rel.app_id FROM mxid_app_access_policy p
    INNER JOIN mxid_app_group_rel rel ON rel.group_id = p.app_group_id
    WHERE p.tenant_id IN (?, 0) AND p.effect = 'deny' AND p.app_group_id IS NOT NULL
      AND ` + subjectMatchSQL + `
)`

	var allowed, denied []int64
	if err := r.db.WithContext(ctx).
		Raw(allowedSQL, tenantID, userID, userID, userID, userID, tenantID, userID, userID, userID, userID).
		Scan(&allowed).Error; err != nil {
		return nil, err
	}
	if err := r.db.WithContext(ctx).
		Raw(deniedSQL, tenantID, userID, userID, userID, userID, tenantID, userID, userID, userID, userID).
		Scan(&denied).Error; err != nil {
		return nil, err
	}

	deniedSet := make(map[int64]struct{}, len(denied))
	for _, id := range denied {
		deniedSet[id] = struct{}{}
	}
	out := make([]int64, 0, len(allowed))
	for _, id := range allowed {
		if _, blocked := deniedSet[id]; blocked {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}
