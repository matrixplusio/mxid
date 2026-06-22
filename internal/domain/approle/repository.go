package approle

import (
	"context"

	"gorm.io/gorm"
)

// Owner identifies which target an AppRole / Binding belongs to.
// Use 'app' or 'app-group'; methods that take an Owner pair with an ID
// of that target.
type Owner string

const (
	OwnerApp      Owner = "app"
	OwnerAppGroup Owner = "app-group"
)

type Repository interface {
	// Roles
	ListRoles(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*AppRole, error)
	GetRoleByID(ctx context.Context, id, tenantID int64) (*AppRole, error)
	CreateRole(ctx context.Context, r *AppRole) error
	UpdateRole(ctx context.Context, r *AppRole) error
	DeleteRole(ctx context.Context, id, tenantID int64) error

	// Bindings
	ListBindings(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*Binding, error)
	ListBindingsBySubject(ctx context.Context, subjectType string, subjectID, tenantID int64) ([]*Binding, error)
	GetBindingByID(ctx context.Context, id, tenantID int64) (*Binding, error)
	CreateBinding(ctx context.Context, b *Binding) error
	DeleteBinding(ctx context.Context, id, tenantID int64) error

	// ResolveCodesForUser returns role codes (app-level + group-inherited)
	// for the given user against an app at /token time.
	ResolveCodesForUser(ctx context.Context, userID, appID, tenantID int64) ([]string, error)

	// MemberAppIDs returns the app_ids belonging to an app-group. Used by
	// the app-group role aggregation view in the console.
	MemberAppIDs(ctx context.Context, groupID int64) ([]int64, error)
}

type repo struct{ db *gorm.DB }

func NewRepository(db *gorm.DB) Repository { return &repo{db: db} }

// ─── Roles ───

func (r *repo) ListRoles(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*AppRole, error) {
	col := ownerColumn(owner)
	var rows []*AppRole
	err := r.db.WithContext(ctx).
		Where(col+" = ? AND tenant_id = ?", ownerID, tenantID).
		Order("sort_order, code").
		Find(&rows).Error
	return rows, err
}

func (r *repo) GetRoleByID(ctx context.Context, id, tenantID int64) (*AppRole, error) {
	var row AppRole
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		First(&row).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *repo) CreateRole(ctx context.Context, role *AppRole) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if role.IsDefault {
			// Unset existing default on the SAME owner scope.
			q := tx.Model(&AppRole{}).Where("tenant_id = ? AND is_default = TRUE", role.TenantID)
			if role.AppID != nil {
				q = q.Where("app_id = ?", *role.AppID)
			} else if role.AppGroupID != nil {
				q = q.Where("app_group_id = ?", *role.AppGroupID)
			}
			if err := q.Update("is_default", false).Error; err != nil {
				return err
			}
		}
		return tx.Create(role).Error
	})
}

func (r *repo) UpdateRole(ctx context.Context, role *AppRole) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if role.IsDefault {
			q := tx.Model(&AppRole{}).
				Where("tenant_id = ? AND id <> ? AND is_default = TRUE", role.TenantID, role.ID)
			if role.AppID != nil {
				q = q.Where("app_id = ?", *role.AppID)
			} else if role.AppGroupID != nil {
				q = q.Where("app_group_id = ?", *role.AppGroupID)
			}
			if err := q.Update("is_default", false).Error; err != nil {
				return err
			}
		}
		return tx.Save(role).Error
	})
}

func (r *repo) DeleteRole(ctx context.Context, id, tenantID int64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("app_role_id = ?", id).Delete(&Binding{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&AppRole{}).Error
	})
}

// ─── Bindings ───

func (r *repo) ListBindings(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*Binding, error) {
	col := ownerColumn(owner)
	var rows []*Binding
	err := r.db.WithContext(ctx).
		Where(col+" = ? AND tenant_id = ?", ownerID, tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

// ListBindingsBySubject — reverse view. Used by the user-group page to
// show "this group is bound to these app roles" without rebuilding the
// query per app.
func (r *repo) ListBindingsBySubject(ctx context.Context, subjectType string, subjectID, tenantID int64) ([]*Binding, error) {
	var rows []*Binding
	err := r.db.WithContext(ctx).
		Where("subject_type = ? AND subject_id = ? AND tenant_id = ?", subjectType, subjectID, tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

func (r *repo) GetBindingByID(ctx context.Context, id, tenantID int64) (*Binding, error) {
	var row Binding
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		First(&row).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *repo) CreateBinding(ctx context.Context, b *Binding) error {
	return r.db.WithContext(ctx).Create(b).Error
}

func (r *repo) DeleteBinding(ctx context.Context, id, tenantID int64) error {
	return r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		Delete(&Binding{}).Error
}

// ResolveCodesForUser unions:
//   - bindings where app_id = appID
//   - bindings where app_group_id ∈ groups containing appID
//
// Only active bindings count: status=1 AND (expires_at IS NULL OR expires_at > NOW()).
// NULL expires_at = permanent binding (unchanged behavior).
// Empty result → fall back to default role of the app (app-level priority).
func (r *repo) ResolveCodesForUser(ctx context.Context, userID, appID, tenantID int64) ([]string, error) {
	// activeBindingSQL filters out expired and revoked time-bound bindings.
	// Uses no extra query params (NOW() is a SQL function call, not a placeholder).
	const activeBindingSQL = ` AND b.status = 1 AND (b.expires_at IS NULL OR b.expires_at > NOW()) `

	const subjectMatchSQL = `
    (
      (b.subject_type = 'user'  AND b.subject_id = ?)
      OR (b.subject_type = 'group' AND b.subject_id IN (
          SELECT g.id FROM mxid_user_group g
          INNER JOIN mxid_user_group_member m ON m.group_id = g.id
          WHERE m.user_id = ? AND g.deleted_at IS NULL
      ))
      OR (b.subject_type = 'org' AND EXISTS (
          SELECT 1 FROM mxid_user_org uo
          INNER JOIN mxid_organization o ON o.id = uo.org_id AND o.deleted_at IS NULL
          WHERE uo.user_id = ?
            AND (o.id = b.subject_id OR o.path <@ (
                SELECT path FROM mxid_organization WHERE id = b.subject_id
            ))
      ))
      OR (b.subject_type = 'role' AND EXISTS (
          SELECT 1 FROM mxid_role_binding rb
          WHERE rb.role_id = b.subject_id
            AND rb.subject_type = 'user'
            AND rb.subject_id = ?
            AND rb.status = 1
            AND (rb.expires_at IS NULL OR rb.expires_at > NOW())
      ))
    )`

	q := `
(
    SELECT DISTINCT ar.code, ar.sort_order
    FROM mxid_app_role_binding b
    INNER JOIN mxid_app_role ar ON ar.id = b.app_role_id
    WHERE b.app_id = ? AND b.tenant_id IN (?, 0)` + activeBindingSQL + `
      AND ` + subjectMatchSQL + `
)
UNION
(
    SELECT DISTINCT ar.code, ar.sort_order
    FROM mxid_app_role_binding b
    INNER JOIN mxid_app_role ar ON ar.id = b.app_role_id
    INNER JOIN mxid_app_group_rel rel ON rel.group_id = b.app_group_id
    WHERE rel.app_id = ? AND b.tenant_id IN (?, 0) AND b.app_group_id IS NOT NULL` + activeBindingSQL + `
      AND ` + subjectMatchSQL + `
)
ORDER BY sort_order ASC, code ASC`

	type row struct {
		Code      string
		SortOrder int
	}
	var rows []row
	if err := r.db.WithContext(ctx).Raw(q,
		appID, tenantID, userID, userID, userID, userID,
		appID, tenantID, userID, userID, userID, userID,
	).Scan(&rows).Error; err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		// Fall back: default role on the app itself, then on any group it belongs to.
		var defaultCode string
		const dq = `
SELECT code FROM mxid_app_role
WHERE tenant_id = ? AND is_default = TRUE
  AND (
    app_id = ?
    OR app_group_id IN (SELECT group_id FROM mxid_app_group_rel WHERE app_id = ?)
  )
ORDER BY (app_id IS NOT NULL) DESC, sort_order ASC
LIMIT 1`
		err := r.db.WithContext(ctx).Raw(dq, tenantID, appID, appID).Scan(&defaultCode).Error
		if err != nil || defaultCode == "" {
			return []string{}, nil
		}
		return []string{defaultCode}, nil
	}

	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Code
	}
	return out, nil
}

func ownerColumn(o Owner) string {
	if o == OwnerAppGroup {
		return "app_group_id"
	}
	return "app_id"
}

func (r *repo) MemberAppIDs(ctx context.Context, groupID int64) ([]int64, error) {
	var ids []int64
	err := r.db.WithContext(ctx).
		Table("mxid_app_group_rel").
		Where("group_id = ?", groupID).
		Pluck("app_id", &ids).Error
	return ids, err
}
