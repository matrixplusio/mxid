package org

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type repository struct {
	db *gorm.DB
}

// NewRepository creates a new GORM-backed organization repository.
func NewRepository(db *gorm.DB) Repository {
	return &repository{db: db}
}

func (r *repository) Create(ctx context.Context, org *Organization) error {
	if err := r.db.WithContext(ctx).Create(org).Error; err != nil {
		return fmt.Errorf("create organization: %w", err)
	}
	return nil
}

func (r *repository) GetByID(ctx context.Context, id int64) (*Organization, error) {
	var org Organization
	if err := r.db.WithContext(ctx).First(&org, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("get organization by id: %w", err)
	}
	return &org, nil
}

func (r *repository) GetByCode(ctx context.Context, tenantID int64, code string) (*Organization, error) {
	var org Organization
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code = ?", tenantID, code).
		First(&org).Error; err != nil {
		return nil, fmt.Errorf("get organization by code: %w", err)
	}
	return &org, nil
}

func (r *repository) Update(ctx context.Context, org *Organization) error {
	if err := r.db.WithContext(ctx).Save(org).Error; err != nil {
		return fmt.Errorf("update organization: %w", err)
	}
	return nil
}

// Delete HARD-deletes the org so its user assignments (mxid_user_org) cascade
// away. Soft delete would strand them. The service layer guards against deleting
// an org that still has sub-orgs (the parent_id self-ref has no ON DELETE, so a
// bare delete would orphan the subtree). Org access policies (subject_type='org')
// are removed by the OrgDeleted event subscriber.
func (r *repository) Delete(ctx context.Context, id int64) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&Organization{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	return nil
}

func (r *repository) GetTree(ctx context.Context, tenantID int64) ([]*Organization, error) {
	var orgs []*Organization
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("path ASC, sort_order ASC").
		Find(&orgs).Error; err != nil {
		return nil, fmt.Errorf("get organization tree: %w", err)
	}
	return orgs, nil
}

func (r *repository) GetChildren(ctx context.Context, parentID int64) ([]*Organization, error) {
	var orgs []*Organization
	if err := r.db.WithContext(ctx).
		Where("parent_id = ?", parentID).
		Order("sort_order ASC").
		Find(&orgs).Error; err != nil {
		return nil, fmt.Errorf("get children: %w", err)
	}
	return orgs, nil
}

func (r *repository) GetByPath(ctx context.Context, tenantID int64, path string) ([]*Organization, error) {
	var orgs []*Organization
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND path::text LIKE ?", tenantID, path+".%").
		Order("path ASC").
		Find(&orgs).Error; err != nil {
		return nil, fmt.Errorf("get organizations by path: %w", err)
	}
	return orgs, nil
}

func (r *repository) Move(ctx context.Context, id int64, newParentID *int64, newPath string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Get the current organization
		var org Organization
		if err := tx.First(&org, "id = ?", id).Error; err != nil {
			return fmt.Errorf("get organization for move: %w", err)
		}

		oldPath := org.Path

		// Update the organization itself
		updates := map[string]any{
			"parent_id": newParentID,
			"path":      newPath,
		}
		if err := tx.Model(&Organization{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return fmt.Errorf("update organization path: %w", err)
		}

		// Update all descendant paths by replacing the old prefix with the new one
		if err := tx.Exec(
			"UPDATE mxid_organization SET path = CAST(? || SUBSTRING(path::text FROM ?) AS ltree) WHERE path::text LIKE ? AND id != ? AND deleted_at IS NULL",
			newPath,
			fmt.Sprintf("%d", len(oldPath)+1),
			oldPath+".%",
			id,
		).Error; err != nil {
			return fmt.Errorf("update descendant paths: %w", err)
		}

		return nil
	})
}

func (r *repository) AddMember(ctx context.Context, rel *UserOrg) error {
	if err := r.db.WithContext(ctx).Create(rel).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return fmt.Errorf("user already member of organization: %w", err)
		}
		return fmt.Errorf("add member to organization: %w", err)
	}
	return nil
}

func (r *repository) RemoveMember(ctx context.Context, userID, orgID int64) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND org_id = ?", userID, orgID).
		Delete(&UserOrg{})
	if result.Error != nil {
		return fmt.Errorf("remove member from organization: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("member not found in organization")
	}
	return nil
}

// GetMembers lists the users of an org AND of every descendant org. A department
// head sees everyone under them without opening each sub-department. The subtree
// is matched on the path prefix — an org is in the subtree when its path equals
// the root path or begins with "<root>." — expressed via CAST(path AS TEXT) so
// it runs on both Postgres (ltree) and the SQLite test harness. A user assigned
// to several sub-orgs is returned once (DISTINCT), ordered by first assignment
// for stable pagination.
func (r *repository) GetMembers(ctx context.Context, orgID int64, page, pageSize int) ([]int64, int64, error) {
	rootPath := r.db.
		Table("mxid_organization").
		Select("CAST(path AS TEXT)").
		Where("id = ? AND deleted_at IS NULL", orgID)
	subtree := r.db.WithContext(ctx).
		Table("mxid_organization").
		Select("id").
		Where("deleted_at IS NULL AND (CAST(path AS TEXT) = (?) OR CAST(path AS TEXT) LIKE (?) || '.%')", rootPath, rootPath)

	// Exclude soft-deleted users: their mxid_user_org rows persist (membership is
	// normally purged on UserDeleted, but this is the defense-in-depth net for a
	// dropped event) and mxid_user_org has no deleted_at of its own, so without
	// this a soft-deleted user would still be counted and listed as a member.
	liveUsers := "user_id IN (SELECT id FROM mxid_user WHERE deleted_at IS NULL)"

	var total int64
	if err := r.db.WithContext(ctx).
		Model(&UserOrg{}).
		Where("org_id IN (?)", subtree).
		Where(liveUsers).
		Distinct("user_id").
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count organization members: %w", err)
	}

	var userIDs []int64
	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).
		Model(&UserOrg{}).
		Where("org_id IN (?)", subtree).
		Where(liveUsers).
		Group("user_id").
		Order("MIN(created_at) ASC").
		Offset(offset).
		Limit(pageSize).
		Pluck("user_id", &userIDs).Error; err != nil {
		return nil, 0, fmt.Errorf("get organization members: %w", err)
	}
	return userIDs, total, nil
}

func (r *repository) GetUserOrgs(ctx context.Context, tenantID, userID int64) ([]*UserOrgInfo, error) {
	out := make([]*UserOrgInfo, 0)
	// Explicit tenant filter on the JOINed org table: mxid_user_org has no
	// tenant column, so a bare WHERE user_id=? would leak any org row the
	// membership points at. The join fences it to the caller's tenant.
	if err := r.db.WithContext(ctx).
		Raw(`
SELECT o.id AS org_id, o.name, o.code, o.path, uo.is_primary
FROM mxid_user_org uo
JOIN mxid_organization o ON o.id = uo.org_id AND o.deleted_at IS NULL AND o.tenant_id = ?
WHERE uo.user_id = ?
ORDER BY uo.is_primary DESC, o.path
`, tenantID, userID).
		Scan(&out).Error; err != nil {
		return nil, fmt.Errorf("get user organizations: %w", err)
	}
	return out, nil
}

// AncestorIDsForUser returns every org_id a user belongs to, expanded along
// the ltree path so each direct membership pulls in its ancestor chain.
//
// Used by the permission resolver: a user assigned to "root.eng.platform"
// inherits role bindings on root.eng.platform, root.eng AND root.
func (r *repository) AncestorIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error) {
	ids := make([]int64, 0)
	err := r.db.WithContext(ctx).
		Raw(`
SELECT DISTINCT o2.id
FROM mxid_user_org uo
JOIN mxid_organization o1 ON o1.id = uo.org_id AND o1.deleted_at IS NULL
JOIN mxid_organization o2 ON o1.path <@ o2.path AND o2.deleted_at IS NULL AND o2.tenant_id = ?
WHERE uo.user_id = ?
`, tenantID, userID).
		Scan(&ids).Error
	if err != nil {
		return nil, fmt.Errorf("ancestor org ids: %w", err)
	}
	return ids, nil
}

// IsAncestorOrSelf reports whether `ancestor` is on the path of `descendant`,
// inclusive. Implemented via ltree's `<@` (is-descendant-of) operator on the
// path column — uses the GIST index created in migration 000003.
func (r *repository) IsAncestorOrSelf(ctx context.Context, ancestor, descendant int64) (bool, error) {
	if ancestor == descendant {
		return true, nil
	}
	var n int64
	err := r.db.WithContext(ctx).
		Raw(`
SELECT 1
FROM mxid_organization d, mxid_organization a
WHERE d.id = ? AND a.id = ?
  AND d.path <@ a.path
  AND d.deleted_at IS NULL AND a.deleted_at IS NULL
LIMIT 1
`, descendant, ancestor).
		Scan(&n).Error
	if err != nil {
		return false, fmt.Errorf("is ancestor: %w", err)
	}
	return n == 1, nil
}
