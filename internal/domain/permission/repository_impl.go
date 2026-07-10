package permission

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// liveUserSubject excludes bindings whose subject is a SOFT-DELETED user, while
// keeping group/org subjects (which don't point at mxid_user). A user binding
// normally goes away on UserDeleted; this is the defense-in-depth net for a
// dropped event so a deleted user is not counted or listed as a role member.
const liveUserSubject = "(subject_type <> 'user' OR subject_id IN (SELECT id FROM mxid_user WHERE deleted_at IS NULL))"

// gormRepository implements Repository using GORM.
type gormRepository struct {
	db *gorm.DB
}

// NewGormRepository creates a new GORM-based permission repository.
func NewGormRepository(db *gorm.DB) Repository {
	return &gormRepository{db: db}
}

// CreateRole inserts a new role record.
func (r *gormRepository) CreateRole(ctx context.Context, role *Role) error {
	if err := r.db.WithContext(ctx).Create(role).Error; err != nil {
		return fmt.Errorf("create role: %w", err)
	}
	return nil
}

// GetRoleByID finds a role by primary key.
func (r *gormRepository) GetRoleByID(ctx context.Context, id int64) (*Role, error) {
	var role Role
	if err := r.db.WithContext(ctx).First(&role, id).Error; err != nil {
		return nil, fmt.Errorf("get role by id: %w", err)
	}
	return &role, nil
}

// GetRoleByCode finds a role by tenant and code.
func (r *gormRepository) GetRoleByCode(ctx context.Context, tenantID int64, code string) (*Role, error) {
	var role Role
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code = ?", tenantID, code).
		First(&role).Error
	if err != nil {
		return nil, fmt.Errorf("get role by code: %w", err)
	}
	return &role, nil
}

// UpdateRole saves changes to an existing role.
func (r *gormRepository) UpdateRole(ctx context.Context, role *Role) error {
	if err := r.db.WithContext(ctx).Save(role).Error; err != nil {
		return fmt.Errorf("update role: %w", err)
	}
	return nil
}

// DeleteRole performs a soft delete on a role.
// DeleteRole HARD-deletes the role so its bindings (mxid_role_binding) and
// permission grants (mxid_role_permission) cascade away. Soft delete orphans
// both. Role access policies (subject_type='role') are removed by the
// RoleDeleted event subscriber. System roles are guarded in the service layer.
func (r *gormRepository) DeleteRole(ctx context.Context, id int64) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&Role{}, id).Error; err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}

// ListRoles returns a paginated list of roles for a tenant.
func (r *gormRepository) ListRoles(ctx context.Context, tenantID int64, params RoleListParams) ([]*Role, int64, error) {
	var roles []*Role
	var total int64

	query := r.db.WithContext(ctx).Model(&Role{}).Where("tenant_id = ?", tenantID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count roles: %w", err)
	}

	offset := (params.Page - 1) * params.PageSize
	if err := query.Offset(offset).Limit(params.PageSize).Order("created_at DESC").Find(&roles).Error; err != nil {
		return nil, 0, fmt.Errorf("list roles: %w", err)
	}

	return roles, total, nil
}

// AddMember inserts a new role binding record.
func (r *gormRepository) AddMember(ctx context.Context, binding *RoleBinding) error {
	if err := r.db.WithContext(ctx).Create(binding).Error; err != nil {
		return fmt.Errorf("add role member: %w", err)
	}
	return nil
}

// RemoveMember deletes a role binding by ID.
func (r *gormRepository) RemoveMember(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Delete(&RoleBinding{}, id)
	if result.Error != nil {
		return fmt.Errorf("remove role member: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListMembers returns a paginated list of role bindings for a role.
func (r *gormRepository) ListMembers(ctx context.Context, roleID int64, params MemberListParams) ([]*RoleBinding, int64, error) {
	var bindings []*RoleBinding
	var total int64

	query := r.db.WithContext(ctx).Model(&RoleBinding{}).
		Where("role_id = ?", roleID).
		Where(liveUserSubject)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count role members: %w", err)
	}

	offset := (params.Page - 1) * params.PageSize
	if err := query.Offset(offset).Limit(params.PageSize).Order("created_at DESC").Find(&bindings).Error; err != nil {
		return nil, 0, fmt.Errorf("list role members: %w", err)
	}

	return bindings, total, nil
}

// GetBySubject returns all role bindings for a given subject.
func (r *gormRepository) GetBySubject(ctx context.Context, subjectType string, subjectID int64) ([]*RoleBinding, error) {
	var bindings []*RoleBinding
	err := r.db.WithContext(ctx).
		Where("subject_type = ? AND subject_id = ?", subjectType, subjectID).
		Find(&bindings).Error
	if err != nil {
		return nil, fmt.Errorf("get bindings by subject: %w", err)
	}
	return bindings, nil
}

// CountMembers returns the number of members bound to a role.
func (r *gormRepository) CountMembers(ctx context.Context, roleID int64) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&RoleBinding{}).
		Where("role_id = ?", roleID).
		Where(liveUserSubject).
		Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count role members: %w", err)
	}
	return count, nil
}

// ListPermissions returns all permissions for a tenant.
func (r *gormRepository) ListPermissions(ctx context.Context, tenantID int64) ([]*Permission, error) {
	var perms []*Permission
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("resource, action").
		Find(&perms).Error
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	return perms, nil
}

// GetPermissionsByIDs returns permissions matching the given IDs.
func (r *gormRepository) GetPermissionsByIDs(ctx context.Context, ids []int64) ([]*Permission, error) {
	var perms []*Permission
	if len(ids) == 0 {
		return perms, nil
	}
	err := r.db.WithContext(ctx).Where("id IN ?", ids).Find(&perms).Error
	if err != nil {
		return nil, fmt.Errorf("get permissions by ids: %w", err)
	}
	return perms, nil
}

// SetRolePermissions replaces all permissions for a role within a transaction.
func (r *gormRepository) SetRolePermissions(ctx context.Context, roleID int64, permissions []RolePermission) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete existing permissions for this role
		if err := tx.Where("role_id = ?", roleID).Delete(&RolePermission{}).Error; err != nil {
			return fmt.Errorf("delete existing role permissions: %w", err)
		}

		// Batch insert new permissions
		if len(permissions) > 0 {
			if err := tx.Create(&permissions).Error; err != nil {
				return fmt.Errorf("create role permissions: %w", err)
			}
		}

		return nil
	})
}

// GetRolePermissions returns all role-permission records for a role.
func (r *gormRepository) GetRolePermissions(ctx context.Context, roleID int64) ([]*RolePermission, error) {
	var rps []*RolePermission
	err := r.db.WithContext(ctx).
		Where("role_id = ?", roleID).
		Find(&rps).Error
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}
	return rps, nil
}

// GetBySubjects loads bindings for multiple subjects of one type in a single
// query. Returns an empty slice when subjectIDs is empty.
func (r *gormRepository) GetBySubjects(ctx context.Context, subjectType string, subjectIDs []int64) ([]*RoleBinding, error) {
	if len(subjectIDs) == 0 {
		return []*RoleBinding{}, nil
	}
	var rows []*RoleBinding
	err := r.db.WithContext(ctx).
		Where("subject_type = ? AND subject_id IN ?", subjectType, subjectIDs).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("get bindings by subjects: %w", err)
	}
	return rows, nil
}

// PermissionCodesByRoleIDs joins role_permission with permission so the authz
// engine gets each role's permission codes in one query.
func (r *gormRepository) PermissionCodesByRoleIDs(ctx context.Context, roleIDs []int64) (map[int64][]string, error) {
	result := make(map[int64][]string)
	if len(roleIDs) == 0 {
		return result, nil
	}
	type row struct {
		RoleID int64  `gorm:"column:role_id"`
		Code   string `gorm:"column:code"`
	}
	var rows []row
	err := r.db.WithContext(ctx).
		Table("mxid_role_permission rp").
		Select("rp.role_id AS role_id, p.code AS code").
		Joins("INNER JOIN mxid_permission p ON p.id = rp.permission_id").
		Where("rp.role_id IN ?", roleIDs).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("permission codes by role ids: %w", err)
	}
	for _, r := range rows {
		result[r.RoleID] = append(result[r.RoleID], r.Code)
	}
	return result, nil
}
