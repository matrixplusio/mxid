package permission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Service errors.
var (
	ErrRoleNotFound       = errors.New("role not found")
	ErrRoleCodeExists     = errors.New("role code already exists")
	ErrSystemRoleDelete   = errors.New("cannot delete system role")
	ErrMemberNotFound     = errors.New("member not found")
	ErrPermissionNotFound = errors.New("permission not found")
	// ErrSubjectNotInTenant is returned when AddMember is asked to bind a
	// subject (user/group/org) that does not exist in the caller's tenant —
	// including a cross-tenant id, which the injected validator (tenant-scoped
	// repo) reports as absent. Blocks the residual referenced-entity IDOR where
	// an admin binds a foreign-tenant subject to their own role.
	ErrSubjectNotInTenant = errors.New("subject not found in tenant")
	// ErrScopeNotInTenant is the same guard for the optional binding scope
	// (org/group) target.
	ErrScopeNotInTenant = errors.New("scope not found in tenant")
	// ErrScopeIncomplete is returned when only one of ScopeType/ScopeID is
	// set on an AddMember request — a half-set scope is ambiguous and must
	// be rejected as a client error, not silently accepted.
	ErrScopeIncomplete = errors.New("scope_type and scope_id must be set together")
)

// EntityValidator reports whether a referenced entity id exists within the
// caller's tenant. Backed by the referent's tenant-scoped GetByID (the
// tenantscope plugin appends tenant_id=?, so a cross-tenant id resolves to
// false). Injected so the permission service does not import user/group/org.
type EntityValidator func(ctx context.Context, id int64) (bool, error)

// RefValidators bundles the per-type tenant-scoped existence checks the
// binding-subject / scope guards need. Each may be nil only if the
// corresponding type can never be referenced.
type RefValidators struct {
	User  EntityValidator
	Group EntityValidator
	Org   EntityValidator
}

// Event type constants.
const (
	RoleCreated        = "role.created"
	RoleUpdated        = "role.updated"
	RoleDeleted        = "role.deleted"
	RolePermissionsSet = "role.permissions_set"
	RoleMemberAdded    = "role.member_added"
	RoleMemberRemoved  = "role.member_removed"
)

// Service provides business logic for permission management.
type Service struct {
	repo       Repository
	idGen      *snowflake.Generator
	eventBus   *event.Bus
	tenantID   int64
	validators RefValidators
}

// SetRefValidators injects the tenant-scoped subject/scope existence checks
// used by AddMember to validate request-body subject and scope ids. Wired in
// cmd/server/main.go once the user/group/org modules exist.
func (s *Service) SetRefValidators(v RefValidators) { s.validators = v }

// validateRef runs the tenant-scoped existence check for refType (user/group/
// org). A cross-tenant id resolves to false → notFoundErr. Fails closed if the
// matching validator was not wired.
func (s *Service) validateRef(ctx context.Context, refType string, id int64, notFoundErr error) error {
	var v EntityValidator
	switch refType {
	case SubjectTypeUser:
		v = s.validators.User
	case SubjectTypeGroup: // == ScopeTypeGroup
		v = s.validators.Group
	case SubjectTypeOrg: // == ScopeTypeOrg
		v = s.validators.Org
	default:
		return fmt.Errorf("permission: unknown ref type %q", refType)
	}
	if v == nil {
		return fmt.Errorf("permission: validator for %q not configured", refType)
	}
	ok, err := v(ctx, id)
	if err != nil {
		return fmt.Errorf("validate %s: %w", refType, err)
	}
	if !ok {
		return notFoundErr
	}
	return nil
}

// NewService creates a new permission service.
func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus, tenantID int64) *Service {
	return &Service{
		repo:     repo,
		idGen:    idGen,
		eventBus: eventBus,
		tenantID: tenantID,
	}
}

// CreateRole creates a new role for the given tenant.
//
// tenantID is the effective tenant — read from gin.Context by the handler
// (super_admin can override via X-Tenant-ID; tenant_admin sticks with their
// session tenant). When 0 falls back to the service's configured default
// so legacy callers still compile.
func (s *Service) CreateRole(ctx context.Context, tenantID int64, req *CreateRoleRequest) (*Role, error) {
	if tenantID == 0 {
		tenantID = s.tenantID
	}
	// Check code uniqueness within the tenant.
	if _, err := s.repo.GetRoleByCode(ctx, tenantID, req.Code); err == nil {
		return nil, ErrRoleCodeExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("check role code: %w", err)
	}

	now := time.Now()
	role := &Role{
		ID:          s.idGen.Generate(),
		TenantID:    tenantID,
		Name:        req.Name,
		Code:        req.Code,
		Type:        req.Type,
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.CreateRole(ctx, role); err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    RoleCreated,
		Payload: map[string]any{"role_id": role.ID, "code": role.Code},
	})

	return role, nil
}

// GetRole retrieves a role by ID.
func (s *Service) GetRole(ctx context.Context, id int64) (*Role, error) {
	role, err := s.repo.GetRoleByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	return role, nil
}

// UpdateRole modifies a role's mutable fields.
func (s *Service) UpdateRole(ctx context.Context, id int64, req *UpdateRoleRequest) (*Role, error) {
	role, err := s.repo.GetRoleByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}

	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		role.Description = req.Description
	}
	role.UpdatedAt = time.Now()

	if err := s.repo.UpdateRole(ctx, role); err != nil {
		return nil, fmt.Errorf("update role: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    RoleUpdated,
		Payload: map[string]any{"role_id": role.ID},
	})

	return role, nil
}

// DeleteRole soft-deletes a role. System roles cannot be deleted.
func (s *Service) DeleteRole(ctx context.Context, id int64) error {
	role, err := s.repo.GetRoleByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get role: %w", err)
	}

	if role.Type == RoleTypeSystem {
		return ErrSystemRoleDelete
	}

	if err := s.repo.DeleteRole(ctx, id); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    RoleDeleted,
		Payload: map[string]any{"role_id": id},
	})

	return nil
}

// ListRoles returns a paginated list of roles for the given tenant.
func (s *Service) ListRoles(ctx context.Context, tenantID int64, params RoleListParams) ([]*Role, int64, error) {
	if tenantID == 0 {
		tenantID = s.tenantID
	}
	roles, total, err := s.repo.ListRoles(ctx, tenantID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("list roles: %w", err)
	}
	return roles, total, nil
}

// GetRolePermissions returns the permissions assigned to a role.
func (s *Service) GetRolePermissions(ctx context.Context, roleID int64) ([]*Permission, error) {
	// Verify role exists
	if _, err := s.repo.GetRoleByID(ctx, roleID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}

	rps, err := s.repo.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}

	if len(rps) == 0 {
		return []*Permission{}, nil
	}

	ids := make([]int64, len(rps))
	for i, rp := range rps {
		ids[i] = rp.PermissionID
	}

	perms, err := s.repo.GetPermissionsByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("get permissions by ids: %w", err)
	}

	return perms, nil
}

// SetRolePermissions replaces all permissions for a role.
func (s *Service) SetRolePermissions(ctx context.Context, roleID int64, permissionIDs []int64) error {
	// Verify role exists
	if _, err := s.repo.GetRoleByID(ctx, roleID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get role: %w", err)
	}

	// Verify all permission IDs exist
	if len(permissionIDs) > 0 {
		perms, err := s.repo.GetPermissionsByIDs(ctx, permissionIDs)
		if err != nil {
			return fmt.Errorf("verify permissions: %w", err)
		}
		if len(perms) != len(permissionIDs) {
			return ErrPermissionNotFound
		}
	}

	now := time.Now()
	rps := make([]RolePermission, len(permissionIDs))
	for i, pid := range permissionIDs {
		rps[i] = RolePermission{
			ID:           s.idGen.Generate(),
			RoleID:       roleID,
			PermissionID: pid,
			CreatedAt:    now,
		}
	}

	if err := s.repo.SetRolePermissions(ctx, roleID, rps); err != nil {
		return fmt.Errorf("set role permissions: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    RolePermissionsSet,
		Payload: map[string]any{"role_id": roleID, "permission_ids": permissionIDs},
	})

	return nil
}

// AddMember adds a subject to a role, optionally bound to a resource scope.
//
// Validation: if ScopeType is set, ScopeID must also be set, and vice versa
// — half-set scopes would be ambiguous.
func (s *Service) AddMember(ctx context.Context, roleID int64, req *AddMemberRequest) (*RoleBinding, error) {
	if _, err := s.repo.GetRoleByID(ctx, roleID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}

	// scope_type and scope_id must come together.
	if (req.ScopeType != nil) != (req.ScopeID != nil) {
		return nil, ErrScopeIncomplete
	}

	// Referenced-entity guard: the subject (and optional scope) ids come from
	// the request body. Validate each against the caller's tenant so a foreign
	// subject/scope cannot be bound to a role the caller owns. A cross-tenant id
	// resolves to not-found via the tenant-scoped validator.
	if err := s.validateRef(ctx, req.SubjectType, req.SubjectID, ErrSubjectNotInTenant); err != nil {
		return nil, err
	}
	if req.ScopeType != nil {
		if err := s.validateRef(ctx, *req.ScopeType, *req.ScopeID, ErrScopeNotInTenant); err != nil {
			return nil, err
		}
	}

	binding := &RoleBinding{
		ID:          s.idGen.Generate(),
		RoleID:      roleID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		ScopeType:   req.ScopeType,
		ScopeID:     req.ScopeID,
		CreatedAt:   time.Now(),
	}

	if err := s.repo.AddMember(ctx, binding); err != nil {
		return nil, fmt.Errorf("add member: %w", err)
	}

	payload := map[string]any{
		"role_id":      roleID,
		"subject_type": req.SubjectType,
		"subject_id":   req.SubjectID,
	}
	if req.ScopeType != nil {
		payload["scope_type"] = *req.ScopeType
		payload["scope_id"] = *req.ScopeID
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    RoleMemberAdded,
		Payload: payload,
	})

	return binding, nil
}

// RemoveMember removes a member binding from a role.
func (s *Service) RemoveMember(ctx context.Context, roleID int64, memberID int64) error {
	// Verify role exists
	if _, err := s.repo.GetRoleByID(ctx, roleID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get role: %w", err)
	}

	if err := s.repo.RemoveMember(ctx, memberID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("remove member: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    RoleMemberRemoved,
		Payload: map[string]any{"role_id": roleID, "member_id": memberID},
	})

	return nil
}

// ListMembers returns a paginated list of members for a role.
func (s *Service) ListMembers(ctx context.Context, roleID int64, params MemberListParams) ([]*RoleBinding, int64, error) {
	// Verify role exists
	if _, err := s.repo.GetRoleByID(ctx, roleID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrRoleNotFound
		}
		return nil, 0, fmt.Errorf("get role: %w", err)
	}

	bindings, total, err := s.repo.ListMembers(ctx, roleID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("list members: %w", err)
	}

	return bindings, total, nil
}

// CountMembers returns the count of members for a role.
func (s *Service) CountMembers(ctx context.Context, roleID int64) (int64, error) {
	count, err := s.repo.CountMembers(ctx, roleID)
	if err != nil {
		return 0, fmt.Errorf("count members: %w", err)
	}
	return count, nil
}

// ListAllPermissions returns all permissions for the given tenant.
func (s *Service) ListAllPermissions(ctx context.Context, tenantID int64) ([]*Permission, error) {
	if tenantID == 0 {
		tenantID = s.tenantID
	}
	perms, err := s.repo.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	return perms, nil
}
