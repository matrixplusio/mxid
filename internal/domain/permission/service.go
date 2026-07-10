package permission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
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
	// ErrSuperAdminUserOnly is returned when a group/org subject is added to the
	// built-in super_admin role. Super-admin is a per-user capability (the
	// mxid_user.is_super_admin flag), so only user subjects are meaningful.
	ErrSuperAdminUserOnly = errors.New("super_admin can only be granted to a user")
	// ErrSuperAdminUnavailable is returned when the super_admin role is operated
	// on but the flag manager was not wired (misconfiguration / tests).
	ErrSuperAdminUnavailable = errors.New("super-admin manager not configured")
)

// SuperAdminRoleCode is the reserved code of the built-in super-admin role
// (seed migration 000006). Its power lives on the mxid_user.is_super_admin flag
// (migration 000033), so the permission service treats this role's membership
// as a FAÇADE over that flag: add/remove/list a member here grants/revokes/lists
// the flag rather than writing role_binding rows. See SuperAdminManager.
const SuperAdminRoleCode = "super_admin"

// SuperAdminInfo identifies a super-admin user for the super_admin role's
// member list (rendered from the is_super_admin flag, not role bindings).
type SuperAdminInfo struct {
	UserID    int64
	Name      string
	Secondary string
}

// SuperAdminManager bridges the super_admin role's member operations to the
// authoritative is_super_admin flag. Injected from the app layer over the user
// domain so the permission package does not import it. SetSuperAdmin enforces
// the tenant scope, idempotency and the last-super-admin guard; ListSuperAdmins
// backs the member list.
type SuperAdminManager interface {
	SetSuperAdmin(ctx context.Context, actorID, tenantID, targetID int64, makeSuper bool) error
	ListSuperAdmins(ctx context.Context, tenantID int64) ([]SuperAdminInfo, error)
}

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

// SubjectInfo is the human-readable identity of a role-binding subject,
// resolved for display in the member list (so admins see a name, not a raw
// snowflake id). Secondary is an optional disambiguator (e.g. a user's email).
type SubjectInfo struct {
	Name      string
	Secondary string
}

// SubjectNameResolver batch-resolves subject ids of one type (user/group/org)
// to display info. Missing ids are simply absent from the returned map; the
// caller falls back to the raw id. Injected so the permission service does not
// import user/group/org (mirrors RefValidators).
type SubjectNameResolver func(ctx context.Context, ids []int64) (map[int64]SubjectInfo, error)

// SubjectResolvers bundles the per-type name resolvers used to enrich the
// member list. Any may be nil; a nil resolver leaves those subjects showing
// their raw id.
type SubjectResolvers struct {
	User  SubjectNameResolver
	Group SubjectNameResolver
	Org   SubjectNameResolver
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
	resolvers  SubjectResolvers
	superAdmin SuperAdminManager
}

// SetSuperAdminManager injects the flag bridge used to operate the super_admin
// role as a façade over mxid_user.is_super_admin. Wired once the user module
// exists. When nil, super_admin member operations return ErrSuperAdminUnavailable.
func (s *Service) SetSuperAdminManager(m SuperAdminManager) { s.superAdmin = m }

// SetRefValidators injects the tenant-scoped subject/scope existence checks
// used by AddMember to validate request-body subject and scope ids. Wired in
// cmd/server/main.go once the user/group/org modules exist.
func (s *Service) SetRefValidators(v RefValidators) { s.validators = v }

// SetSubjectResolvers injects the per-type name resolvers used to enrich the
// member list with display names. Wired alongside SetRefValidators once the
// user/group/org modules exist. Nil resolvers leave subjects showing raw ids.
func (s *Service) SetSubjectResolvers(r SubjectResolvers) { s.resolvers = r }

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
	} else if !dberr.IsNotFound(err) {
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
		if dberr.IsNotFound(err) {
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
		if dberr.IsNotFound(err) {
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
		if dberr.IsNotFound(err) {
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
		if dberr.IsNotFound(err) {
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

// GetPermissionsByIDs resolves permission rows (incl. their codes) for the given
// ids. Used by the handler's privilege-escalation guard on SetPermissions so a
// caller can only add permissions they themselves hold.
func (s *Service) GetPermissionsByIDs(ctx context.Context, ids []int64) ([]*Permission, error) {
	return s.repo.GetPermissionsByIDs(ctx, ids)
}

// SetRolePermissions replaces all permissions for a role.
func (s *Service) SetRolePermissions(ctx context.Context, roleID int64, permissionIDs []int64) error {
	// Verify role exists
	if _, err := s.repo.GetRoleByID(ctx, roleID); err != nil {
		if dberr.IsNotFound(err) {
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
// actorID is the caller performing the assignment — recorded on the audit event
// for the super_admin grant path.
//
// Validation: if ScopeType is set, ScopeID must also be set, and vice versa
// — half-set scopes would be ambiguous.
func (s *Service) AddMember(ctx context.Context, actorID, roleID int64, req *AddMemberRequest) (*RoleBinding, error) {
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}

	// The built-in super_admin role is a façade over the mxid_user.is_super_admin
	// flag (migration 000033 moved super-admin power off role bindings onto that
	// column, which the authz engine reads). So "adding a member" here means
	// flipping the flag — not writing an inert role_binding that would grant
	// nothing. Only user subjects are meaningful (the flag is per-user).
	if role.Code == SuperAdminRoleCode {
		return s.grantSuperAdmin(ctx, actorID, role.TenantID, roleID, req)
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
		"tenant_id":    role.TenantID,
	}
	// When the subject is a user, surface it under the "user_id" key too so the
	// authz cache-invalidation subscriber can do a TARGETED Invalidate (which
	// purges the L2/Redis entry immediately) instead of falling back to a coarse
	// InvalidateAll that only clears L1 — otherwise the new binding stays stale
	// in L2 for up to its TTL (default 5m). See app/adapters_authz.go.
	if req.SubjectType == SubjectTypeUser {
		payload["user_id"] = req.SubjectID
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

// grantSuperAdmin implements AddMember for the super_admin role: it flips the
// target user's is_super_admin flag via the manager (which emits the grant
// audit event and enforces tenant scope). Returns a synthetic binding whose id
// is the user id so RemoveMember can round-trip it. Only user subjects apply.
func (s *Service) grantSuperAdmin(ctx context.Context, actorID, tenantID, roleID int64, req *AddMemberRequest) (*RoleBinding, error) {
	if req.SubjectType != SubjectTypeUser {
		return nil, ErrSuperAdminUserOnly
	}
	if s.superAdmin == nil {
		return nil, ErrSuperAdminUnavailable
	}
	// Tenant-scoped existence guard (blocks cross-tenant / missing user).
	if err := s.validateRef(ctx, SubjectTypeUser, req.SubjectID, ErrSubjectNotInTenant); err != nil {
		return nil, err
	}
	if err := s.superAdmin.SetSuperAdmin(ctx, actorID, tenantID, req.SubjectID, true); err != nil {
		return nil, err
	}
	// Synthetic binding — the super_admin "membership" lives on the flag, not
	// mxid_role_binding. id == user id so the member row is removable.
	return &RoleBinding{
		ID:          req.SubjectID,
		RoleID:      roleID,
		SubjectType: SubjectTypeUser,
		SubjectID:   req.SubjectID,
		CreatedAt:   time.Now(),
	}, nil
}

// RemoveMember removes a member binding from a role. actorID is the caller,
// recorded on the super_admin revoke audit event. For the super_admin role,
// memberID is the target user id and removal revokes their is_super_admin flag.
func (s *Service) RemoveMember(ctx context.Context, actorID, roleID int64, memberID int64) error {
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get role: %w", err)
	}

	// Façade: revoking a super_admin "member" clears the user's flag (the
	// manager enforces the last-super-admin guard + emits the revoke event).
	if role.Code == SuperAdminRoleCode {
		if s.superAdmin == nil {
			return ErrSuperAdminUnavailable
		}
		return s.superAdmin.SetSuperAdmin(ctx, actorID, role.TenantID, memberID, false)
	}

	if err := s.repo.RemoveMember(ctx, memberID); err != nil {
		if dberr.IsNotFound(err) {
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

// ListMembers returns a paginated list of members for a role, enriched with
// each subject's display name so the console renders "who" instead of a raw
// snowflake id. Names are batch-resolved per subject type via the injected
// resolvers; an unresolved subject (deleted / no resolver) falls back to its
// string id so the response is never blank.
func (s *Service) ListMembers(ctx context.Context, roleID int64, params MemberListParams) ([]*MemberResponse, int64, error) {
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, 0, ErrRoleNotFound
		}
		return nil, 0, fmt.Errorf("get role: %w", err)
	}

	// Façade: the super_admin role's "members" are the is_super_admin users, not
	// role_binding rows. Render them from the flag so the list reflects reality
	// (and stays consistent with grants made via the user super-admin toggle).
	if role.Code == SuperAdminRoleCode {
		return s.listSuperAdminMembers(ctx, role.TenantID)
	}

	bindings, total, err := s.repo.ListMembers(ctx, roleID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("list members: %w", err)
	}

	return s.enrichMembers(ctx, bindings), total, nil
}

// listSuperAdminMembers renders the super_admin role's member list from the
// is_super_admin flag via the manager. Each entry's id == the user id so the
// console's remove action round-trips to a flag revoke.
func (s *Service) listSuperAdminMembers(ctx context.Context, tenantID int64) ([]*MemberResponse, int64, error) {
	if s.superAdmin == nil {
		return nil, 0, ErrSuperAdminUnavailable
	}
	infos, err := s.superAdmin.ListSuperAdmins(ctx, tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("list super admins: %w", err)
	}
	out := make([]*MemberResponse, len(infos))
	for i, in := range infos {
		name := in.Name
		if name == "" {
			name = fmt.Sprintf("%d", in.UserID)
		}
		out[i] = &MemberResponse{
			ID:               in.UserID,
			SubjectType:      SubjectTypeUser,
			SubjectID:        in.UserID,
			SubjectName:      name,
			SubjectSecondary: in.Secondary,
		}
	}
	return out, int64(len(out)), nil
}

// enrichMembers batch-resolves subject display names for a page of bindings.
// One resolver call per subject type present on the page (≤3), each over the
// distinct ids of that type — no per-row N+1. Resolver errors are non-fatal:
// the affected subjects keep their id fallback rather than failing the list.
func (s *Service) enrichMembers(ctx context.Context, bindings []*RoleBinding) []*MemberResponse {
	// Collect distinct ids per subject type.
	idsByType := map[string]map[int64]struct{}{}
	for _, b := range bindings {
		if idsByType[b.SubjectType] == nil {
			idsByType[b.SubjectType] = map[int64]struct{}{}
		}
		idsByType[b.SubjectType][b.SubjectID] = struct{}{}
	}

	resolve := func(kind string, r SubjectNameResolver) map[int64]SubjectInfo {
		set := idsByType[kind]
		if r == nil || len(set) == 0 {
			return nil
		}
		ids := make([]int64, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		info, err := r(ctx, ids)
		if err != nil {
			return nil // non-fatal: fall back to id
		}
		return info
	}

	infoByType := map[string]map[int64]SubjectInfo{
		SubjectTypeUser:  resolve(SubjectTypeUser, s.resolvers.User),
		SubjectTypeGroup: resolve(SubjectTypeGroup, s.resolvers.Group),
		SubjectTypeOrg:   resolve(SubjectTypeOrg, s.resolvers.Org),
	}

	out := make([]*MemberResponse, len(bindings))
	for i, b := range bindings {
		m := &MemberResponse{
			ID:          b.ID,
			RoleID:      b.RoleID,
			SubjectType: b.SubjectType,
			SubjectID:   b.SubjectID,
			SubjectName: fmt.Sprintf("%d", b.SubjectID), // id fallback
			ScopeType:   b.ScopeType,
			ScopeID:     b.ScopeID,
			CreatedAt:   b.CreatedAt,
		}
		if info, ok := infoByType[b.SubjectType][b.SubjectID]; ok {
			if info.Name != "" {
				m.SubjectName = info.Name
			}
			m.SubjectSecondary = info.Secondary
		}
		out[i] = m
	}
	return out
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
