package approle

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

const EventAppRoleChanged = "app_role.changed"

// Referenced-entity guard errors. The parent app/app-group id and the subject
// id arrive from the request and must be proven to live in the caller's tenant
// before a role/binding row is written; the AppRoleID a binding attaches to
// must additionally belong to that same parent.
var (
	ErrParentNotInTenant  = errors.New("app or app-group not found in tenant")
	ErrSubjectNotInTenant = errors.New("subject not found in tenant")
	ErrAppRoleNotInParent = errors.New("app role not found under this app/app-group")
)

// Validation / lookup sentinels bound to HTTP codes in errcodes.go. Field
// validation wraps these via fmt.Errorf("%w: <detail>", ErrX) so the client
// still sees the precise reason under a stable code; response.MapError sends
// any unbound error (wrapped DB failure, missing-validator misconfig) to a
// logged 500 that never leaks its text.
var (
	// ErrInvalidRole marks a CreateRole/UpdateRole that fails field validation.
	ErrInvalidRole = errors.New("invalid app role")
	// ErrInvalidBinding marks an AddBinding that fails field validation.
	ErrInvalidBinding = errors.New("invalid app-role binding")
	// ErrRoleNotFound marks an UpdateRole against a missing app-role id
	// (translated from the repository's not-found so it 404s cleanly).
	ErrRoleNotFound = errors.New("app role not found")
)

// EntityValidator reports whether a referenced entity id exists within the
// caller's tenant. Backed by the referent's tenant-scoped GetByID (the
// tenantscope plugin appends tenant_id=?, so a cross-tenant id resolves to
// false). Injected so approle does not import app/user/group/org/role.
type EntityValidator func(ctx context.Context, id int64) (bool, error)

// RefValidators bundles the per-type tenant-scoped existence checks CreateRole
// and AddBinding need: the parent app / app-group and the binding subject
// (user/group/org/role).
type RefValidators struct {
	App      EntityValidator
	AppGroup EntityValidator
	User     EntityValidator
	Group    EntityValidator
	Org      EntityValidator
	Role     EntityValidator
}

type Service struct {
	repo       Repository
	idGen      *snowflake.Generator
	eventBus   *event.Bus
	validators RefValidators
}

func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus) *Service {
	return &Service{repo: repo, idGen: idGen, eventBus: eventBus}
}

// SetRefValidators injects the tenant-scoped parent/subject existence checks
// used by CreateRole and AddBinding. Wired in cmd/server/main.go once the
// domains exist.
func (s *Service) SetRefValidators(v RefValidators) { s.validators = v }

// validateParent proves the parent app / app-group belongs to the caller's
// tenant. Exactly one of appID / groupID is non-nil (caller already checked).
func (s *Service) validateParent(ctx context.Context, appID, groupID *int64) error {
	var (
		v  EntityValidator
		id int64
	)
	switch {
	case appID != nil:
		v, id = s.validators.App, *appID
	case groupID != nil:
		v, id = s.validators.AppGroup, *groupID
	}
	if v == nil {
		return fmt.Errorf("approle: parent validator not configured")
	}
	ok, err := v(ctx, id)
	if err != nil {
		return fmt.Errorf("validate parent: %w", err)
	}
	if !ok {
		return ErrParentNotInTenant
	}
	return nil
}

// validateAppRoleParent proves the AppRoleID a binding attaches to exists in
// the caller's tenant (repo.GetRoleByID already filters tenant_id) AND hangs
// off the same parent app/app-group the request targets. A cross-tenant or
// mismatched-parent role id resolves to ErrAppRoleNotInParent.
func (s *Service) validateAppRoleParent(ctx context.Context, appRoleID, tenantID int64, appID, groupID *int64) error {
	role, err := s.repo.GetRoleByID(ctx, appRoleID, tenantID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppRoleNotInParent
		}
		return fmt.Errorf("get app role: %w", err)
	}
	switch {
	case appID != nil:
		if role.AppID == nil || *role.AppID != *appID {
			return ErrAppRoleNotInParent
		}
	case groupID != nil:
		if role.AppGroupID == nil || *role.AppGroupID != *groupID {
			return ErrAppRoleNotInParent
		}
	}
	return nil
}

// validateSubject proves the binding subject belongs to the caller's tenant.
func (s *Service) validateSubject(ctx context.Context, subjectType string, subjectID int64) error {
	var v EntityValidator
	switch subjectType {
	case SubjectUser:
		v = s.validators.User
	case SubjectGroup:
		v = s.validators.Group
	case SubjectOrg:
		v = s.validators.Org
	case SubjectRole:
		v = s.validators.Role
	default:
		return fmt.Errorf("approle: unknown subject_type %q", subjectType)
	}
	if v == nil {
		return fmt.Errorf("approle: validator for %q not configured", subjectType)
	}
	ok, err := v(ctx, subjectID)
	if err != nil {
		return fmt.Errorf("validate subject: %w", err)
	}
	if !ok {
		return ErrSubjectNotInTenant
	}
	return nil
}

/* ──────────────── Role CRUD ──────────────── */

type CreateRoleRequest struct {
	AppID       *int64
	AppGroupID  *int64
	TenantID    int64
	Code        string
	Name        string
	Description string
	IsDefault   bool
	SortOrder   int
	CreatedBy   *int64
}

func (s *Service) CreateRole(ctx context.Context, req CreateRoleRequest) (*AppRole, error) {
	if (req.AppID == nil) == (req.AppGroupID == nil) {
		return nil, fmt.Errorf("%w: exactly one of app_id / app_group_id must be set", ErrInvalidRole)
	}
	if req.Code == "" {
		return nil, fmt.Errorf("%w: code required", ErrInvalidRole)
	}
	if req.Name == "" {
		return nil, fmt.Errorf("%w: name required", ErrInvalidRole)
	}
	// Referenced-entity guard: the parent app/app-group id is an untrusted path
	// param. Prove it lives in the caller's tenant before stamping it into the
	// new app-role (cross-tenant parent 404s via the tenant-scoped validator).
	if err := s.validateParent(ctx, req.AppID, req.AppGroupID); err != nil {
		return nil, err
	}
	r := &AppRole{
		ID:         s.idGen.Generate(),
		AppID:      req.AppID,
		AppGroupID: req.AppGroupID,
		TenantID:   req.TenantID,
		Code:       req.Code,
		Name:       req.Name,
		IsDefault:  req.IsDefault,
		SortOrder:  req.SortOrder,
		CreatedBy:  req.CreatedBy,
	}
	if req.Description != "" {
		r.Description = &req.Description
	}
	if err := s.repo.CreateRole(ctx, r); err != nil {
		return nil, err
	}
	s.publish(req.TenantID)
	s.auditPublish(ctx, event.AppRoleCreated, r.TenantID, r.AppID, r.AppGroupID, map[string]any{
		"role_id": r.ID, "code": r.Code, "name": r.Name,
	})
	return r, nil
}

type UpdateRoleRequest struct {
	ID          int64
	TenantID    int64
	Name        *string
	Description *string
	IsDefault   *bool
	SortOrder   *int
}

func (s *Service) UpdateRole(ctx context.Context, req UpdateRoleRequest) (*AppRole, error) {
	role, err := s.repo.GetRoleByID(ctx, req.ID, req.TenantID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		desc := *req.Description
		role.Description = &desc
	}
	if req.IsDefault != nil {
		role.IsDefault = *req.IsDefault
	}
	if req.SortOrder != nil {
		role.SortOrder = *req.SortOrder
	}
	if err := s.repo.UpdateRole(ctx, role); err != nil {
		return nil, err
	}
	s.publish(role.TenantID)
	s.auditPublish(ctx, event.AppRoleUpdated, role.TenantID, role.AppID, role.AppGroupID, map[string]any{
		"role_id": role.ID, "code": role.Code, "name": role.Name,
	})
	return role, nil
}

func (s *Service) DeleteRole(ctx context.Context, id, tenantID int64) error {
	// Load the role before deleting so the audit row can name which app/group
	// and which role lost a definition — DeleteRole's args alone carry no
	// parent context.
	role, getErr := s.repo.GetRoleByID(ctx, id, tenantID)
	if err := s.repo.DeleteRole(ctx, id, tenantID); err != nil {
		return err
	}
	s.publish(tenantID)
	if getErr == nil {
		s.auditPublish(ctx, event.AppRoleDeleted, tenantID, role.AppID, role.AppGroupID, map[string]any{
			"role_id": role.ID, "code": role.Code, "name": role.Name,
		})
	}
	return nil
}

func (s *Service) ListRoles(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*AppRole, error) {
	return s.repo.ListRoles(ctx, owner, ownerID, tenantID)
}

/* ──────────────── Bindings ──────────────── */

type AddBindingRequest struct {
	AppID       *int64
	AppGroupID  *int64
	TenantID    int64
	AppRoleID   int64
	SubjectType string
	SubjectID   int64
	CreatedBy   *int64
}

func (s *Service) AddBinding(ctx context.Context, req AddBindingRequest) (*Binding, error) {
	if (req.AppID == nil) == (req.AppGroupID == nil) {
		return nil, fmt.Errorf("%w: exactly one of app_id / app_group_id must be set", ErrInvalidBinding)
	}
	if !validSubject(req.SubjectType) {
		return nil, fmt.Errorf("%w: invalid subject_type: %s", ErrInvalidBinding, req.SubjectType)
	}
	if req.SubjectID == 0 {
		return nil, fmt.Errorf("%w: subject_id required", ErrInvalidBinding)
	}
	// Referenced-entity guard. (1) Parent app/app-group must live in the
	// caller's tenant. (2) The AppRoleID the binding attaches to must belong to
	// the same tenant AND hang off this same parent — otherwise a caller could
	// attach a binding to a foreign/unrelated app-role. (3) The subject must
	// live in the caller's tenant.
	if err := s.validateParent(ctx, req.AppID, req.AppGroupID); err != nil {
		return nil, err
	}
	if err := s.validateAppRoleParent(ctx, req.AppRoleID, req.TenantID, req.AppID, req.AppGroupID); err != nil {
		return nil, err
	}
	if err := s.validateSubject(ctx, req.SubjectType, req.SubjectID); err != nil {
		return nil, err
	}
	b := &Binding{
		ID:          s.idGen.Generate(),
		AppID:       req.AppID,
		AppGroupID:  req.AppGroupID,
		TenantID:    req.TenantID,
		AppRoleID:   req.AppRoleID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		CreatedBy:   req.CreatedBy,
	}
	if err := s.repo.CreateBinding(ctx, b); err != nil {
		return nil, err
	}
	s.publish(req.TenantID)
	s.auditPublish(ctx, event.AppRoleBindingCreated, b.TenantID, b.AppID, b.AppGroupID, map[string]any{
		"role_id": b.AppRoleID, "subject_type": b.SubjectType, "subject_id": b.SubjectID, "binding_id": b.ID,
	})
	return b, nil
}

func (s *Service) DeleteBinding(ctx context.Context, id, tenantID int64) error {
	// Load the binding before deleting so the audit row names the parent
	// app/group, the role and the subject that lost the grant.
	binding, getErr := s.repo.GetBindingByID(ctx, id, tenantID)
	if err := s.repo.DeleteBinding(ctx, id, tenantID); err != nil {
		return err
	}
	s.publish(tenantID)
	if getErr == nil {
		s.auditPublish(ctx, event.AppRoleBindingDeleted, tenantID, binding.AppID, binding.AppGroupID, map[string]any{
			"role_id": binding.AppRoleID, "subject_type": binding.SubjectType, "subject_id": binding.SubjectID, "binding_id": binding.ID,
		})
	}
	return nil
}

func (s *Service) ListBindings(ctx context.Context, owner Owner, ownerID, tenantID int64) ([]*Binding, error) {
	return s.repo.ListBindings(ctx, owner, ownerID, tenantID)
}

// ListBindingsBySubject — used by user-group page reverse view.
func (s *Service) ListBindingsBySubject(ctx context.Context, subjectType string, subjectID, tenantID int64) ([]*Binding, error) {
	return s.repo.ListBindingsBySubject(ctx, subjectType, subjectID, tenantID)
}

/* ──────────────── Resolve for OIDC claim ──────────────── */

func (s *Service) ResolveCodes(ctx context.Context, userID, appID, tenantID int64) ([]string, error) {
	return s.repo.ResolveCodesForUser(ctx, userID, appID, tenantID)
}

// GetRole exposes the single-row fetch for handlers that need to
// enrich responses (e.g. reverse view rendering role name+code).
func (s *Service) GetRole(ctx context.Context, id, tenantID int64) (*AppRole, error) {
	return s.repo.GetRoleByID(ctx, id, tenantID)
}

// MemberAppIDs is a pass-through used by the app-group aggregation
// handler (group → list of member app ids).
func (s *Service) MemberAppIDs(ctx context.Context, groupID int64) ([]int64, error) {
	return s.repo.MemberAppIDs(ctx, groupID)
}

func (s *Service) publish(tenantID int64) {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Publish(context.Background(), event.Event{
		Type:    EventAppRoleChanged,
		Payload: map[string]any{"tenant_id": tenantID},
	})
}

// auditPublish emits a security-audit domain event for an app-role/binding
// change. Unlike publish() (an SSE cache-bust with no actor on a detached
// context), this carries the REQUEST ctx so the audit enricher can attribute
// the change to the acting admin. Resource is the parent app or app-group.
func (s *Service) auditPublish(ctx context.Context, eventType string, tenantID int64, appID, groupID *int64, extra map[string]any) {
	if s.eventBus == nil {
		return
	}
	payload := map[string]any{"tenant_id": tenantID}
	if appID != nil {
		payload["app_id"] = *appID
	}
	if groupID != nil {
		payload["app_group_id"] = *groupID
	}
	maps.Copy(payload, extra)
	s.eventBus.Publish(ctx, event.Event{Type: eventType, Payload: payload})
}

func validSubject(s string) bool {
	switch s {
	case SubjectUser, SubjectGroup, SubjectOrg, SubjectRole:
		return true
	}
	return false
}
