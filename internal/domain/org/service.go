package org

import (
	"context"
	"errors"
	"fmt"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// RootOrgID is the ID of the seeded root organization (see migration 000013).
// The root acts as the implicit parent for all org-tree work; deleting it
// would orphan every downstream subtree, so Delete refuses to remove it.
const RootOrgID int64 = 1

// ErrRootOrgDelete is returned when a caller tries to delete the seeded root.
var ErrRootOrgDelete = errors.New("root organization cannot be deleted")

// ErrOrgNotFound is returned when an organization is absent — or, because the
// org repo is tenant-scoped by the tenantscope plugin, when the requested org
// belongs to another tenant (the plugin appends tenant_id=?, so a cross-tenant
// id resolves to gorm.ErrRecordNotFound).
var ErrOrgNotFound = errors.New("organization not found")

// ErrParentOrgNotFound is the parent-context variant of ErrOrgNotFound: the
// parent org referenced by a Create/Move request does not exist (or is
// cross-tenant). Distinct so the handler maps it to its own code/message
// ("parent organization not found") instead of the plain "not found".
var ErrParentOrgNotFound = errors.New("parent organization not found")

// ErrUserNotInTenant is returned when AddMember is asked to plant a user that
// does not exist in the caller's tenant — including a cross-tenant user id,
// which the injected validator (backed by the tenant-scoped user repo) reports
// as absent. Blocks the residual referenced-entity IDOR where an admin links a
// foreign-tenant user into their own org, granting it the org's scoped access.
var ErrUserNotInTenant = errors.New("user not found in tenant")

// EntityValidator reports whether a referenced entity id exists within the
// caller's tenant. Backed by the referent's tenant-scoped GetByID (the
// tenantscope plugin appends tenant_id=?, so a cross-tenant id resolves to
// not-found → false). Injected via SetUserValidator so the org service does
// not import the user domain.
type EntityValidator func(ctx context.Context, id int64) (bool, error)

// Service handles organization business logic.
type Service struct {
	repo          Repository
	idGen         *snowflake.Generator
	eventBus      *event.Bus
	userValidator EntityValidator
}

// SetUserValidator injects the tenant-scoped user existence check used by
// AddMember to validate the request-body user id before planting a membership.
// Wired in cmd/server/main.go once the user module exists.
func (s *Service) SetUserValidator(v EntityValidator) { s.userValidator = v }

// NewService creates a new organization service.
func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus) *Service {
	return &Service{
		repo:     repo,
		idGen:    idGen,
		eventBus: eventBus,
	}
}

// Create creates a new organization with a generated ID and computed path.
func (s *Service) Create(ctx context.Context, tenantID int64, req *CreateOrgRequest) (*Organization, error) {
	// Build path based on parent
	path := req.Code
	if req.ParentID != nil {
		parent, err := s.fetchParentOrg(ctx, *req.ParentID)
		if err != nil {
			return nil, err
		}
		path = parent.Path + "." + req.Code
	}

	org := &Organization{
		ID:        s.idGen.Generate(),
		TenantID:  tenantID,
		Name:      req.Name,
		Code:      req.Code,
		ParentID:  req.ParentID,
		Path:      path,
		SortOrder: req.SortOrder,
		Status:    1,
		Extra:     make(JSONMap),
	}

	if err := s.repo.Create(ctx, org); err != nil {
		return nil, fmt.Errorf("create organization: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.OrgCreated,
		Payload: org,
	})

	return org, nil
}

// GetByID retrieves an organization by ID, surfacing a missing/cross-tenant id
// as ErrOrgNotFound so the handler maps it to a 404 (not a 500).
func (s *Service) GetByID(ctx context.Context, id int64) (*Organization, error) {
	return s.fetchOrg(ctx, id)
}

// fetchParentOrg is the parent-context variant of fetchOrg: a missing parent
// surfaces as ErrParentOrgNotFound so Create/Move report it distinctly.
func (s *Service) fetchParentOrg(ctx context.Context, parentID int64) (*Organization, error) {
	org, err := s.fetchOrg(ctx, parentID)
	if errors.Is(err, ErrOrgNotFound) {
		return nil, ErrParentOrgNotFound
	}
	return org, err
}

// fetchOrg fetches an org via the tenant-scoped repo. A cross-tenant orgID
// resolves to ErrRecordNotFound, surfaced as ErrOrgNotFound so handlers can
// errors.Is-discriminate it into a 404 instead of falling through to 500.
func (s *Service) fetchOrg(ctx context.Context, orgID int64) (*Organization, error) {
	org, err := s.repo.GetByID(ctx, orgID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("get organization: %w", err)
	}
	return org, nil
}

// requireOrg fetches the parent org via the tenant-scoped repo. A cross-tenant
// orgID resolves to ErrRecordNotFound, surfaced as ErrOrgNotFound. This is the
// parent-ownership guard the tenant-less child table mxid_user_org (org_id)
// relies on, since the column plugin cannot filter it.
func (s *Service) requireOrg(ctx context.Context, orgID int64) error {
	_, err := s.fetchOrg(ctx, orgID)
	return err
}

// requireUserInTenant validates a request-body user id against the caller's
// tenant via the injected tenant-scoped validator. A cross-tenant id resolves
// to false → ErrUserNotInTenant. Fails closed: if no validator was wired the
// referenced-entity guard cannot be skipped silently.
func (s *Service) requireUserInTenant(ctx context.Context, userID int64) error {
	if s.userValidator == nil {
		return fmt.Errorf("org: user validator not configured")
	}
	ok, err := s.userValidator(ctx, userID)
	if err != nil {
		return fmt.Errorf("validate user: %w", err)
	}
	if !ok {
		return ErrUserNotInTenant
	}
	return nil
}

// Update updates an existing organization.
func (s *Service) Update(ctx context.Context, id int64, req *UpdateOrgRequest) (*Organization, error) {
	org, err := s.fetchOrg(ctx, id)
	if err != nil {
		return nil, err
	}

	org.Name = req.Name
	org.SortOrder = req.SortOrder
	org.Status = req.Status

	if err := s.repo.Update(ctx, org); err != nil {
		return nil, fmt.Errorf("update organization: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.OrgUpdated,
		Payload: org,
	})

	return org, nil
}

// Delete soft-deletes an organization. Refuses to remove the seeded root.
func (s *Service) Delete(ctx context.Context, id int64) error {
	if id == RootOrgID {
		return ErrRootOrgDelete
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.OrgDeleted,
		Payload: map[string]int64{"id": id},
	})

	return nil
}

// GetTree retrieves the full organization tree for a tenant.
func (s *Service) GetTree(ctx context.Context, tenantID int64) ([]*OrgResponse, error) {
	orgs, err := s.repo.GetTree(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get organization tree: %w", err)
	}

	return buildTree(orgs), nil
}

// Move moves an organization to a new parent, recalculating paths.
func (s *Service) Move(ctx context.Context, id int64, req *MoveOrgRequest) error {
	org, err := s.fetchOrg(ctx, id)
	if err != nil {
		return err
	}

	// Build new path
	newPath := org.Code
	if req.ParentID != nil {
		parent, err := s.fetchParentOrg(ctx, *req.ParentID)
		if err != nil {
			return err
		}
		newPath = parent.Path + "." + org.Code
	}

	if err := s.repo.Move(ctx, id, req.ParentID, newPath); err != nil {
		return fmt.Errorf("move organization: %w", err)
	}

	return nil
}

// AddMember adds a user to an organization.
func (s *Service) AddMember(ctx context.Context, orgID int64, req *AddMemberRequest) error {
	// Tenant-ownership guard on the parent org before planting a membership.
	// fetchOrg (not requireOrg) so we can read tenant_id for the event payload.
	org, err := s.fetchOrg(ctx, orgID)
	if err != nil {
		return err
	}
	// Referenced-entity guard: the user id comes from the request body. Reject
	// a user that is not in the caller's tenant (a cross-tenant id resolves to
	// not-found via the tenant-scoped validator) so a foreign user cannot be
	// planted into this org.
	if err := s.requireUserInTenant(ctx, req.UserID); err != nil {
		return err
	}
	rel := &UserOrg{
		ID:        s.idGen.Generate(),
		UserID:    req.UserID,
		OrgID:     orgID,
		IsPrimary: req.IsPrimary,
	}

	if err := s.repo.AddMember(ctx, rel); err != nil {
		return fmt.Errorf("add member: %w", err)
	}

	s.publishMemberChange(ctx, event.OrgMemberAdded, org.TenantID, req.UserID, orgID)
	return nil
}

// RemoveMember removes a user from an organization.
func (s *Service) RemoveMember(ctx context.Context, userID, orgID int64) error {
	// Tenant-ownership guard on the parent org before the delete.
	org, err := s.fetchOrg(ctx, orgID)
	if err != nil {
		return err
	}
	if err := s.repo.RemoveMember(ctx, userID, orgID); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	s.publishMemberChange(ctx, event.OrgMemberRemoved, org.TenantID, userID, orgID)
	return nil
}

// publishMemberChange emits an org membership event so downstream subscribers
// (dynamic user-group re-sync) can react. Carries tenant_id explicitly so an
// async handler need not rely on the request-scoped tenant context.
func (s *Service) publishMemberChange(ctx context.Context, eventType string, tenantID, userID, orgID int64) {
	s.eventBus.Publish(ctx, event.Event{
		Type: eventType,
		Payload: map[string]any{
			"tenant_id": tenantID,
			"user_id":   userID,
			"org_id":    orgID,
		},
	})
}

// IsAncestorOrSelf delegates to the repo's ltree-based check. Used by the
// authz scope engine to decide whether a binding's org scope covers a
// target org.
func (s *Service) IsAncestorOrSelf(ctx context.Context, ancestor, descendant int64) (bool, error) {
	return s.repo.IsAncestorOrSelf(ctx, ancestor, descendant)
}

// AncestorIDsForUser returns every org_id the user belongs to plus every
// ancestor in the ltree path. The permission resolver uses this to climb
// org-inherited role bindings (a binding on "root.eng" applies to every
// descendant org member).
func (s *Service) AncestorIDsForUser(ctx context.Context, tenantID, userID int64) ([]int64, error) {
	ids, err := s.repo.AncestorIDsForUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if ids == nil {
		ids = []int64{}
	}
	return ids, nil
}

// GetMembers returns paginated user IDs for an organization.
//
// Empty result returns an empty (non-nil) slice so JSON encoders emit `[]`,
// not `null`.
func (s *Service) GetMembers(ctx context.Context, orgID int64, page, pageSize int) ([]int64, int64, error) {
	if err := s.requireOrg(ctx, orgID); err != nil {
		return nil, 0, err
	}
	ids, total, err := s.repo.GetMembers(ctx, orgID, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	if ids == nil {
		ids = []int64{}
	}
	return ids, total, nil
}

// GetUserOrgs returns the orgs a user belongs to, enriched for display on the
// user detail page. Tenant-scoped via the repo join. Returns an empty (non-nil)
// slice so the JSON response is `[]`, not `null`.
func (s *Service) GetUserOrgs(ctx context.Context, tenantID, userID int64) ([]*UserOrgInfo, error) {
	infos, err := s.repo.GetUserOrgs(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if infos == nil {
		infos = []*UserOrgInfo{}
	}
	return infos, nil
}

// buildTree converts a flat list of organizations (ordered by path) into a tree.
// Returns an empty (non-nil) slice when there are no organizations so the JSON
// response is `[]` instead of `null` — frontends iterate the result directly
// without nil-guarding.
func buildTree(orgs []*Organization) []*OrgResponse {
	responseMap := make(map[int64]*OrgResponse, len(orgs))
	roots := make([]*OrgResponse, 0, len(orgs))

	// First pass: convert all to responses
	for _, org := range orgs {
		resp := ToOrgResponse(org)
		resp.Children = make([]*OrgResponse, 0)
		responseMap[org.ID] = resp
	}

	// Second pass: build tree
	for _, org := range orgs {
		resp := responseMap[org.ID]
		if org.ParentID == nil {
			roots = append(roots, resp)
		} else {
			parent, ok := responseMap[*org.ParentID]
			if ok {
				parent.Children = append(parent.Children, resp)
			} else {
				// Parent not found (possibly deleted), treat as root
				roots = append(roots, resp)
			}
		}
	}

	return roots
}
