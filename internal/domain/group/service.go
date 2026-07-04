package group

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// Service errors.
var (
	ErrGroupNotFound   = errors.New("user group not found")
	ErrGroupHasMembers = errors.New("user group still has members; remove all members or pass force=true")
	// ErrUserNotInTenant is returned when AddMember(s) is asked to add a user
	// that does not exist in the caller's tenant — including a cross-tenant id,
	// which the injected validator (tenant-scoped user repo) reports as absent.
	// Blocks the residual referenced-entity IDOR where an admin plants a
	// foreign-tenant user into their own group.
	ErrUserNotInTenant = errors.New("user not found in tenant")
)

// EntityValidator reports whether a referenced entity id exists within the
// caller's tenant. Backed by the referent's tenant-scoped GetByID (the
// tenantscope plugin appends tenant_id=?, so a cross-tenant id resolves to
// false). Injected via SetUserValidator so the group service does not import
// the user domain.
type EntityValidator func(ctx context.Context, id int64) (bool, error)

// Service handles user group business logic.
type Service struct {
	repo          Repository
	idGen         *snowflake.Generator
	eventBus      *event.Bus
	userValidator EntityValidator
}

// NewService creates a new user group service.
func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus) *Service {
	return &Service{
		repo:     repo,
		idGen:    idGen,
		eventBus: eventBus,
	}
}

// SetUserValidator injects the tenant-scoped user existence check used by
// AddMember / AddMembers to validate request-body user ids. Wired in
// cmd/server/main.go once the user module exists.
func (s *Service) SetUserValidator(v EntityValidator) { s.userValidator = v }

// requireUsersInTenant validates request-body user ids against the caller's
// tenant via the injected validator. A cross-tenant id resolves to false →
// ErrUserNotInTenant. Fails closed when no validator is wired.
func (s *Service) requireUsersInTenant(ctx context.Context, userIDs ...int64) error {
	if s.userValidator == nil {
		return fmt.Errorf("group: user validator not configured")
	}
	for _, uid := range userIDs {
		ok, err := s.userValidator(ctx, uid)
		if err != nil {
			return fmt.Errorf("validate user: %w", err)
		}
		if !ok {
			return ErrUserNotInTenant
		}
	}
	return nil
}

// Create creates a new user group with a generated ID.
func (s *Service) Create(ctx context.Context, tenantID int64, req *CreateGroupRequest) (*UserGroup, error) {
	var desc *string
	if req.Description != "" {
		desc = &req.Description
	}

	g := &UserGroup{
		ID:          s.idGen.Generate(),
		TenantID:    tenantID,
		Name:        req.Name,
		Code:        req.Code,
		Description: desc,
	}

	if err := s.repo.Create(ctx, g); err != nil {
		return nil, fmt.Errorf("create user group: %w", err)
	}

	s.publishGroup(ctx, event.GroupCreated, g)
	return g, nil
}

// publishGroup emits a group lifecycle event. Actor / IP are denormalized
// downstream from the request-scoped auditctx; the payload carries the group
// identity that the audit resource columns render.
func (s *Service) publishGroup(ctx context.Context, eventType string, g *UserGroup) {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: eventType,
		Payload: map[string]any{
			"id":        g.ID,
			"tenant_id": g.TenantID,
			"name":      g.Name,
			"code":      g.Code,
		},
	})
}

// GetByID retrieves a user group by ID, surfacing a missing/cross-tenant id as
// ErrGroupNotFound (via requireGroup) so the handler maps it to a 404 not a 500.
func (s *Service) GetByID(ctx context.Context, id int64) (*UserGroup, error) {
	return s.requireGroup(ctx, id)
}

// requireGroup fetches the parent group via the tenant-scoped repo so the
// tenantscope plugin appends tenant_id=?. A cross-tenant groupID resolves to
// ErrRecordNotFound, surfaced as ErrGroupNotFound. This is the parent-ownership
// guard the tenant-less child tables (mxid_user_group_member,
// mxid_user_group_rule) rely on, since the column plugin cannot filter them.
func (s *Service) requireGroup(ctx context.Context, groupID int64) (*UserGroup, error) {
	g, err := s.repo.GetByID(ctx, groupID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("get group: %w", err)
	}
	return g, nil
}

// Update updates an existing user group.
func (s *Service) Update(ctx context.Context, id int64, req *UpdateGroupRequest) (*UserGroup, error) {
	g, err := s.requireGroup(ctx, id)
	if err != nil {
		return nil, err
	}

	g.Name = req.Name
	if req.Description != "" {
		g.Description = &req.Description
	} else {
		g.Description = nil
	}

	if err := s.repo.Update(ctx, g); err != nil {
		return nil, fmt.Errorf("update user group: %w", err)
	}

	s.publishGroup(ctx, event.GroupUpdated, g)
	return g, nil
}

// Delete soft-deletes a user group.
//
// When force is false, refuses to delete a group that still has members so
// memberships aren't silently orphaned. Pass force=true to cascade — the
// FK on mxid_user_group_member has ON DELETE CASCADE so the rows clean up
// automatically; the flag is purely a safety gate at the API boundary.
func (s *Service) Delete(ctx context.Context, id int64, force bool) error {
	// Load before delete so the audit event carries the group's name/tenant.
	// Already gone → idempotent success (preserves the pre-existing behavior
	// where repo.Delete on a missing row was a no-op).
	g, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get group for delete: %w", err)
	}
	count, err := s.repo.CountMembers(ctx, id)
	if err != nil {
		return fmt.Errorf("count members before delete: %w", err)
	}
	if count > 0 && !force {
		return ErrGroupHasMembers
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete user group: %w", err)
	}
	s.publishGroup(ctx, event.GroupDeleted, g)
	return nil
}

// List returns paginated user groups for a tenant, optionally filtered by keyword.
func (s *Service) List(ctx context.Context, tenantID int64, keyword string, page, pageSize int) ([]*GroupResponse, int64, error) {
	groups, total, err := s.repo.List(ctx, tenantID, keyword, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list user groups: %w", err)
	}

	responses, err := s.buildGroupResponsesWithCounts(ctx, groups)
	if err != nil {
		return nil, 0, err
	}
	return responses, total, nil
}

// ListByUserID returns every group the given user belongs to.
func (s *Service) ListByUserID(ctx context.Context, tenantID, userID int64) ([]*GroupResponse, error) {
	groups, err := s.repo.ListByUserID(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("list groups by user: %w", err)
	}
	// Member counts resolved in one batched query (informational on this listing).
	return s.buildGroupResponsesWithCounts(ctx, groups)
}

// buildGroupResponsesWithCounts maps groups to responses, resolving all member
// counts in ONE grouped query instead of an N+1 CountMembers-per-group loop.
func (s *Service) buildGroupResponsesWithCounts(ctx context.Context, groups []*UserGroup) ([]*GroupResponse, error) {
	ids := make([]int64, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	counts, err := s.repo.CountMembersByGroupIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("count group members: %w", err)
	}
	responses := make([]*GroupResponse, len(groups))
	for i, g := range groups {
		responses[i] = ToGroupResponse(g, counts[g.ID])
	}
	return responses, nil
}

// AddMember adds a user to a group. Refuses if the group is dynamic — those
// memberships are owned by the sync engine.
func (s *Service) AddMember(ctx context.Context, groupID int64, req *AddMemberRequest) error {
	g, err := s.requireGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if g.Type == TypeDynamic {
		return ErrGroupIsDynamic
	}
	// Referenced-entity guard: reject a request-body user id that is not in the
	// caller's tenant (cross-tenant id resolves to not-found via the validator).
	if err := s.requireUsersInTenant(ctx, req.UserID); err != nil {
		return err
	}
	m := &UserGroupMember{
		ID:      s.idGen.Generate(),
		GroupID: groupID,
		UserID:  req.UserID,
	}
	if err := s.repo.AddMember(ctx, m); err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	s.publishMember(ctx, event.GroupMemberAdded, g.TenantID, groupID, req.UserID)
	return nil
}

// publishMember emits a group-member event with the standard payload
// shape (tenant_id, group_id, user_id). Subscribers — chief among them
// the authz cache — drop the affected user's binding entry.
func (s *Service) publishMember(ctx context.Context, eventType string, tenantID, groupID, userID int64) {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Publish(ctx, event.Event{
		Type: eventType,
		Payload: map[string]any{
			"tenant_id": tenantID,
			"group_id":  groupID,
			"user_id":   userID,
		},
	})
}

// AddMembers adds multiple users to a group. Users already in the group are
// reported via the skipped slice in the returned response — never as errors.
func (s *Service) AddMembers(ctx context.Context, groupID int64, userIDs []int64) (*BatchMembersResponse, error) {
	// Tenant-ownership guard BEFORE any membership write — mirrors the singular
	// AddMember, which also rejects dynamic groups.
	g, err := s.requireGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if g.Type == TypeDynamic {
		return nil, ErrGroupIsDynamic
	}
	// Referenced-entity guard: every request-body user id must belong to the
	// caller's tenant. Reject the whole batch if any id is cross-tenant /
	// missing (resolved via the tenant-scoped validator) before any write.
	if err := s.requireUsersInTenant(ctx, userIDs...); err != nil {
		return nil, err
	}
	members := make([]*UserGroupMember, 0, len(userIDs))
	for _, uid := range userIDs {
		members = append(members, &UserGroupMember{
			ID:      s.idGen.Generate(),
			GroupID: groupID,
			UserID:  uid,
		})
	}
	skipped, err := s.repo.AddMembers(ctx, groupID, members)
	if err != nil {
		return nil, fmt.Errorf("batch add members: %w", err)
	}
	if skipped == nil {
		skipped = []int64{}
	}
	skippedSet := make(map[int64]struct{}, len(skipped))
	for _, uid := range skipped {
		skippedSet[uid] = struct{}{}
	}
	for _, uid := range userIDs {
		if _, skip := skippedSet[uid]; skip {
			continue
		}
		s.publishMember(ctx, event.GroupMemberAdded, g.TenantID, groupID, uid)
	}
	return &BatchMembersResponse{
		Affected: len(userIDs) - len(skipped),
		Skipped:  int64sToStrings(skipped),
	}, nil
}

// RemoveMember removes a user from a group. Refuses on dynamic groups —
// adjust the rule instead.
func (s *Service) RemoveMember(ctx context.Context, groupID, userID int64) error {
	g, err := s.requireGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if g.Type == TypeDynamic {
		return ErrGroupIsDynamic
	}
	if err := s.repo.RemoveMember(ctx, groupID, userID); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	s.publishMember(ctx, event.GroupMemberRemoved, g.TenantID, groupID, userID)
	return nil
}

// RemoveMembers removes multiple users from a group. UserIDs that were not
// members are reported via the skipped slice.
func (s *Service) RemoveMembers(ctx context.Context, groupID int64, userIDs []int64) (*BatchMembersResponse, error) {
	// Tenant-ownership guard BEFORE the delete.
	g, err := s.requireGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	skipped, err := s.repo.RemoveMembers(ctx, groupID, userIDs)
	if err != nil {
		return nil, fmt.Errorf("batch remove members: %w", err)
	}
	skippedSet := make(map[int64]struct{}, len(skipped))
	for _, uid := range skipped {
		skippedSet[uid] = struct{}{}
	}
	for _, uid := range userIDs {
		if _, skip := skippedSet[uid]; skip {
			continue
		}
		s.publishMember(ctx, event.GroupMemberRemoved, g.TenantID, groupID, uid)
	}
	if skipped == nil {
		skipped = []int64{}
	}
	return &BatchMembersResponse{
		Affected: len(userIDs) - len(skipped),
		Skipped:  int64sToStrings(skipped),
	}, nil
}

// int64sToStrings converts a slice of snowflake IDs to strings for JSON
// transport — JS loses precision above Number.MAX_SAFE_INTEGER.
func int64sToStrings(ids []int64) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.FormatInt(id, 10)
	}
	return out
}

// GetMembers returns enriched paginated members for a group.
//
// Empty result returns an empty (non-nil) slice so JSON encoders emit `[]`,
// not `null`.
func (s *Service) GetMembers(ctx context.Context, groupID int64, page, pageSize int) ([]*MemberInfo, int64, error) {
	if _, err := s.requireGroup(ctx, groupID); err != nil {
		return nil, 0, err
	}
	members, total, err := s.repo.GetMembers(ctx, groupID, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	if members == nil {
		members = []*MemberInfo{}
	}
	return members, total, nil
}

// CountMembers returns the member count for a group.
func (s *Service) CountMembers(ctx context.Context, groupID int64) (int64, error) {
	return s.repo.CountMembers(ctx, groupID)
}
