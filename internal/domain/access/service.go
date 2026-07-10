package access

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// ErrSelfApproval is returned by Approve when the approver is the same identity
// as the requester. Separation of duties (SoD): a person approving their own
// privilege elevation defeats the approval gate and forges a "compliant" audit
// trail, so it is refused unconditionally regardless of eligibility config. The
// sanctioned "no second person" paths are explicit auto-approval (ApproverAuto,
// which calls Approve with approverID=0/system) or a purpose-built break-glass
// flow — never a silent self-approval on the normal path. Handlers should map
// this to 403 Forbidden.
var ErrSelfApproval = errors.New("access: approver must differ from requester (self-approval is not allowed)")

// ErrApproverNotEligible is returned by Approve when the approver is neither a
// super-admin (break-glass) nor a member of the eligibility's designated
// approver_subject (role / group / user). Without this the per-eligibility
// approver designation is decorative — route-level authz + SoD would let ANY
// holder of access.request.approve approve ANY request, defeating the intent of
// scoping approval authority per eligibility. Handlers should map it to 403.
var ErrApproverNotEligible = errors.New("access: approver is not authorized to approve this eligibility")

// ErrRequestNotPending is returned by ApproveAndGrant when the guarded UPDATE
// (WHERE status='pending') matches zero rows — the request was already decided
// by a concurrent approver or a double-submit. Returning it rolls back the
// binding INSERT in the same transaction; without the RowsAffected check the
// binding would commit as an orphan grant that never expires.
var ErrRequestNotPending = errors.New("access: request is no longer pending")

// SuperAdminChecker reports whether a user holds the global super-admin flag.
// Super-admins get a break-glass exemption from the per-eligibility approver
// scoping (they can already approve anything via the wildcard authz policy;
// this keeps the service-level guard consistent with that). Optional — a nil
// checker means no exemption (strict scoping), which is the safe default for
// tests.
type SuperAdminChecker func(ctx context.Context, userID int64) bool

// CacheInvalidator drops the authz cache entry for a (tenant, user) pair so
// the newly-granted or revoked role takes effect immediately without re-login.
// Implementations must be safe for concurrent use. The error return must be
// treated as best-effort by callers — a cache-bust failure must not abort the
// business operation.
type CacheInvalidator interface {
	Invalidate(ctx context.Context, tenantID, userID int64) error
}

// EventPublisher is a subset of *event.Bus used by the service.  A nil
// *event.Bus already satisfies this via the nil-safe Publish method, and the
// test's fakePublisher satisfies it too.
type EventPublisher interface {
	Publish(ctx context.Context, evt event.Event)
}

// SubjectMatcher resolves group / org / role membership for eligibility checks.
type SubjectMatcher interface {
	UserInGroup(ctx context.Context, tenantID, userID, groupID int64) bool
	UserInOrg(ctx context.Context, tenantID, userID, orgID int64) bool
	UserHasRole(ctx context.Context, tenantID, userID, roleID int64) bool
}

// DownstreamTerminator forces logout of a user's session on ONE downstream app
// (the app whose elevated role just ended), so the elevated role can't outlive
// the grant in the app's own session. Implemented per-protocol in the
// jit-downstream-logout plan. AppID is nil for console-target grants (nothing
// downstream to terminate).
type DownstreamTerminator interface {
	TerminateAppSession(ctx context.Context, tenantID, userID, appID int64)
}

type noopTerminator struct{}

func (noopTerminator) TerminateAppSession(context.Context, int64, int64, int64) {}

// NoopTerminator returns a DownstreamTerminator that does nothing. Use it
// until the jit-downstream-logout plan lands a real implementation.
func NoopTerminator() DownstreamTerminator { return noopTerminator{} }

// Service orchestrates the JIT access lifecycle: eligibility management,
// request creation, approval (with immediate cache invalidation so the role
// goes live with no re-login), rejection, cancellation, revocation, and
// expiry.
type Service struct {
	repo       Repository
	idGen      *snowflake.Generator
	busAdp     EventPublisher
	cache      CacheInvalidator
	matcher    SubjectMatcher
	terminator DownstreamTerminator
	superAdmin SuperAdminChecker
	logger     *zap.Logger
}

// SetSuperAdminChecker wires the break-glass super-admin exemption used by the
// per-eligibility approver check. Best-effort: nil leaves strict scoping (only
// the designated approver_subject may approve).
func (s *Service) SetSuperAdminChecker(fn SuperAdminChecker) { s.superAdmin = fn }

// NewService constructs a Service. bus may be nil (events are silently skipped
// when there are no subscribers; *event.Bus.Publish is nil-safe).
// terminator may be nil (defaults to noopTerminator).
func NewService(repo Repository, idGen *snowflake.Generator, bus EventPublisher, cache CacheInvalidator, matcher SubjectMatcher, terminator DownstreamTerminator) *Service {
	if terminator == nil {
		terminator = noopTerminator{}
	}
	return &Service{
		repo:       repo,
		idGen:      idGen,
		busAdp:     bus,
		cache:      cache,
		matcher:    matcher,
		terminator: terminator,
	}
}

// NewServiceWithLogger is the production constructor used by app/run.go.
// terminator may be nil (defaults to noopTerminator).
func NewServiceWithLogger(repo Repository, idGen *snowflake.Generator, bus EventPublisher, cache CacheInvalidator, matcher SubjectMatcher, terminator DownstreamTerminator, logger *zap.Logger) *Service {
	if terminator == nil {
		terminator = noopTerminator{}
	}
	return &Service{
		repo:       repo,
		idGen:      idGen,
		busAdp:     bus,
		cache:      cache,
		matcher:    matcher,
		terminator: terminator,
		logger:     logger,
	}
}

// ─── Eligibility ──────────────────────────────────────────────────────────────

// maxEligibilityTTL is the 7-day hard ceiling (seconds) on any eligibility's
// max_duration_seconds, enforced by both CreateEligibility and
// UpdateEligibility.
const maxEligibilityTTL = 604800

// validateEligibilityRequest applies the same validation to both create and
// update: target_kind/app_id consistency, a non-empty allowed_durations set,
// max_duration_seconds within (0, 7d], and every allowed duration within
// (0, max_duration_seconds].
func validateEligibilityRequest(req CreateEligibilityRequest) error {
	if req.TargetKind != TargetConsole && req.TargetKind != TargetApp {
		return fmt.Errorf("access: invalid target_kind %q", req.TargetKind)
	}
	if req.TargetKind == TargetApp && req.AppID == nil {
		return fmt.Errorf("access: app_id required for app target")
	}
	if len(req.AllowedDurations) == 0 {
		return fmt.Errorf("access: allowed_durations must not be empty")
	}
	if req.MaxDurationSeconds <= 0 || req.MaxDurationSeconds > maxEligibilityTTL {
		return fmt.Errorf("access: max_duration_seconds must be in (0, %d]", maxEligibilityTTL)
	}
	for _, d := range req.AllowedDurations {
		if d <= 0 || d > req.MaxDurationSeconds {
			return fmt.Errorf("access: each allowed duration must be in (0, max_duration_seconds=%d]", req.MaxDurationSeconds)
		}
	}
	return nil
}

// CreateEligibility validates and persists a new access eligibility rule.
func (s *Service) CreateEligibility(ctx context.Context, tenantID int64, createdBy *int64, req CreateEligibilityRequest) (*Eligibility, error) {
	if err := validateEligibilityRequest(req); err != nil {
		return nil, err
	}

	e := &Eligibility{
		ID:                   s.idGen.Generate(),
		TenantID:             tenantID,
		TargetKind:           req.TargetKind,
		RoleID:               req.RoleID,
		ScopeType:            req.ScopeType,
		ScopeID:              req.ScopeID,
		AppID:                req.AppID,
		RequesterSubjectType: req.RequesterSubjectType,
		RequesterSubjectID:   req.RequesterSubjectID,
		AllowedDurations:     IntSlice(req.AllowedDurations),
		MaxDurationSeconds:   req.MaxDurationSeconds,
		ApproverSubjectType:  orDefault(req.ApproverSubjectType, ApproverRole),
		ApproverSubjectID:    req.ApproverSubjectID,
		RequireJustification: boolOrDefault(req.RequireJustification, true),
		RequireStepUp:        boolOrDefault(req.RequireStepUp, true),
		Status:               1,
		CreatedBy:            createdBy,
	}
	if err := s.repo.CreateEligibility(ctx, e); err != nil {
		return nil, err
	}
	s.publishEligibility(ctx, EventEligibilityCreated, e)
	return e, nil
}

// UpdateEligibility re-validates req exactly like CreateEligibility, then
// overwrites the editable fields of the existing eligibility identified by
// (id, tenantID). TenantID, CreatedBy, CreatedAt, and Status are preserved
// from the existing row — this endpoint edits the rule's shape, not its
// enable/disable state or ownership. RequireJustification/RequireStepUp fall
// back to the CURRENT value (not "true") when omitted from the request, so a
// partial edit payload can't silently flip either flag back on.
func (s *Service) UpdateEligibility(ctx context.Context, tenantID, id int64, req CreateEligibilityRequest) (*Eligibility, error) {
	if err := validateEligibilityRequest(req); err != nil {
		return nil, err
	}

	existing, err := s.repo.GetEligibility(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}

	existing.TargetKind = req.TargetKind
	existing.RoleID = req.RoleID
	existing.ScopeType = req.ScopeType
	existing.ScopeID = req.ScopeID
	existing.AppID = req.AppID
	existing.RequesterSubjectType = req.RequesterSubjectType
	existing.RequesterSubjectID = req.RequesterSubjectID
	existing.AllowedDurations = IntSlice(req.AllowedDurations)
	existing.MaxDurationSeconds = req.MaxDurationSeconds
	existing.ApproverSubjectType = orDefault(req.ApproverSubjectType, ApproverRole)
	existing.ApproverSubjectID = req.ApproverSubjectID
	existing.RequireJustification = boolOrDefault(req.RequireJustification, existing.RequireJustification)
	existing.RequireStepUp = boolOrDefault(req.RequireStepUp, existing.RequireStepUp)

	if err := s.repo.UpdateEligibility(ctx, existing); err != nil {
		return nil, err
	}
	s.publishEligibility(ctx, EventEligibilityUpdated, existing)
	return existing, nil
}

// DeleteEligibility loads the rule first (so the audit event can carry its
// shape), removes it, then publishes a typed delete event. Fetching before the
// delete is deliberate: a delete-then-nothing would leave the audit trail
// unable to say WHICH role/target the removed rule elevated.
func (s *Service) DeleteEligibility(ctx context.Context, id, tenantID int64) error {
	existing, err := s.repo.GetEligibility(ctx, id, tenantID)
	if err != nil {
		return err
	}
	if err := s.repo.DeleteEligibility(ctx, id, tenantID); err != nil {
		return err
	}
	s.publishEligibility(ctx, EventEligibilityDeleted, existing)
	return nil
}

// ListEligibilityForRequester returns enabled eligibilities that the given
// user may request (subject-type filtering via the SubjectMatcher).
func (s *Service) ListEligibilityForRequester(ctx context.Context, tenantID, userID int64) ([]*Eligibility, error) {
	all, err := s.repo.ListEligibility(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]*Eligibility, 0, len(all))
	for _, e := range all {
		if e.Status != 1 {
			continue
		}
		if s.requesterEligible(ctx, tenantID, userID, e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// requesterEligible checks whether userID satisfies the eligibility's
// requester subject constraint.
func (s *Service) requesterEligible(ctx context.Context, tenantID, userID int64, e *Eligibility) bool {
	switch e.RequesterSubjectType {
	case "any":
		return true
	case "user":
		return e.RequesterSubjectID == userID
	case "group":
		return s.matcher.UserInGroup(ctx, tenantID, userID, e.RequesterSubjectID)
	case "org":
		return s.matcher.UserInOrg(ctx, tenantID, userID, e.RequesterSubjectID)
	default:
		return false
	}
}

// approverAllowed reports whether approverID may approve requests against e.
// Super-admins are exempt (break-glass). Otherwise the approver must satisfy the
// eligibility's approver_subject: hold the role, be in the group, or be the
// named user. "auto" eligibilities have no human approver gate (they are
// policy-approved; the auto path calls Approve with approverID=0), so they pass.
func (s *Service) approverAllowed(ctx context.Context, tenantID, approverID int64, e *Eligibility) bool {
	if s.superAdmin != nil && s.superAdmin(ctx, approverID) {
		return true
	}
	switch e.ApproverSubjectType {
	case ApproverAuto:
		return true
	case ApproverUser:
		return e.ApproverSubjectID == approverID
	case ApproverRole:
		return s.matcher.UserHasRole(ctx, tenantID, approverID, e.ApproverSubjectID)
	case ApproverGroup:
		return s.matcher.UserInGroup(ctx, tenantID, approverID, e.ApproverSubjectID)
	default:
		return false
	}
}

// ─── Request ──────────────────────────────────────────────────────────────────

// CreateRequest validates eligibility and duration, persists a pending request,
// and auto-approves if the eligibility is configured for auto-approval.
func (s *Service) CreateRequest(ctx context.Context, tenantID, requesterID int64, in CreateAccessRequest) (*Request, error) {
	elig, err := s.repo.GetEligibility(ctx, in.EligibilityID, tenantID)
	if err != nil {
		return nil, err
	}
	if elig.Status != 1 {
		return nil, fmt.Errorf("access: eligibility is disabled")
	}
	if !s.requesterEligible(ctx, tenantID, requesterID, elig) {
		return nil, fmt.Errorf("access: user %d is not eligible for this rule", requesterID)
	}
	if !elig.DurationAllowed(in.RequestedSeconds) {
		return nil, fmt.Errorf("access: requested duration %ds is not in the allowed set", in.RequestedSeconds)
	}
	if elig.RequireJustification && in.Justification == "" {
		return nil, fmt.Errorf("access: justification is required for this eligibility")
	}

	secs := elig.ClampDuration(in.RequestedSeconds)
	req := &Request{
		ID:               s.idGen.Generate(),
		TenantID:         tenantID,
		RequesterID:      requesterID,
		EligibilityID:    elig.ID,
		TargetKind:       elig.TargetKind,
		RoleID:           elig.RoleID,
		ScopeType:        elig.ScopeType,
		ScopeID:          elig.ScopeID,
		AppID:            elig.AppID,
		RequestedSeconds: secs,
		Justification:    in.Justification,
		Status:           StatusPending,
	}
	if err := s.repo.CreateRequest(ctx, req); err != nil {
		return nil, err
	}
	s.publish(ctx, EventRequestCreated, req, nil)

	// Auto-approval: skip the approval queue entirely.
	if elig.ApproverSubjectType == ApproverAuto {
		return s.Approve(ctx, tenantID, req.ID, 0, "auto-approved")
	}
	return req, nil
}

// ─── Lifecycle transitions ─────────────────────────────────────────────────────

// Approve transitions a pending request to approved, atomically inserts a
// time-bound role-binding grant, invalidates the requester's authz cache so
// the role goes live immediately, and publishes audit events.
func (s *Service) Approve(ctx context.Context, tenantID, requestID, approverID int64, reason string) (*Request, error) {
	req, err := s.repo.GetRequest(ctx, requestID, tenantID)
	if err != nil {
		return nil, err
	}
	if req.Status != StatusPending {
		return nil, fmt.Errorf("access: request %d is not pending (status=%s)", requestID, req.Status)
	}

	// Separation of duties: the approver must never be the requester. This is a
	// hard, config-independent guard — it holds even if an eligibility's approver
	// set wrongly includes the requester. Auto-approval is unaffected: it calls
	// Approve with approverID=0 (system), which can never equal a real
	// requester's snowflake id.
	if approverID == req.RequesterID {
		return nil, ErrSelfApproval
	}

	// Per-eligibility approver scoping: the approver must belong to the
	// eligibility's designated approver_subject (role / group / user), unless
	// they are a super-admin (break-glass). Enforced here so the designation is
	// real governance, not just a displayed field.
	elig, err := s.repo.GetEligibility(ctx, req.EligibilityID, tenantID)
	if err != nil {
		return nil, err
	}
	if !s.approverAllowed(ctx, tenantID, approverID, elig) {
		return nil, ErrApproverNotEligible
	}

	expiresAt := time.Now().Add(time.Duration(req.RequestedSeconds) * time.Second)
	bindingID := s.idGen.Generate()

	if err := s.repo.ApproveAndGrant(ctx, req, approverID, expiresAt, bindingID); err != nil {
		return nil, err
	}

	req.Status = StatusApproved
	req.ExpiresAt = &expiresAt
	req.BindingID = &bindingID

	// Best-effort: drop cached bindings so the new role takes effect without
	// re-login. A Redis blip must not roll back a successful grant.
	if err := s.cache.Invalidate(ctx, tenantID, req.RequesterID); err != nil && s.logger != nil {
		s.logger.Warn("access: cache invalidation failed after approve",
			zap.Int64("tenant_id", tenantID),
			zap.Int64("user_id", req.RequesterID),
			zap.Error(err),
		)
	}

	s.publish(ctx, EventRequestApproved, req, nil)
	// The grant-activated detail records the approver explicitly: the actor
	// column (via audit enrich) already reflects the approver from the
	// request-scoped auditctx, but a named approver_id key keeps the detail
	// self-describing without relying on the caller cross-referencing the
	// column. requester_id (already in the base payload) is the beneficiary,
	// not the actor — the two must never collapse into one ambiguous key.
	s.publish(ctx, EventGrantActivated, req, map[string]any{"approver_id": approverID})
	return req, nil
}

// Reject transitions a pending request to rejected.
func (s *Service) Reject(ctx context.Context, tenantID, requestID, approverID int64, reason string) error {
	req, err := s.repo.GetRequest(ctx, requestID, tenantID)
	if err != nil {
		return err
	}
	if req.Status != StatusPending {
		return fmt.Errorf("access: request %d is not pending (status=%s)", requestID, req.Status)
	}
	if err := s.repo.UpdateRequestStatus(ctx, requestID, tenantID, StatusRejected, reason, &approverID); err != nil {
		return err
	}
	s.publish(ctx, EventRequestRejected, req, nil)
	return nil
}

// Cancel lets the original requester withdraw a pending request.
func (s *Service) Cancel(ctx context.Context, tenantID, requestID, requesterID int64) error {
	req, err := s.repo.GetRequest(ctx, requestID, tenantID)
	if err != nil {
		return err
	}
	if req.RequesterID != requesterID {
		return fmt.Errorf("access: request %d does not belong to user %d", requestID, requesterID)
	}
	if req.Status != StatusPending {
		return fmt.Errorf("access: only pending requests can be cancelled (status=%s)", req.Status)
	}
	if err := s.repo.UpdateRequestStatus(ctx, requestID, tenantID, StatusCancelled, "", nil); err != nil {
		return err
	}
	s.publish(ctx, EventRequestCancelled, req, nil)
	return nil
}

// Revoke terminates an active grant (admin/security action). Invalidates the
// requester's authz cache immediately and publishes a revoke event.
func (s *Service) Revoke(ctx context.Context, tenantID, requestID, actorID int64) error {
	req, err := s.repo.GetRequest(ctx, requestID, tenantID)
	if err != nil {
		return err
	}
	if req.Status != StatusApproved {
		return fmt.Errorf("access: only active (approved) grants can be revoked (status=%s)", req.Status)
	}
	if err := s.repo.EndGrant(ctx, req, StatusRevoked, BindingRevoked); err != nil {
		return err
	}

	// Best-effort cache bust: remove the (now-gone) binding from the cache.
	if err := s.cache.Invalidate(ctx, tenantID, req.RequesterID); err != nil && s.logger != nil {
		s.logger.Warn("access: cache invalidation failed after revoke",
			zap.Int64("tenant_id", tenantID),
			zap.Int64("user_id", req.RequesterID),
			zap.Error(err),
		)
	}

	s.publish(ctx, EventGrantRevoked, req, nil)
	s.terminateIfApp(ctx, req)
	return nil
}

// Expire is called by the sweeper goroutine for grants whose expires_at has
// passed. It ends the grant, invalidates the cache, and publishes an event.
func (s *Service) Expire(ctx context.Context, req *Request) error {
	if err := s.repo.EndGrant(ctx, req, StatusExpired, BindingExpired); err != nil {
		return err
	}

	// Best-effort cache bust.
	if err := s.cache.Invalidate(ctx, req.TenantID, req.RequesterID); err != nil && s.logger != nil {
		s.logger.Warn("access: cache invalidation failed after expire",
			zap.Int64("tenant_id", req.TenantID),
			zap.Int64("user_id", req.RequesterID),
			zap.Error(err),
		)
	}

	s.publish(ctx, EventGrantExpired, req, nil)
	s.terminateIfApp(ctx, req)
	return nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// terminateIfApp calls the DownstreamTerminator for app-target grants so the
// elevated role can't outlive the grant in the app's own session.
// Console-target grants have no downstream app session; this is a no-op for them.
func (s *Service) terminateIfApp(ctx context.Context, req *Request) {
	if req.TargetKind == TargetApp && req.AppID != nil {
		s.terminator.TerminateAppSession(ctx, req.TenantID, req.RequesterID, *req.AppID)
	}
}

// publish emits a domain event for the access request lifecycle. The base
// payload never carries an "actor_id" key: the audit row's actor COLUMN is
// owned exclusively by the audit subsystem's enrich() (from the request-scoped
// auditctx — the approver for an approval, an admin for a revoke, "system"
// for the sweeper's expire). "requester_id" names the SUBJECT/beneficiary
// whose access is affected — never the actor, even though it happens to be
// the same person for self-service events like create/cancel. Callers that
// need a distinct acting identity recorded in the detail (e.g. which approver
// activated a grant) pass it via extra using an explicit, unambiguous key
// such as "approver_id" — never the reused, self-contradictory "actor_id".
func (s *Service) publish(ctx context.Context, eventType string, req *Request, extra map[string]any) {
	if s.busAdp == nil {
		return
	}
	payload := map[string]any{
		"resource_type": "access_request",
		"resource_id":   req.ID,
		"tenant_id":     req.TenantID,
		"request_id":    req.ID,
		"requester_id":  req.RequesterID,
		"target_kind":   req.TargetKind,
		"role_id":       req.RoleID,
		"app_id":        req.AppID,
		"expires_at":    req.ExpiresAt,
	}
	maps.Copy(payload, extra)
	s.busAdp.Publish(ctx, event.Event{
		Type:    eventType,
		Payload: payload,
	})
}

// publishEligibility emits a domain event for an eligibility (policy-config)
// write. Like publish(), the base payload carries NO "actor_id": the admin who
// made the change is owned by the audit row's actor COLUMN via enrich() from the
// request-scoped auditctx. resource_type is "access_eligibility" so the audit
// UI can filter policy changes apart from the request lifecycle.
func (s *Service) publishEligibility(ctx context.Context, eventType string, e *Eligibility) {
	if s.busAdp == nil {
		return
	}
	payload := map[string]any{
		"resource_type": "access_eligibility",
		"resource_id":   e.ID,
		"tenant_id":     e.TenantID,
		"target_kind":   e.TargetKind,
		"role_id":       e.RoleID,
		"app_id":        e.AppID,
	}
	s.busAdp.Publish(ctx, event.Event{
		Type:    eventType,
		Payload: payload,
	})
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func boolOrDefault(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
}
