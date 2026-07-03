package access

import (
	"context"
	"fmt"
	"maps"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

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
	logger     *zap.Logger
}

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

// CreateEligibility validates and persists a new access eligibility rule.
func (s *Service) CreateEligibility(ctx context.Context, tenantID int64, createdBy *int64, req CreateEligibilityRequest) (*Eligibility, error) {
	if req.TargetKind != TargetConsole && req.TargetKind != TargetApp {
		return nil, fmt.Errorf("access: invalid target_kind %q", req.TargetKind)
	}
	if req.TargetKind == TargetApp && req.AppID == nil {
		return nil, fmt.Errorf("access: app_id required for app target")
	}
	if len(req.AllowedDurations) == 0 {
		return nil, fmt.Errorf("access: allowed_durations must not be empty")
	}
	const maxTTL = 604800 // 7-day hard ceiling (seconds)
	if req.MaxDurationSeconds <= 0 || req.MaxDurationSeconds > maxTTL {
		return nil, fmt.Errorf("access: max_duration_seconds must be in (0, %d]", maxTTL)
	}
	for _, d := range req.AllowedDurations {
		if d <= 0 || d > req.MaxDurationSeconds {
			return nil, fmt.Errorf("access: each allowed duration must be in (0, max_duration_seconds=%d]", req.MaxDurationSeconds)
		}
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
	return e, nil
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
