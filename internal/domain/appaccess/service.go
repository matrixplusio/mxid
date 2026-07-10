package appaccess

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// Event types — published whenever access policy mutates so the portal
// SSE channel can push refresh signals to currently-connected users.
const (
	EventAccessPolicyChanged = "app_access.changed"
)

// Referenced-entity guard errors. The parent app/app-group id arrives as an
// untrusted path param and the subject id from the request body; both must be
// proven to live in the caller's tenant before a policy row is written.
var (
	ErrParentNotInTenant  = errors.New("app or app-group not found in tenant")
	ErrSubjectNotInTenant = errors.New("subject not found in tenant")
)

// ErrInvalidPolicy marks an AddPolicy that fails field validation (parent
// exclusivity, subject_type, effect, subject_id). Bound to 400 in errcodes.go;
// response.MapError renders it while sending any unbound error (wrapped DB
// failure, missing-validator misconfig) to a logged 500 that never leaks.
var ErrInvalidPolicy = errors.New("invalid access policy")

// EntityValidator reports whether a referenced entity id exists within the
// caller's tenant. Backed by the referent's tenant-scoped GetByID (the
// tenantscope plugin appends tenant_id=?, so a cross-tenant id resolves to
// false). Injected so appaccess does not import app/user/group/org/role.
type EntityValidator func(ctx context.Context, id int64) (bool, error)

// RefValidators bundles the per-type tenant-scoped existence checks AddPolicy
// needs: the parent app / app-group and the policy subject (user/group/org/
// role). Subject "public" needs no validation.
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
	logger     *zap.Logger
}

func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus) *Service {
	return &Service{repo: repo, idGen: idGen, eventBus: eventBus}
}

// SetRefValidators injects the tenant-scoped parent/subject existence checks
// used by AddPolicy. Wired in cmd/server/main.go once the domains exist.
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
		return fmt.Errorf("appaccess: parent validator not configured")
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

// validateSubject proves the policy subject belongs to the caller's tenant.
// "public" needs no validation (SubjectID is normalized to 0 by the caller).
func (s *Service) validateSubject(ctx context.Context, subjectType string, subjectID int64) error {
	var v EntityValidator
	switch subjectType {
	case SubjectPublic:
		return nil
	case SubjectUser:
		v = s.validators.User
	case SubjectGroup:
		v = s.validators.Group
	case SubjectOrg:
		v = s.validators.Org
	case SubjectRole:
		v = s.validators.Role
	default:
		return fmt.Errorf("appaccess: unknown subject_type %q", subjectType)
	}
	if v == nil {
		return fmt.Errorf("appaccess: validator for %q not configured", subjectType)
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

// ListOwnByApp returns rules attached directly to a single app (excludes
// group-inherited rules). Console renders these in the app's own access
// tab; the inherited ones are shown separately as read-only badges.
func (s *Service) ListOwnByApp(ctx context.Context, appID, tenantID int64) ([]*Policy, error) {
	return s.repo.ListOwnByApp(ctx, appID, tenantID)
}

// ListByApp returns the EFFECTIVE policy set for an app (own + inherited
// from app groups). Used by CanAccess; also exposed if UI wants to show
// the full picture for diagnostics.
func (s *Service) ListByApp(ctx context.Context, appID, tenantID int64) ([]*Policy, error) {
	return s.repo.ListByApp(ctx, appID, tenantID)
}

// ListByAppGroup returns rules attached to an app group.
func (s *Service) ListByAppGroup(ctx context.Context, groupID, tenantID int64) ([]*Policy, error) {
	return s.repo.ListByAppGroup(ctx, groupID, tenantID)
}

// AddPolicy creates a new access rule. Exactly one of AppID / AppGroupID
// must be set. SubjectType + SubjectID uniqueness within the target +
// tenant is enforced by the underlying UNIQUE index.
type AddPolicyRequest struct {
	AppID       *int64
	AppGroupID  *int64
	TenantID    int64
	SubjectType string
	SubjectID   int64
	Effect      string
	CreatedBy   *int64
}

func (s *Service) AddPolicy(ctx context.Context, req AddPolicyRequest) (*Policy, error) {
	if (req.AppID == nil) == (req.AppGroupID == nil) {
		return nil, fmt.Errorf("%w: exactly one of app_id / app_group_id must be set", ErrInvalidPolicy)
	}
	if !validSubjectType(req.SubjectType) {
		return nil, fmt.Errorf("%w: invalid subject_type: %s", ErrInvalidPolicy, req.SubjectType)
	}
	if req.Effect == "" {
		req.Effect = EffectAllow
	}
	if !validEffect(req.Effect) {
		return nil, fmt.Errorf("%w: invalid effect: %s", ErrInvalidPolicy, req.Effect)
	}
	if req.SubjectType == SubjectPublic {
		req.SubjectID = 0 // normalize
	} else if req.SubjectID == 0 {
		return nil, fmt.Errorf("%w: subject_id required for subject_type %s", ErrInvalidPolicy, req.SubjectType)
	}
	// Referenced-entity guard. The parent app/app-group id is an untrusted path
	// param and the subject id comes from the request body; prove both live in
	// the caller's tenant (cross-tenant ids 404 via the tenant-scoped
	// validators) before writing the policy row.
	if err := s.validateParent(ctx, req.AppID, req.AppGroupID); err != nil {
		return nil, err
	}
	if err := s.validateSubject(ctx, req.SubjectType, req.SubjectID); err != nil {
		return nil, err
	}
	p := &Policy{
		ID:          s.idGen.Generate(),
		AppID:       req.AppID,
		AppGroupID:  req.AppGroupID,
		TenantID:    req.TenantID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		Effect:      req.Effect,
		CreatedBy:   req.CreatedBy,
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return nil, err
	}
	// Always publish — portal SSE refreshes /apps regardless of which side
	// (app or group) was touched; the user's effective access set might
	// change in either case.
	s.publishGroupOrApp(req.AppID, req.AppGroupID, req.TenantID)
	s.auditPublish(ctx, event.AppAccessPolicyCreated, p.TenantID, p.AppID, p.AppGroupID, map[string]any{
		"policy_id": p.ID, "subject_type": p.SubjectType, "subject_id": p.SubjectID, "effect": p.Effect,
	})
	return p, nil
}

func (s *Service) DeletePolicy(ctx context.Context, id, tenantID int64) error {
	// Load the policy before deleting so the audit row names which app/group
	// and which subject lost the rule — Delete's args carry no context.
	policy, getErr := s.repo.GetByID(ctx, id, tenantID)
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	// Publish without a specific target id — clients re-fetch the whole
	// /apps list on apps_updated, so the exact id isn't important.
	s.publishGroupOrApp(nil, nil, tenantID)
	if getErr == nil {
		s.auditPublish(ctx, event.AppAccessPolicyDeleted, tenantID, policy.AppID, policy.AppGroupID, map[string]any{
			"policy_id": policy.ID, "subject_type": policy.SubjectType, "subject_id": policy.SubjectID, "effect": policy.Effect,
		})
	}
	return nil
}

// CanAccess decides whether `userID` may launch `appID`. Returns the
// matched rule for audit logging. Walks rules once; deny short-circuits.
func (s *Service) CanAccess(ctx context.Context, userID, appID, tenantID int64) (*AccessDecision, error) {
	rows, err := s.repo.ListByApp(ctx, appID, tenantID)
	if err != nil {
		return nil, err
	}
	// Cross-tenant policies (tenant_id=0) inherit for shared apps; merge them.
	if tenantID != 0 {
		global, err := s.repo.ListByApp(ctx, appID, 0)
		if err == nil {
			rows = append(rows, global...)
		}
	}

	if len(rows) == 0 {
		return &AccessDecision{Allowed: false, Reason: "no-rule-defined"}, nil
	}

	// First pass: find any deny that matches → instant deny.
	for _, r := range rows {
		if r.Effect != EffectDeny {
			continue
		}
		matched, err := s.subjectMatches(ctx, r, userID)
		if err != nil {
			return nil, err
		}
		if matched {
			return &AccessDecision{
				Allowed:     false,
				MatchedRule: r,
				Reason:      fmt.Sprintf("deny:%s:%d", r.SubjectType, r.SubjectID),
			}, nil
		}
	}

	// Second pass: any allow match.
	for _, r := range rows {
		if r.Effect != EffectAllow {
			continue
		}
		matched, err := s.subjectMatches(ctx, r, userID)
		if err != nil {
			return nil, err
		}
		if matched {
			return &AccessDecision{
				Allowed:     true,
				MatchedRule: r,
				Reason:      fmt.Sprintf("%s:%d", r.SubjectType, r.SubjectID),
			}, nil
		}
	}

	return &AccessDecision{Allowed: false, Reason: "no-rule-matched"}, nil
}

// SubjectMatcher provides per-subject-type membership lookups. We inject
// these instead of importing every domain module here — keeps appaccess
// independent of user/group/org/role packages.
type SubjectMatcher interface {
	UserInGroup(ctx context.Context, userID, groupID int64) (bool, error)
	UserInOrg(ctx context.Context, userID, orgID int64) (bool, error)
	UserHasRole(ctx context.Context, userID, roleID int64) (bool, error)
}

// matcher is injected via SetMatcher at bootstrap. nil-safe so unit tests
// without full domain wiring can still test public/user matching.
var matcher SubjectMatcher

func SetMatcher(m SubjectMatcher) { matcher = m }

func (s *Service) subjectMatches(ctx context.Context, r *Policy, userID int64) (bool, error) {
	switch r.SubjectType {
	case SubjectPublic:
		return true, nil
	case SubjectUser:
		return r.SubjectID == userID, nil
	case SubjectGroup:
		if matcher == nil {
			return false, nil
		}
		return matcher.UserInGroup(ctx, userID, r.SubjectID)
	case SubjectOrg:
		if matcher == nil {
			return false, nil
		}
		return matcher.UserInOrg(ctx, userID, r.SubjectID)
	case SubjectRole:
		if matcher == nil {
			return false, nil
		}
		return matcher.UserHasRole(ctx, userID, r.SubjectID)
	}
	return false, nil
}

// AppsForUser is a thin pass-through used by the portal /apps handler.
func (s *Service) AppsForUser(ctx context.Context, userID, tenantID int64) ([]int64, error) {
	return s.repo.AppsForUser(ctx, userID, tenantID)
}

// publishGroupOrApp emits the policy-changed event. Either or both of
// appID / appGroupID may be nil — portal SSE clients refetch their /apps
// list on receipt regardless, so granular targeting isn't needed yet.
// Could later filter per-tenant if shared-app deployments grow.
func (s *Service) publishGroupOrApp(appID, appGroupID *int64, tenantID int64) {
	if s.eventBus == nil {
		return
	}
	payload := map[string]any{"tenant_id": tenantID}
	if appID != nil {
		payload["app_id"] = *appID
	}
	if appGroupID != nil {
		payload["app_group_id"] = *appGroupID
	}
	s.eventBus.Publish(context.Background(), event.Event{
		Type:    EventAccessPolicyChanged,
		Payload: payload,
	})
}

// auditPublish emits a security-audit domain event for an access-policy
// change. Unlike publishGroupOrApp() (an SSE cache-bust with no actor on a
// detached context), this carries the REQUEST ctx so the audit enricher can
// attribute the change to the acting admin. Resource is the parent app or
// app-group.
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

func validSubjectType(s string) bool {
	switch s {
	case SubjectPublic, SubjectUser, SubjectGroup, SubjectOrg, SubjectRole:
		return true
	}
	return false
}

func validEffect(e string) bool { return e == EffectAllow || e == EffectDeny }
