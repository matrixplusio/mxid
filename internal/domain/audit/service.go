package audit

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/geoip"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
)

// Service provides business logic for audit logging.
type Service struct {
	repo     Repository
	idGen    *snowflake.Generator
	eventBus *event.Bus
	logger   *zap.Logger
	tenantID int64
	geo      geoip.Resolver
	// nameResolver denormalizes an actor's username at write time for events
	// whose publisher only carries a user_id (e.g. app.launched fired from the
	// portal middleware context, which holds no username). nil falls back to a
	// blank ActorName — the actor_id is still recorded, so the row stays
	// attributable. Set via SetUserNameResolver.
	nameResolver func(ctx context.Context, userID int64) string
}

// NewService creates a new audit service.
func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus, logger *zap.Logger, tenantID int64) *Service {
	return &Service{
		repo:     repo,
		idGen:    idGen,
		eventBus: eventBus,
		logger:   logger,
		tenantID: tenantID,
		geo:      geoip.NoopResolver{},
	}
}

// SetUserNameResolver wires a user_id → username lookup used to denormalize
// ActorName for events whose payload omits the username. Best-effort: a nil
// resolver or empty result leaves ActorName blank (actor_id still recorded).
func (s *Service) SetUserNameResolver(fn func(ctx context.Context, userID int64) string) {
	s.nameResolver = fn
}

// SetGeoResolver wires the GeoIP backend. Pass geoip.NoopResolver{} to
// disable lookups (the default). Wrap with PrivateAwareResolver to skip
// RFC1918 / loopback addresses.
func (s *Service) SetGeoResolver(r geoip.Resolver) {
	if r == nil {
		s.geo = geoip.NoopResolver{}
		return
	}
	s.geo = r
}

// fillGeo resolves the IP and writes Country / City pointers onto the
// passed log. Errors are logged at debug and swallowed — geo enrichment
// is best-effort, never blocking the audit write.
func (s *Service) fillGeo(log *AuditLog, ip string) {
	if ip == "" || s.geo == nil {
		return
	}
	loc, err := s.geo.Lookup(ip)
	if err != nil {
		s.logger.Debug("geoip lookup", zap.String("ip", ip), zap.Error(err))
		return
	}
	if loc.Country != "" {
		c := loc.Country
		log.GeoCountry = &c
	}
	if loc.City != "" {
		c := loc.City
		log.GeoCity = &c
	}
}

// SubscribeEvents subscribes to domain events and creates audit logs automatically.
func (s *Service) SubscribeEvents() {
	// Login events
	s.eventBus.Subscribe(event.LoginSuccess, s.handleLoginSuccess)
	s.eventBus.Subscribe(event.LoginFailed, s.handleLoginFailed)
	s.eventBus.Subscribe(event.LoginRisk, s.handleLoginRisk)
	s.eventBus.Subscribe(event.Logout, s.handleLogout)

	// User events
	s.eventBus.Subscribe(event.UserCreated, s.handleUserEvent(event.UserCreated, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserUpdated, s.handleUserEvent(event.UserUpdated, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserDeleted, s.handleUserEvent(event.UserDeleted, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserLocked, s.handleUserEvent(event.UserLocked, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserUnlocked, s.handleUserEvent(event.UserUnlocked, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserPasswordChanged, s.handleUserEvent(event.UserPasswordChanged, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserPIIView, s.handleUserEvent(event.UserPIIView, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserSuperAdminGrant, s.handleUserEvent(event.UserSuperAdminGrant, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserSuperAdminRevoke, s.handleUserEvent(event.UserSuperAdminRevoke, EventStatusSuccess))
	s.eventBus.Subscribe(event.UserOffboarded, s.handleUserEvent(event.UserOffboarded, EventStatusSuccess))

	// App events
	s.eventBus.Subscribe(event.AppCreated, s.handleResourceEvent(event.AppCreated, "app"))
	s.eventBus.Subscribe(event.AppUpdated, s.handleResourceEvent(event.AppUpdated, "app"))
	s.eventBus.Subscribe(event.AppDeleted, s.handleResourceEvent(event.AppDeleted, "app"))
	s.eventBus.Subscribe(event.AppLaunched, s.handleAppLaunched)

	// Security-sensitive app sub-resource changes (access grants, signing
	// certs, app roles, role bindings, access policies). Access/cert always
	// carry app_id so resolve to resource_type "app"; role/binding/policy can
	// hang off an app OR an app-group, so handleAppOwnedEvent picks the right
	// resource_type from the payload.
	s.eventBus.Subscribe(event.AppAccessGranted, s.handleResourceEvent(event.AppAccessGranted, "app"))
	s.eventBus.Subscribe(event.AppAccessRevoked, s.handleResourceEvent(event.AppAccessRevoked, "app"))
	s.eventBus.Subscribe(event.AppCertCreated, s.handleResourceEvent(event.AppCertCreated, "app"))
	s.eventBus.Subscribe(event.AppCertDeleted, s.handleResourceEvent(event.AppCertDeleted, "app"))
	s.eventBus.Subscribe(event.AppRoleCreated, s.handleAppOwnedEvent(event.AppRoleCreated))
	s.eventBus.Subscribe(event.AppRoleUpdated, s.handleAppOwnedEvent(event.AppRoleUpdated))
	s.eventBus.Subscribe(event.AppRoleDeleted, s.handleAppOwnedEvent(event.AppRoleDeleted))
	s.eventBus.Subscribe(event.AppRoleBindingCreated, s.handleAppOwnedEvent(event.AppRoleBindingCreated))
	s.eventBus.Subscribe(event.AppRoleBindingDeleted, s.handleAppOwnedEvent(event.AppRoleBindingDeleted))
	s.eventBus.Subscribe(event.AppAccessPolicyCreated, s.handleAppOwnedEvent(event.AppAccessPolicyCreated))
	s.eventBus.Subscribe(event.AppAccessPolicyDeleted, s.handleAppOwnedEvent(event.AppAccessPolicyDeleted))

	// Org events
	s.eventBus.Subscribe(event.OrgCreated, s.handleResourceEvent(event.OrgCreated, "org"))
	s.eventBus.Subscribe(event.OrgUpdated, s.handleResourceEvent(event.OrgUpdated, "org"))
	s.eventBus.Subscribe(event.OrgDeleted, s.handleResourceEvent(event.OrgDeleted, "org"))

	// Tenant events (super-admin operations)
	s.eventBus.Subscribe(event.TenantCreated, s.handleResourceEvent(event.TenantCreated, "tenant"))
	s.eventBus.Subscribe(event.TenantUpdated, s.handleResourceEvent(event.TenantUpdated, "tenant"))
	s.eventBus.Subscribe(event.TenantDeleted, s.handleResourceEvent(event.TenantDeleted, "tenant"))

	// External IdP (inbound federation) config events
	s.eventBus.Subscribe(event.IDPCreated, s.handleResourceEvent(event.IDPCreated, "idp"))
	s.eventBus.Subscribe(event.IDPUpdated, s.handleResourceEvent(event.IDPUpdated, "idp"))
	s.eventBus.Subscribe(event.IDPDeleted, s.handleResourceEvent(event.IDPDeleted, "idp"))

	// Application group events
	s.eventBus.Subscribe(event.AppGroupCreated, s.handleResourceEvent(event.AppGroupCreated, "app_group"))
	s.eventBus.Subscribe(event.AppGroupUpdated, s.handleResourceEvent(event.AppGroupUpdated, "app_group"))
	s.eventBus.Subscribe(event.AppGroupDeleted, s.handleResourceEvent(event.AppGroupDeleted, "app_group"))
	s.eventBus.Subscribe(event.AppGroupMemberAdded, s.handleResourceEvent(event.AppGroupMemberAdded, "app_group"))
	s.eventBus.Subscribe(event.AppGroupMemberRemoved, s.handleResourceEvent(event.AppGroupMemberRemoved, "app_group"))

	// Runtime settings changes (security policy, branding, SMTP, …)
	s.eventBus.Subscribe(event.SettingsUpdated, s.handleGenericEvent(event.SettingsUpdated))

	// Portal self-service identity changes
	s.eventBus.Subscribe(event.ProfileUpdated, s.handleUserEvent(event.ProfileUpdated, EventStatusSuccess))
	s.eventBus.Subscribe(event.APITokenCreated, s.handleGenericEvent(event.APITokenCreated))
	s.eventBus.Subscribe(event.APITokenRevoked, s.handleGenericEvent(event.APITokenRevoked))

	// Session and MFA events
	s.eventBus.Subscribe(event.SessionKicked, s.handleGenericEvent(event.SessionKicked))
	s.eventBus.Subscribe(event.MFAEnabled, s.handleGenericEvent(event.MFAEnabled))
	s.eventBus.Subscribe(event.MFADisabled, s.handleGenericEvent(event.MFADisabled))

	// OIDC token-lifecycle events. Persisted as generic audit rows so
	// admins can trace per-RP issuance / refresh / reuse-detection / consent
	// across the IdP.
	s.eventBus.Subscribe(event.OIDCTokenIssued, s.handleGenericEvent(event.OIDCTokenIssued))
	s.eventBus.Subscribe(event.OIDCTokenRefreshed, s.handleGenericEvent(event.OIDCTokenRefreshed))
	s.eventBus.Subscribe(event.OIDCTokenRevoked, s.handleGenericEvent(event.OIDCTokenRevoked))
	s.eventBus.Subscribe(event.OIDCTokenReuse, s.handleGenericEvent(event.OIDCTokenReuse))
	s.eventBus.Subscribe(event.OIDCConsentGranted, s.handleGenericEvent(event.OIDCConsentGranted))
	s.eventBus.Subscribe(event.OIDCConsentRevoked, s.handleGenericEvent(event.OIDCConsentRevoked))
	s.eventBus.Subscribe(event.OIDCBackchannelLogout, s.handleGenericEvent(event.OIDCBackchannelLogout))
}

// List returns a paginated list of audit logs.
func (s *Service) List(ctx context.Context, params ListParams) ([]*AuditLog, int64, error) {
	return s.repo.List(ctx, params)
}

// GetStats returns audit statistics.
func (s *Service) GetStats(ctx context.Context, tenantID int64, start, end time.Time) (*AuditStatsResponse, error) {
	return s.repo.GetStats(ctx, tenantID, start, end)
}

// handleLoginSuccess creates an audit entry for a successful login.
func (s *Service) handleLoginSuccess(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	username := s.toString(payload["username"])
	ip := s.toString(payload["ip"])
	userAgent := s.toString(payload["user_agent"])
	tenantID := s.toInt64OrDefault(payload["tenant_id"], s.tenantID)

	resourceType := "session"

	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     tenantID,
		ActorID:      &userID,
		ActorName:    &username,
		ActorType:    ActorUser,
		EventType:    event.LoginSuccess,
		EventStatus:  EventStatusSuccess,
		ResourceType: &resourceType,
		IP:           strPtr(ip),
		UserAgent:    strPtr(userAgent),
		Detail:       s.marshalDetailFor(event.LoginSuccess, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleLoginRisk records a conditional-access risk event: a login that fired a
// risk signal but was allowed through (the user had no second factor to
// challenge). Persisted so security operators can review risky logins.
func (s *Service) handleLoginRisk(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	ip := s.toString(payload["ip"])
	tenantID := s.toInt64OrDefault(payload["tenant_id"], s.tenantID)
	resourceType := "session"

	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     tenantID,
		ActorID:      &userID,
		ActorType:    ActorUser,
		EventType:    event.LoginRisk,
		EventStatus:  EventStatusSuccess,
		ResourceType: &resourceType,
		IP:           strPtr(ip),
		Detail:       s.marshalDetailFor(event.LoginRisk, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleLoginFailed creates an audit entry for a failed login attempt.
func (s *Service) handleLoginFailed(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	username := s.toString(payload["username"])
	ip := s.toString(payload["ip"])
	userAgent := s.toString(payload["user_agent"])
	tenantID := s.toInt64OrDefault(payload["tenant_id"], s.tenantID)

	resourceType := "session"

	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     tenantID,
		ActorID:      int64Ptr(userID),
		ActorName:    strPtr(username),
		ActorType:    ActorUser,
		EventType:    event.LoginFailed,
		EventStatus:  EventStatusFail,
		ResourceType: &resourceType,
		IP:           strPtr(ip),
		UserAgent:    strPtr(userAgent),
		Detail:       s.marshalDetailFor(event.LoginFailed, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleLogout creates an audit entry for a logout.
func (s *Service) handleLogout(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	sessionID := s.toString(payload["session_id"])
	ip := s.toString(payload["ip"])
	userAgent := s.toString(payload["user_agent"])

	resourceType := "session"

	// A logout is definitionally a user action. The logout route runs without
	// AuthMiddleware (it reads the cookie directly), so auditctx isn't stamped —
	// pin ActorType here rather than letting enrich() fall back to system. Name
	// still resolves from actor_id via nameResolver; IP comes from the payload.
	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
		ActorID:      int64Ptr(userID),
		ActorType:    ActorUser,
		EventType:    event.Logout,
		EventStatus:  EventStatusSuccess,
		ResourceType: &resourceType,
		IP:           strPtr(ip),
		UserAgent:    strPtr(userAgent),
		SessionID:    strPtr(sessionID),
		Detail:       s.marshalDetailFor(event.Logout, payload),
		CreatedAt:    time.Now(),
	}

	s.createLog(ctx, log)
}

// handleUserEvent returns a handler for user-related domain events.
func (s *Service) handleUserEvent(eventType string, status int) event.Handler {
	return func(ctx context.Context, evt event.Event) {
		payload := s.toMap(evt.Payload)

		userID := s.toInt64(payload["user_id"])
		resourceType := "user"

		// Actor (the admin or self-service user performing the change) is filled
		// by enrich() from auditctx. ResourceID is the *target* user.
		log := &AuditLog{
			ID:           s.idGen.Generate(),
			TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
			EventType:    eventType,
			EventStatus:  status,
			ResourceType: &resourceType,
			ResourceID:   int64Ptr(userID),
			Detail:       s.marshalDetailFor(eventType, payload),
			CreatedAt:    time.Now(),
		}

		// Denormalize the target user's name onto the resource column when the
		// publisher carried it, so the row reads "<actor> changed <username>".
		if name := s.toString(payload["username"]); name != "" {
			log.ResourceName = &name
		}

		s.createLog(ctx, log)
	}
}

// handleResourceEvent returns a handler for generic resource events (app, org, etc.).
func (s *Service) handleResourceEvent(eventType, resourceType string) event.Handler {
	return func(ctx context.Context, evt event.Event) {
		payload := s.toMap(evt.Payload)

		// Actor identity is filled by enrich() from auditctx.
		rt := resourceType
		// Publishers are inconsistent about the primary-key field name: some
		// emit a bare "id", others a domain-scoped "<resource>_id" (e.g. app
		// events carry "app_id"). Accept either so ResourceID is never silently
		// dropped to 0 — an audit row that can't name its subject is useless.
		resourceID := s.toInt64(payload["id"])
		if resourceID == 0 {
			resourceID = s.toInt64(payload[resourceType+"_id"])
		}
		log := &AuditLog{
			ID:           s.idGen.Generate(),
			TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
			EventType:    eventType,
			EventStatus:  EventStatusSuccess,
			ResourceType: &rt,
			ResourceID:   int64Ptr(resourceID),
			Detail:       s.marshalDetailFor(eventType, payload),
			CreatedAt:    time.Now(),
		}

		if name := s.toString(payload["name"]); name != "" {
			log.ResourceName = &name
		}

		s.createLog(ctx, log)
	}
}

// handleAppOwnedEvent records a change to a resource that may belong to either
// an app or an app-group (app roles, role bindings, access policies). The
// resource_type / resource_id are picked from whichever parent id the payload
// carries, so the trail reads "who changed role X on app Y" vs "…on group Z".
func (s *Service) handleAppOwnedEvent(eventType string) event.Handler {
	return func(ctx context.Context, evt event.Event) {
		payload := s.toMap(evt.Payload)

		rt := "app"
		rid := s.toInt64(payload["app_id"])
		if rid == 0 {
			if g := s.toInt64(payload["app_group_id"]); g != 0 {
				rt = "app_group"
				rid = g
			}
		}
		log := &AuditLog{
			ID:           s.idGen.Generate(),
			TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
			EventType:    eventType,
			EventStatus:  EventStatusSuccess,
			ResourceType: &rt,
			ResourceID:   int64Ptr(rid),
			Detail:       s.marshalDetailFor(eventType, payload),
			CreatedAt:    time.Now(),
		}
		if name := s.toString(payload["name"]); name != "" {
			log.ResourceName = &name
		}
		s.createLog(ctx, log)
	}
}

// handleAppLaunched records a portal-user app launch. ActorType is User
// (not Admin like CRUD writes) and ResourceID is the launched app — the
// "recently used" portal endpoint reads back via (actor_id, event_type,
// created_at DESC) so each field matters.
func (s *Service) handleAppLaunched(ctx context.Context, evt event.Event) {
	payload := s.toMap(evt.Payload)

	userID := s.toInt64(payload["user_id"])
	appID := s.toInt64(payload["app_id"])
	ip := s.toString(payload["ip"])
	userAgent := s.toString(payload["user_agent"])
	sessionID := s.toString(payload["session_id"])

	// Actor identity (id / name / type) is filled by enrich() from the
	// request-scoped auditctx; the launch publisher only carries the network
	// fields and the launched app id.
	rt := "app"
	log := &AuditLog{
		ID:           s.idGen.Generate(),
		TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
		ActorID:      int64Ptr(userID),
		EventType:    event.AppLaunched,
		EventStatus:  EventStatusSuccess,
		ResourceType: &rt,
		ResourceID:   int64Ptr(appID),
		IP:           strPtr(ip),
		UserAgent:    strPtr(userAgent),
		SessionID:    strPtr(sessionID),
		Detail:       s.marshalDetailFor(event.AppLaunched, payload),
		CreatedAt:    time.Now(),
	}

	if name := s.toString(payload["name"]); name != "" {
		log.ResourceName = &name
	}

	s.createLog(ctx, log)
}

// handleGenericEvent returns a handler for events that don't fit the resource pattern.
func (s *Service) handleGenericEvent(eventType string) event.Handler {
	return func(ctx context.Context, evt event.Event) {
		payload := s.toMap(evt.Payload)

		// Derive a resource type from the event prefix so generic rows still
		// render a 资源类型 column (e.g. api_token.created → "api_token",
		// settings.updated → "settings"). Actor identity is filled by enrich()
		// from auditctx — do NOT hardcode ActorType here, or self-service /
		// admin events would be mis-tagged as system.
		rt := eventResourcePrefix(eventType)
		log := &AuditLog{
			ID:           s.idGen.Generate(),
			TenantID:     s.toInt64OrDefault(payload["tenant_id"], s.tenantID),
			EventType:    eventType,
			EventStatus:  EventStatusSuccess,
			ResourceType: &rt,
			ResourceID:   int64Ptr(s.toInt64(payload["id"])),
			Detail:       s.marshalDetailFor(eventType, payload),
			CreatedAt:    time.Now(),
		}

		s.createLog(ctx, log)
	}
}

// eventResourcePrefix returns the segment of an event_type before the first
// dot, used as a fallback resource_type for generic events.
func eventResourcePrefix(eventType string) string {
	if i := strings.IndexByte(eventType, '.'); i > 0 {
		return eventType[:i]
	}
	return eventType
}

// enrich fills actor identity and request network context from the
// request-scoped actor stamped by the auth middleware (auditctx). Per-event
// handlers set only what they uniquely know (resource, event-specific detail);
// the "who / from where" is centralized here so every audit row is
// attributable without each publisher reassembling the fields. Values already
// set by the handler win — an explicit payload actor overrides the caller.
func (s *Service) enrich(ctx context.Context, log *AuditLog) {
	if a, ok := auditctx.From(ctx); ok {
		if log.ActorID == nil && a.ActorID != 0 {
			id := a.ActorID
			log.ActorID = &id
		}
		if log.ActorType == "" {
			log.ActorType = a.ActorType
		}
		if log.IP == nil {
			log.IP = strPtr(a.IP)
		}
		if log.UserAgent == nil {
			log.UserAgent = strPtr(a.UserAgent)
		}
		if log.SessionID == nil {
			log.SessionID = strPtr(a.SessionID)
		}
		if log.TenantID == 0 {
			log.TenantID = a.TenantID
		}
	}

	// Denormalize the actor name once, using a cancellation-detached context:
	// the bus delivers events asynchronously (see pkg/event/bus.go) so the
	// originating request context is frequently already canceled by the time
	// this runs — resolving with the raw ctx silently yielded a blank name.
	if log.ActorName == nil && log.ActorID != nil && s.nameResolver != nil {
		if name := s.nameResolver(context.WithoutCancel(ctx), *log.ActorID); name != "" {
			log.ActorName = &name
		}
	}

	// actor_type is NOT NULL. Fall back to system for events with no
	// authenticated caller (protocol-layer token lifecycle, scheduled jobs).
	if log.ActorType == "" {
		log.ActorType = ActorSystem
	}
}

// createLog enriches the row with request-scoped actor context, then persists
// it. Uses a background context for the write because event handlers may run
// after the HTTP request context is canceled.
func (s *Service) createLog(ctx context.Context, log *AuditLog) {
	s.enrich(ctx, log)
	if log.IP != nil {
		s.fillGeo(log, *log.IP)
	}
	if err := s.repo.Create(context.Background(), log); err != nil {
		// A dropped audit write is itself a security incident: the action
		// happened but left no trail. We can't fail the originating request
		// (it already committed), so the log line below MUST stand in as the
		// fallback record — it carries every field needed to reconstruct the
		// lost row. The stable "audit_write_failed" marker + alert=true field
		// are what log-based alerting keys on; wire a metrics counter here if
		// one is ever added. See [[project_audit_architecture]].
		fields := []zap.Field{
			zap.String("marker", "audit_write_failed"),
			zap.Bool("alert", true),
			zap.Int64("audit_id", log.ID),
			zap.String("event_type", log.EventType),
			zap.Int("event_status", log.EventStatus),
			zap.Int64("tenant_id", log.TenantID),
			zap.Error(err),
		}
		if log.ActorID != nil {
			fields = append(fields, zap.Int64("actor_id", *log.ActorID))
		}
		if log.ActorName != nil {
			fields = append(fields, zap.String("actor_name", *log.ActorName))
		}
		if log.ResourceType != nil {
			fields = append(fields, zap.String("resource_type", *log.ResourceType))
		}
		if log.ResourceID != nil {
			fields = append(fields, zap.Int64("resource_id", *log.ResourceID))
		}
		if log.IP != nil {
			fields = append(fields, zap.String("ip", *log.IP))
		}
		if len(log.Detail) > 0 {
			fields = append(fields, zap.ByteString("detail", log.Detail))
		}
		s.logger.Error("audit write failed — row dropped, this log line is the fallback record", fields...)
	}
}

// --- helpers ---

func (s *Service) toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func (s *Service) toString(v any) string {
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

func (s *Service) toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	default:
		return 0
	}
}

func (s *Service) toInt64OrDefault(v any, def int64) int64 {
	val := s.toInt64(v)
	if val == 0 {
		return def
	}
	return val
}

// marshalDetailFor is the audit handlers' single path to producing the
// Detail column bytes. Routes through the per-event_type allow-list in
// schema.go so unrelated payload keys (incl. accidental secret leaks)
// are stripped before persist.
func (s *Service) marshalDetailFor(eventType string, payload map[string]any) json.RawMessage {
	return projectDetail(eventType, payload)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func int64Ptr(n int64) *int64 {
	if n == 0 {
		return nil
	}
	return &n
}
