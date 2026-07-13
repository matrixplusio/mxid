package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imkerbos/mxid/internal/protocol/saml"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// Service errors.
var (
	ErrAppNotFound       = errors.New("app not found")
	ErrAppCodeExists     = errors.New("app code already exists")
	ErrAppGroupNotFound  = errors.New("app group not found")
	ErrGroupCodeExists   = errors.New("app group code already exists")
	ErrAccessNotFound    = errors.New("access authorization not found")
	ErrCertNotFound      = errors.New("certificate not found")
	ErrAccountNotFound   = errors.New("app account not found")
	ErrInvalidClientType = errors.New("invalid client_type for protocol")
	// ErrFormFillNotLicensed is returned when a form-fill (SWA) app is created
	// without the EE form_fill license feature.
	ErrFormFillNotLicensed = errors.New("form-fill requires an EE license")
	// ErrSubjectNotInTenant is returned when AddAccess is asked to authorize a
	// subject (user/group/org/role) that does not exist in the caller's tenant
	// — including a cross-tenant id, which the injected validator (tenant-scoped
	// repo) reports as absent. The parent app is already guarded; this closes
	// the residual referenced-entity IDOR on the subject.
	ErrSubjectNotInTenant = errors.New("subject not found in tenant")
)

// Access subject type constants for AddAccess. Mirror the appaccess module's
// subject vocabulary (user|group|org|role).
const (
	AccessSubjectUser  = "user"
	AccessSubjectGroup = "group"
	AccessSubjectOrg   = "org"
	AccessSubjectRole  = "role"
)

// EntityValidator reports whether a referenced entity id exists within the
// caller's tenant. Backed by the referent's tenant-scoped GetByID (the
// tenantscope plugin appends tenant_id=?, so a cross-tenant id resolves to
// false). Injected so the app service does not import user/group/org/role.
type EntityValidator func(ctx context.Context, id int64) (bool, error)

// AccessSubjectValidators bundles the per-type tenant-scoped existence checks
// AddAccess needs to validate the request-body subject.
type AccessSubjectValidators struct {
	User  EntityValidator
	Group EntityValidator
	Org   EntityValidator
	Role  EntityValidator
}

// Service provides business logic for application management.
// ProtocolDefaults carries the admin-configured per-protocol defaults
// applied when an app is created without explicit TTL / subject_strategy
// overrides in the request. Zero fields are ignored — local fallbacks
// (per-protocol Defaults() funcs) provide the next-level default.
type ProtocolDefaults struct {
	OIDCAccessTokenTTL  int
	OIDCRefreshTokenTTL int
	OIDCIDTokenTTL      int
	SAMLAssertionTTL    int
	CASTicketTTL        int
	DefaultSubject      string
}

// ProtocolDefaultsProvider returns the runtime defaults for new apps.
// Always called at app.Create time; nil = no overrides (legacy behaviour).
type ProtocolDefaultsProvider func(ctx context.Context, tenantID int64) ProtocolDefaults

type Service struct {
	repo              Repository
	idGen             *snowflake.Generator
	eventBus          *event.Bus
	keyService        *KeyService
	protoDefaultsP    ProtocolDefaultsProvider
	subjectValidators AccessSubjectValidators
}

// SetAccessSubjectValidators injects the tenant-scoped subject existence checks
// used by AddAccess. Wired in cmd/server/main.go once the domains exist.
func (s *Service) SetAccessSubjectValidators(v AccessSubjectValidators) {
	s.subjectValidators = v
}

// validateAccessSubject proves the request-body subject belongs to the caller's
// tenant. A cross-tenant id resolves to false via the tenant-scoped validator
// → ErrSubjectNotInTenant. Fails closed if no validator was wired.
func (s *Service) validateAccessSubject(ctx context.Context, subjectType string, subjectID int64) error {
	var v EntityValidator
	switch subjectType {
	case AccessSubjectUser:
		v = s.subjectValidators.User
	case AccessSubjectGroup:
		v = s.subjectValidators.Group
	case AccessSubjectOrg:
		v = s.subjectValidators.Org
	case AccessSubjectRole:
		v = s.subjectValidators.Role
	default:
		return fmt.Errorf("app: unknown access subject_type %q", subjectType)
	}
	if v == nil {
		return fmt.Errorf("app: validator for %q not configured", subjectType)
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

// SetProtocolDefaultsProvider injects the runtime defaults lookup. Called
// by main.go after the setting service is built.
func (s *Service) SetProtocolDefaultsProvider(p ProtocolDefaultsProvider) {
	s.protoDefaultsP = p
}

func (s *Service) protoDefaults(ctx context.Context, tenantID int64) ProtocolDefaults {
	if s.protoDefaultsP == nil {
		return ProtocolDefaults{}
	}
	return s.protoDefaultsP(ctx, tenantID)
}

// NewService creates a new app service.
func NewService(repo Repository, idGen *snowflake.Generator, eventBus *event.Bus) *Service {
	return &Service{
		repo:     repo,
		idGen:    idGen,
		eventBus: eventBus,
	}
}

// SetKeyService injects the key management service. Called by Register after
// both Service and KeyService are constructed; resolves the circular dep
// without forcing key material into NewService's signature.
func (s *Service) SetKeyService(ks *KeyService) {
	s.keyService = ks
}

// --- App CRUD ---

// Create creates a new application with auto-generated client_id, hashed
// client_secret (when applicable), and protocol-specific defaults.
//
// The returned CreateAppResult carries the one-time plaintext client_secret
// for confidential OIDC clients (web_app / m2m); SPAs and native clients
// receive an empty plaintext per OAuth 2.0 best practice (no secret).
//
// Signing key material is NOT generated here — call KeyService.GenerateForApp
// from the caller (gateway) within the same logical unit so that a key
// failure rolls back the app creation.
func (s *Service) Create(ctx context.Context, tenantID int64, req *CreateAppRequest) (*CreateAppResult, error) {
	if _, err := s.repo.GetByCode(ctx, tenantID, req.Code); err == nil {
		return nil, ErrAppCodeExists
	} else if !dberr.IsNotFound(err) {
		return nil, fmt.Errorf("check app code: %w", err)
	}

	clientType := req.ClientType
	if clientType == "" {
		clientType = ClientTypeWebApp
	}

	if req.Protocol == ProtocolOIDC {
		switch clientType {
		case ClientTypeWebApp, ClientTypeSPA, ClientTypeNative, ClientTypeM2M:
		default:
			return nil, ErrInvalidClientType
		}
	}

	// Form-fill apps carry a downstream credential vault — an EE (form_fill)
	// capability. The generic app-create route serves every protocol, so the
	// license gate lives here rather than as route middleware. CE (no license)
	// rejects; the descriptor + credential logic lives in mxid-ee.
	if req.Protocol == ProtocolForm && !license.Current().Has(license.FeatureFormFill) {
		return nil, ErrFormFillNotLicensed
	}

	clientID, err := crypto.GenerateClientID()
	if err != nil {
		return nil, fmt.Errorf("generate client_id: %w", err)
	}

	var (
		clientSecretPlain string
		clientSecretHash  *string
	)
	if needsClientSecret(req.Protocol, clientType) {
		clientSecretPlain, err = crypto.GenerateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("generate client_secret: %w", err)
		}
		hashed, err := crypto.HashPassword(clientSecretPlain)
		if err != nil {
			return nil, fmt.Errorf("hash client_secret: %w", err)
		}
		clientSecretHash = &hashed
	}

	defaults := s.protoDefaults(ctx, tenantID)

	var protocolConfig json.RawMessage
	if req.ProtocolConfig != nil {
		protocolConfig, err = json.Marshal(req.ProtocolConfig)
		if err != nil {
			return nil, fmt.Errorf("marshal protocol config: %w", err)
		}
	} else {
		protocolConfig = json.RawMessage(`{}`)
	}
	// Per-protocol TTL defaults from settings. Only applied when the request
	// left protocol_config as {} — explicit configs are honored verbatim.
	if bytes.Equal(protocolConfig, []byte(`{}`)) {
		if patched := defaultProtocolConfig(req.Protocol, defaults); patched != nil {
			protocolConfig = patched
		}
	}

	var redirectURIs json.RawMessage
	if req.RedirectURIs != nil {
		redirectURIs, err = json.Marshal(req.RedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("marshal redirect uris: %w", err)
		}
	} else {
		redirectURIs = json.RawMessage(`[]`)
	}

	accessPolicy := AccessPolicyAll
	if req.AccessPolicy != nil {
		accessPolicy = *req.AccessPolicy
	}

	isFirstParty := true
	if req.IsFirstParty != nil {
		isFirstParty = *req.IsFirstParty
	}
	requireConsent := false
	if req.RequireConsent != nil {
		requireConsent = *req.RequireConsent
	}

	now := time.Now()
	// scope/subject_strategy resolution:
	//   - default scope = ScopeTenant; tenant_id required
	//   - ScopeShared apps have tenant_id = NULL (super_admin only — handler gates)
	//   - subject_strategy default: "username" (back-compat). Shared apps that
	//     try to use "username" are rejected at the API boundary (handler).
	scope := ScopeTenant
	if req.Scope != nil {
		scope = *req.Scope
	}
	subjectStrategy := SubjectStrategyUsername
	if defaults.DefaultSubject != "" {
		subjectStrategy = defaults.DefaultSubject
	}
	if req.SubjectStrategy != nil && *req.SubjectStrategy != "" {
		subjectStrategy = *req.SubjectStrategy
	}
	// Shared apps default to username_suffixed and reject bare username (which
	// can collide across tenants). For non-OIDC protocols pairwise is also
	// rejected — OIDC-only feature.
	if scope == ScopeShared {
		if subjectStrategy == SubjectStrategyUsername {
			subjectStrategy = SubjectStrategyUsernameSuffixed
		}
	}
	if subjectStrategy == SubjectStrategyPairwise && req.Protocol != ProtocolOIDC {
		return nil, fmt.Errorf("subject_strategy=pairwise only valid for OIDC")
	}
	var appTenantID *int64
	if scope == ScopeTenant {
		tid := tenantID
		appTenantID = &tid
	}
	application := &App{
		ID:              s.idGen.Generate(),
		TenantID:        appTenantID,
		Scope:           scope,
		SubjectStrategy: subjectStrategy,
		Name:            req.Name,
		Code:            req.Code,
		Protocol:        req.Protocol,
		ClientType:      clientType,
		Status:          StatusEnabled,
		Icon:            req.Icon,
		Env:             normalizeEnv(req.Env),
		Description:     req.Description,
		ClientID:        &clientID,
		ClientSecret:    clientSecretHash,
		HomeURL:         req.HomeURL,
		IsFirstParty:    isFirstParty,
		RequireConsent:  requireConsent,
		ProtocolConfig:  protocolConfig,
		LoginURL:        req.LoginURL,
		RedirectURIs:    redirectURIs,
		LogoutURL:       req.LogoutURL,
		AccessPolicy:    accessPolicy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := s.repo.Create(ctx, application); err != nil {
		return nil, fmt.Errorf("create app: %w", err)
	}

	// Generate signing key material for protocols that produce signed
	// artefacts:
	//   - OIDC issues signed id_tokens
	//   - SAML signs assertion + response, and the SP needs the cert in IdP metadata
	//   - CAS 3.0 signs SLO LogoutRequest payloads
	//
	// On failure roll back the app row so we never leave a signed-protocol
	// app without a key (would make /metadata + /token return 500).
	var signingKID string
	needsKey := req.Protocol == ProtocolOIDC || req.Protocol == ProtocolSAML || req.Protocol == ProtocolCAS
	if needsKey {
		if s.keyService == nil {
			_ = s.repo.Delete(ctx, application.ID)
			return nil, fmt.Errorf("create app: key service unavailable")
		}
		cert, err := s.keyService.GenerateForApp(ctx, application.ID)
		if err != nil {
			_ = s.repo.Delete(ctx, application.ID)
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
		if cert.KID != nil {
			signingKID = *cert.KID
		}
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppCreated,
		Payload: map[string]any{"app_id": application.ID, "tenant_id": tenantID, "name": application.Name, "code": application.Code, "protocol": application.Protocol},
	})

	return &CreateAppResult{
		App:               application,
		ClientSecretPlain: clientSecretPlain,
		SigningKID:        signingKID,
	}, nil
}

// RotateClientSecret generates a new client_secret for the given app, replacing
// the stored bcrypt hash. Returns the one-time plaintext.
//
// Returns ErrInvalidClientType when called on a public (SPA / native) OIDC client.
func (s *Service) RotateClientSecret(ctx context.Context, id int64) (*RotateSecretResult, error) {
	application, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}
	if !needsClientSecret(application.Protocol, application.ClientType) {
		return nil, ErrInvalidClientType
	}

	plain, err := crypto.GenerateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("generate client_secret: %w", err)
	}
	hashed, err := crypto.HashPassword(plain)
	if err != nil {
		return nil, fmt.Errorf("hash client_secret: %w", err)
	}
	application.ClientSecret = &hashed
	application.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, application); err != nil {
		return nil, fmt.Errorf("update app: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppUpdated,
		Payload: map[string]any{"app_id": application.ID, "action": "rotate_client_secret"},
	})

	return &RotateSecretResult{ClientSecretPlain: plain}, nil
}

// RotateSigningKey performs a soft rotation of the app's signing key.
// Returns the new active cert.
func (s *Service) RotateSigningKey(ctx context.Context, id int64) (*AppCert, error) {
	if _, err := s.repo.GetByID(ctx, id); err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}
	if s.keyService == nil {
		return nil, fmt.Errorf("key service unavailable")
	}
	cert, err := s.keyService.RotateForApp(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("rotate signing key: %w", err)
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppUpdated,
		Payload: map[string]any{"app_id": id, "action": "rotate_signing_key"},
	})
	return cert, nil
}

// VerifyClientSecret returns true when the supplied plaintext matches the
// stored bcrypt hash for the given client_id.
func (s *Service) VerifyClientSecret(ctx context.Context, clientID, plaintext string) (*App, bool, error) {
	application, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get app: %w", err)
	}
	if application.ClientSecret == nil {
		return application, false, nil
	}
	return application, crypto.CheckPassword(plaintext, *application.ClientSecret), nil
}

// needsClientSecret returns true when the (protocol, client_type) pair requires
// a server-side secret (confidential client per OAuth 2.0 §2.1).
func needsClientSecret(protocol, clientType string) bool {
	if protocol != ProtocolOIDC {
		return false
	}
	return clientType == ClientTypeWebApp || clientType == ClientTypeM2M
}

// GetByID retrieves an application by ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*App, error) {
	application, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}
	return application, nil
}

// requireApp fetches the parent app via the tenant-scoped repo so the
// tenantscope plugin appends its predicate (tenant_id=? OR tenant_id IS NULL
// for shared apps). A cross-tenant appID resolves to ErrRecordNotFound,
// surfaced as ErrAppNotFound. This is the parent-ownership guard the tenant-less
// child tables (mxid_app_access, mxid_app_cert, mxid_app_group_rel) rely on,
// since the column plugin cannot filter them.
func (s *Service) requireApp(ctx context.Context, appID int64) error {
	if _, err := s.repo.GetByID(ctx, appID); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("get app: %w", err)
	}
	return nil
}

// requireAppGroup fetches the parent app group via the tenant-scoped repo. A
// cross-tenant groupID resolves to ErrAppGroupNotFound.
func (s *Service) requireAppGroup(ctx context.Context, groupID int64) error {
	if _, err := s.repo.GetGroupByID(ctx, groupID); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppGroupNotFound
		}
		return fmt.Errorf("get app group: %w", err)
	}
	return nil
}

// Update modifies an application's mutable fields.
func (s *Service) Update(ctx context.Context, id int64, req *UpdateAppRequest) (*App, error) {
	application, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}

	// Track which fields the request actually mutated so the audit trail can
	// answer "what changed" instead of an opaque app.updated row.
	var fields []string
	if req.Name != nil {
		application.Name = *req.Name
		fields = append(fields, "name")
	}
	if req.SubjectStrategy != nil && *req.SubjectStrategy != "" {
		// Shared apps forbid the bare-username strategy because it can collide
		// across tenants. The handler also validates this before reaching the
		// service; check here too as defence in depth.
		if application.Scope == ScopeShared && *req.SubjectStrategy == SubjectStrategyUsername {
			return nil, fmt.Errorf("shared app cannot use subject_strategy=username")
		}
		application.SubjectStrategy = *req.SubjectStrategy
		fields = append(fields, "subject_strategy")
	}
	if req.Icon != nil {
		application.Icon = req.Icon
		fields = append(fields, "icon")
	}
	if req.Description != nil {
		application.Description = req.Description
		fields = append(fields, "description")
	}
	if req.HomeURL != nil {
		application.HomeURL = req.HomeURL
		fields = append(fields, "home_url")
	}
	if req.LoginURL != nil {
		application.LoginURL = req.LoginURL
		fields = append(fields, "login_url")
	}
	if req.LogoutURL != nil {
		application.LogoutURL = req.LogoutURL
		fields = append(fields, "logout_url")
	}
	if req.AccessPolicy != nil {
		application.AccessPolicy = *req.AccessPolicy
		fields = append(fields, "access_policy")
	}
	if req.IsFirstParty != nil {
		application.IsFirstParty = *req.IsFirstParty
		fields = append(fields, "is_first_party")
	}
	if req.RequireConsent != nil {
		application.RequireConsent = *req.RequireConsent
		fields = append(fields, "require_consent")
	}
	if req.Env != nil {
		application.Env = normalizeEnv(req.Env)
		fields = append(fields, "env")
	}

	if req.RedirectURIs != nil {
		uris, err := json.Marshal(req.RedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("marshal redirect uris: %w", err)
		}
		application.RedirectURIs = uris
		fields = append(fields, "redirect_uris")
	}

	if req.ProtocolConfig != nil {
		pc, err := json.Marshal(req.ProtocolConfig)
		if err != nil {
			return nil, fmt.Errorf("marshal protocol config: %w", err)
		}
		application.ProtocolConfig = pc
		fields = append(fields, "protocol_config")
	}

	application.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, application); err != nil {
		return nil, fmt.Errorf("update app: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppUpdated,
		Payload: map[string]any{"app_id": application.ID, "tenant_id": application.TenantID, "name": application.Name, "fields": fields},
	})

	return application, nil
}

// normalizeEnv trims and lower-cases an environment label so grouping stays
// stable regardless of how the admin typed it ("Prod" == "prod"). An empty or
// whitespace-only value collapses to nil ("unlabelled").
func normalizeEnv(env *string) *string {
	if env == nil {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(*env))
	if v == "" {
		return nil
	}
	return &v
}

// Delete soft-deletes an application.
func (s *Service) Delete(ctx context.Context, id int64) error {
	application, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("get app: %w", err)
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete app: %w", err)
	}

	// Carry name + code so the audit row can name which app was deleted — the
	// row is gone by read time, so the trail is the only record left.
	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppDeleted,
		Payload: map[string]any{"app_id": id, "tenant_id": application.TenantID, "name": application.Name, "code": application.Code},
	})

	return nil
}

// List returns a paginated list of applications.
func (s *Service) List(ctx context.Context, tenantID int64, params ListAppParams) ([]*App, int64, error) {
	apps, total, err := s.repo.List(ctx, tenantID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("list apps: %w", err)
	}
	return apps, total, nil
}

// ListEnvOptions returns the distinct custom env labels already in use, for the
// console app-form dropdown (merged with the static presets client-side).
func (s *Service) ListEnvOptions(ctx context.Context, tenantID int64) ([]string, error) {
	envs, err := s.repo.ListDistinctEnvs(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list env options: %w", err)
	}
	return envs, nil
}

// UpdateStatus updates an application's status.
func (s *Service) UpdateStatus(ctx context.Context, id int64, status int) error {
	if err := s.repo.UpdateStatus(ctx, id, status); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("update app status: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppUpdated,
		Payload: map[string]any{"app_id": id, "status": status},
	})

	return nil
}

// GetProtocolConfig retrieves the protocol configuration for an application.
func (s *Service) GetProtocolConfig(ctx context.Context, id int64) (map[string]any, error) {
	application, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}

	var config map[string]any
	if len(application.ProtocolConfig) > 0 {
		if err := json.Unmarshal(application.ProtocolConfig, &config); err != nil {
			return nil, fmt.Errorf("unmarshal protocol config: %w", err)
		}
	}
	if config == nil {
		config = make(map[string]any)
	}

	return config, nil
}

// UpdateProtocolConfig updates the protocol configuration for an application.
func (s *Service) UpdateProtocolConfig(ctx context.Context, id int64, config map[string]any) error {
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal protocol config: %w", err)
	}

	if err := s.repo.UpdateProtocolConfig(ctx, id, data); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("update protocol config: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppUpdated,
		Payload: map[string]any{"app_id": id, "action": "update_protocol_config"},
	})

	return nil
}

// ImportSAMLSPMetadata parses an SP metadata XML document and merges the
// extracted fields into the app's protocol_config. Existing keys not produced
// by the parser (sign_assertions, attribute_mapping, …) are preserved so
// operators don't lose their tuning when re-importing.
//
// Returns the resulting protocol_config map so the API handler can echo it
// back to the SPA without an extra round-trip.
func (s *Service) ImportSAMLSPMetadata(ctx context.Context, id int64, xmlBytes []byte) (map[string]any, error) {
	app, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}
	if app.Protocol != ProtocolSAML {
		return nil, fmt.Errorf("app is not SAML (protocol=%s)", app.Protocol)
	}

	parsed, err := saml.ParseSPMetadata(xmlBytes)
	if err != nil {
		return nil, err
	}

	current := map[string]any{}
	if len(app.ProtocolConfig) > 0 {
		_ = json.Unmarshal(app.ProtocolConfig, &current)
	}
	if parsed.EntityID != "" {
		current["sp_entity_id"] = parsed.EntityID
	}
	if parsed.ACSURL != "" {
		current["acs_url"] = parsed.ACSURL
	}
	if parsed.SLOURL != "" {
		current["slo_url"] = parsed.SLOURL
	}
	if parsed.NameIDFormat != "" {
		current["name_id_format"] = parsed.NameIDFormat
	}
	if parsed.X509CertPEM != "" {
		current["sp_cert"] = parsed.X509CertPEM
	}

	if err := s.UpdateProtocolConfig(ctx, id, current); err != nil {
		return nil, err
	}
	return current, nil
}

// --- AppGroup ---

// CreateGroup creates a new application group.
func (s *Service) CreateGroup(ctx context.Context, tenantID int64, req *AppGroupRequest) (*AppGroup, error) {
	// Check code uniqueness
	existing, err := s.repo.ListGroups(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	for _, g := range existing {
		if g.Code == req.Code {
			return nil, ErrGroupCodeExists
		}
	}

	sortOrder := 0
	if req.SortOrder != nil {
		sortOrder = *req.SortOrder
	}

	// App groups are flat (one level by product decision). Any client-
	// supplied parent_id is silently dropped.
	now := time.Now()
	group := &AppGroup{
		ID:        s.idGen.Generate(),
		TenantID:  tenantID,
		Name:      req.Name,
		Code:      req.Code,
		ParentID:  nil,
		SortOrder: sortOrder,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.repo.CreateGroup(ctx, group); err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppGroupCreated,
		Payload: map[string]any{"id": group.ID, "tenant_id": group.TenantID, "name": group.Name, "code": group.Code},
	})
	return group, nil
}

// GetGroupByID retrieves an app group by ID.
func (s *Service) GetGroupByID(ctx context.Context, id int64) (*AppGroup, error) {
	group, err := s.repo.GetGroupByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppGroupNotFound
		}
		return nil, fmt.Errorf("get group: %w", err)
	}
	return group, nil
}

// UpdateGroup modifies an app group.
func (s *Service) UpdateGroup(ctx context.Context, id int64, req *UpdateAppGroupRequest) (*AppGroup, error) {
	group, err := s.repo.GetGroupByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppGroupNotFound
		}
		return nil, fmt.Errorf("get group: %w", err)
	}

	if req.Name != nil {
		group.Name = *req.Name
	}
	if req.SortOrder != nil {
		group.SortOrder = *req.SortOrder
	}
	// App groups are flat — ignore any client-supplied parent_id. Force
	// existing rows back to root on update so legacy nested data heals.
	group.ParentID = nil

	group.UpdatedAt = time.Now()

	if err := s.repo.UpdateGroup(ctx, group); err != nil {
		return nil, fmt.Errorf("update group: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppGroupUpdated,
		Payload: map[string]any{"id": group.ID, "tenant_id": group.TenantID, "name": group.Name},
	})
	return group, nil
}

// DeleteGroup soft-deletes an app group.
func (s *Service) DeleteGroup(ctx context.Context, id int64) error {
	group, err := s.repo.GetGroupByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppGroupNotFound
		}
		return fmt.Errorf("get group: %w", err)
	}

	if err := s.repo.DeleteGroup(ctx, id); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppGroupDeleted,
		Payload: map[string]any{"id": group.ID, "tenant_id": group.TenantID, "name": group.Name},
	})
	return nil
}

// ListGroups returns all app groups for a tenant.
func (s *Service) ListGroups(ctx context.Context, tenantID int64) ([]*AppGroup, error) {
	groups, err := s.repo.ListGroups(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	return groups, nil
}

// ListAppsByGroup returns relation rows linking a group to its member apps.
func (s *Service) ListAppsByGroup(ctx context.Context, groupID int64) ([]*AppGroupRel, error) {
	if err := s.requireAppGroup(ctx, groupID); err != nil {
		return nil, err
	}
	return s.repo.ListAppsByGroup(ctx, groupID)
}

// GetByIDs loads multiple apps in one query.
func (s *Service) GetByIDs(ctx context.Context, ids []int64) ([]*App, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return s.repo.GetByIDs(ctx, ids)
}

// AddAppToGroup adds an app to a group.
func (s *Service) AddAppToGroup(ctx context.Context, groupID, appID int64) error {
	// Verify group exists
	if _, err := s.repo.GetGroupByID(ctx, groupID); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppGroupNotFound
		}
		return fmt.Errorf("get group: %w", err)
	}

	// Verify app exists
	if _, err := s.repo.GetByID(ctx, appID); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("get app: %w", err)
	}

	rel := &AppGroupRel{
		ID:        s.idGen.Generate(),
		AppID:     appID,
		GroupID:   groupID,
		CreatedAt: time.Now(),
	}

	if err := s.repo.AddAppToGroup(ctx, rel); err != nil {
		return fmt.Errorf("add app to group: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppGroupMemberAdded,
		Payload: map[string]any{"id": groupID, "app_id": appID},
	})
	return nil
}

// RemoveAppFromGroup removes an app from a group.
func (s *Service) RemoveAppFromGroup(ctx context.Context, groupID, appID int64) error {
	// Tenant-ownership guard on both parents before the unlink — mirrors
	// AddAppToGroup, which verifies both the group and the app exist.
	if err := s.requireAppGroup(ctx, groupID); err != nil {
		return err
	}
	if err := s.requireApp(ctx, appID); err != nil {
		return err
	}
	if err := s.repo.RemoveAppFromGroup(ctx, appID, groupID); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("remove app from group: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppGroupMemberRemoved,
		Payload: map[string]any{"id": groupID, "app_id": appID},
	})
	return nil
}

// --- AppAccess ---

// AddAccess adds an access authorization for an app.
func (s *Service) AddAccess(ctx context.Context, appID int64, req *AddAccessRequest) (*AppAccess, error) {
	// Verify app exists
	if _, err := s.repo.GetByID(ctx, appID); err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}

	// Referenced-entity guard: the subject id comes from the request body.
	// Reject a subject that is not in the caller's tenant so a foreign
	// user/group/org/role cannot be authorized onto this app.
	if err := s.validateAccessSubject(ctx, req.SubjectType, req.SubjectID); err != nil {
		return nil, err
	}

	access := &AppAccess{
		ID:          s.idGen.Generate(),
		AppID:       appID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		CreatedAt:   time.Now(),
	}

	if err := s.repo.AddAccess(ctx, access); err != nil {
		return nil, fmt.Errorf("add access: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppAccessGranted,
		Payload: map[string]any{"app_id": appID, "subject_type": req.SubjectType, "subject_id": req.SubjectID},
	})

	return access, nil
}

// RemoveAccess removes an access authorization. The request FK is the child
// row id, so we load the access row, then run the tenant-ownership guard on its
// parent app before deleting — a cross-tenant access id resolves to a
// cross-tenant app that requireApp 404s.
func (s *Service) RemoveAccess(ctx context.Context, id int64) error {
	access, err := s.repo.GetAccessByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrAccessNotFound
		}
		return fmt.Errorf("get access: %w", err)
	}
	if err := s.requireApp(ctx, access.AppID); err != nil {
		// Parent app not in caller's tenant — treat the access row as not found.
		if errors.Is(err, ErrAppNotFound) {
			return ErrAccessNotFound
		}
		return err
	}
	if err := s.repo.RemoveAccess(ctx, id); err != nil {
		if dberr.IsNotFound(err) {
			return ErrAccessNotFound
		}
		return fmt.Errorf("remove access: %w", err)
	}

	s.eventBus.Publish(ctx, event.Event{
		Type:    event.AppAccessRevoked,
		Payload: map[string]any{"app_id": access.AppID, "subject_type": access.SubjectType, "subject_id": access.SubjectID},
	})
	return nil
}

// ListAccess returns all access authorizations for an app.
func (s *Service) ListAccess(ctx context.Context, appID int64) ([]*AppAccess, error) {
	if err := s.requireApp(ctx, appID); err != nil {
		return nil, err
	}
	accesses, err := s.repo.ListAccessByApp(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("list access: %w", err)
	}
	return accesses, nil
}

// --- AppCert ---

// CreateCert mints a fresh signing keypair (RSA-2048, RS256) for an app and
// persists it as a new active mxid_app_cert row. Delegates to KeyService so
// private-key material is encrypted with the configured master key.
//
// If an active signing cert already exists, the new key becomes active and
// the previous one is demoted to rotating (overlap window for in-flight
// id_tokens). Pass through ErrAppNotFound if the app does not exist.
func (s *Service) CreateCert(ctx context.Context, appID int64) (*AppCert, error) {
	if s.keyService == nil {
		return nil, fmt.Errorf("key service not configured")
	}
	if _, err := s.repo.GetByID(ctx, appID); err != nil {
		if dberr.IsNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}
	cert, err := s.keyService.RotateForApp(ctx, appID)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{"app_id": appID}
	if cert != nil && cert.KID != nil {
		payload["kid"] = *cert.KID
	}
	s.eventBus.Publish(ctx, event.Event{Type: event.AppCertCreated, Payload: payload})

	return cert, nil
}

// ListCerts returns all certificates for an app.
func (s *Service) ListCerts(ctx context.Context, appID int64) ([]*AppCert, error) {
	if err := s.requireApp(ctx, appID); err != nil {
		return nil, err
	}
	certs, err := s.repo.ListCertsByApp(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	return certs, nil
}

// DeleteCert deletes a certificate. The request FK is the child row id, so we
// load the cert, then run the tenant-ownership guard on its parent app before
// deleting — a cross-tenant cert id resolves to a cross-tenant app that
// requireApp 404s, preventing a DoS on another tenant's signing keys.
func (s *Service) DeleteCert(ctx context.Context, id int64) error {
	cert, err := s.repo.GetCertByID(ctx, id)
	if err != nil {
		if dberr.IsNotFound(err) {
			return ErrCertNotFound
		}
		return fmt.Errorf("get cert: %w", err)
	}
	if err := s.requireApp(ctx, cert.AppID); err != nil {
		if errors.Is(err, ErrAppNotFound) {
			return ErrCertNotFound
		}
		return err
	}
	if err := s.repo.DeleteCert(ctx, id); err != nil {
		if dberr.IsNotFound(err) {
			return ErrCertNotFound
		}
		return fmt.Errorf("delete cert: %w", err)
	}

	payload := map[string]any{"app_id": cert.AppID, "cert_id": id}
	if cert.KID != nil {
		payload["kid"] = *cert.KID
	}
	s.eventBus.Publish(ctx, event.Event{Type: event.AppCertDeleted, Payload: payload})
	return nil
}

// defaultProtocolConfig emits a minimal JSON object carrying just the TTL
// fields the admin set in ProtocolDefaults. Per-protocol Defaults() funcs
// still apply at protocol-read time for any fields left unset here — this
// only injects what the admin chose to override. Returns nil when no
// admin override exists for the protocol.
func defaultProtocolConfig(protocol string, d ProtocolDefaults) json.RawMessage {
	switch protocol {
	case ProtocolOIDC:
		cfg := map[string]int{}
		if d.OIDCAccessTokenTTL > 0 {
			cfg["access_token_ttl"] = d.OIDCAccessTokenTTL
		}
		if d.OIDCRefreshTokenTTL > 0 {
			cfg["refresh_token_ttl"] = d.OIDCRefreshTokenTTL
		}
		if d.OIDCIDTokenTTL > 0 {
			cfg["id_token_ttl"] = d.OIDCIDTokenTTL
		}
		if len(cfg) == 0 {
			return nil
		}
		b, _ := json.Marshal(cfg)
		return b
	case ProtocolSAML:
		if d.SAMLAssertionTTL <= 0 {
			return nil
		}
		b, _ := json.Marshal(map[string]int{"assertion_ttl": d.SAMLAssertionTTL})
		return b
	case ProtocolCAS:
		if d.CASTicketTTL <= 0 {
			return nil
		}
		b, _ := json.Marshal(map[string]int{"ticket_ttl": d.CASTicketTTL})
		return b
	}
	return nil
}
