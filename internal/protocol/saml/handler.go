package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	crewjam "github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/ssoflow"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/imkerbos/mxid/pkg/urlswap"
	"go.uber.org/zap"
)

// AppRoleResolver returns a user's effective app-role codes for an app, ordered
// with JIT (time-bound) elevations first — see approle.Service.ResolveCodes.
// Structurally identical to the OIDC resolver so the same adapter serves both.
type AppRoleResolver interface {
	ResolveAppRoles(ctx context.Context, userID, appID, tenantID int64) ([]string, error)
}

// AccessChecker reports whether a user may access an app under its access
// policy (public/user/group/org/role allow+deny rules). Same contract as the
// OIDC bridge's checker; reason is a machine token for the "no access" page.
// Injected by Register; a nil checker means the policy is NOT enforced.
type AccessChecker interface {
	CheckAppAccess(ctx context.Context, userID, appID, tenantID int64) (allowed bool, reason string, err error)
}

// Handler serves SAML protocol endpoints.
type Handler struct {
	issuer      string
	portalURL   string
	urlProvider urlswap.Provider
	appRes      resolver.AppResolver
	idRes       resolver.IdentityResolver
	sessRes     resolver.SessionResolver
	tenantRes   resolver.TenantResolver
	sessionIdx  *SessionIndexStore
	logger      *zap.Logger
	// access enforces the app-access policy before an assertion is minted. Set
	// by Register. nil = policy NOT enforced (dangerous — always wire in prod).
	access AccessChecker
	// confirm mints/consumes the one-time SSO login-confirmation token. Set by
	// Register. nil = confirmation feature off (SP-initiated stays seamless).
	confirm *ssoflow.ConfirmStore
	// appRoles resolves the user's effective app roles (JIT elevations first) to
	// emit as a multi-value SAML attribute. nil = no role attribute.
	appRoles AppRoleResolver
	// backchannelClient overrides the package-level SSRF-safe
	// samlBackchannelClient when non-nil. Used in tests so an httptest SP on
	// loopback can receive IdP-initiated LogoutRequests; production always uses
	// the SSRF-safe client.
	backchannelClient httpDoer
}

// httpDoer is the minimal HTTP interface used by IdP-initiated SLO so tests can
// substitute a plain http.Client while production uses the SSRF-safe client.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// SetURLProvider wires the runtime URL lookup. nil = stick with the
// issuer + portal URL captured at construction.
func (h *Handler) SetURLProvider(p urlswap.Provider) { h.urlProvider = p }

func (h *Handler) resolveURLs(ctx context.Context, reqHost string) urlswap.URLs {
	return urlswap.Resolve(ctx, h.urlProvider, urlswap.URLs{
		Issuer: h.issuer,
		Portal: h.portalURL,
	}, reqHost)
}

// NewHandler creates a SAML handler. portalURL is where the user-facing
// login lives; empty falls back to issuer (single-domain deploy).
// sessionIdx may be nil — when nil the session index is not persisted
// (degrades gracefully; L3 SLO will simply find nothing to send).
func NewHandler(
	issuer string,
	portalURL string,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
	sessionIdx *SessionIndexStore,
	logger *zap.Logger,
) *Handler {
	if portalURL == "" {
		portalURL = issuer
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Handler{
		issuer:     issuer,
		portalURL:  portalURL,
		appRes:     appRes,
		idRes:      idRes,
		sessRes:    sessRes,
		tenantRes:  tenantRes,
		sessionIdx: sessionIdx,
		logger:     logger,
	}
}

// RegisterRoutes registers SAML endpoints.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	saml := rg.Group("/saml/:app_code")
	{
		saml.GET("/metadata", h.metadata)
		saml.GET("/sso", h.ssoRedirect)
		saml.POST("/sso", h.ssoPost)
		// resume: portal redirects here after login. Carries the
		// in-flight request_id (the SP's AuthnRequest ID, decoded) and
		// relay_state so the response gets the matching InResponseTo
		// attribute. Avoids re-parsing the original SAMLRequest blob.
		saml.GET("/resume", h.ssoResume)
		saml.GET("/slo", h.slo)
		saml.POST("/slo", h.slo)
	}
}

// ssoResume picks up an SP-initiated flow after the user authenticated
// via the portal login page. Required because portal login is on the
// front-end and cannot replay a base64+DEFLATE SAMLRequest blob on its
// own; we pass the decoded ID forward instead.
func (h *Handler) ssoResume(c *gin.Context) {
	appCode := c.Param("app_code")
	requestID := c.Query("request_id")
	relayState := c.Query("relay_state")
	if requestID == "" {
		// No SP-initiated context to resume → behave like IdP-initiated.
		h.idpInitiatedSSO(c, appCode, relayState)
		return
	}
	h.processSSO(c, appCode, requestID, relayState)
}

// metadata returns the IDP metadata for the given application, generated by
// crewjam/saml so it always matches what the SSO handler actually emits.
func (h *Handler) metadata(c *gin.Context) {
	appCode := c.Param("app_code")
	app, err := h.appRes.GetApp(c.Request.Context(), appCode)
	if err != nil || app == nil {
		if err != nil {
			h.logger.Warn("saml metadata: resolve app failed", zap.String("app_code", appCode), zap.Error(err))
		}
		response.NotFound(c, 40401, "application not found")
		return
	}

	_, cert, err := h.loadKeyAndCert(c.Request.Context(), app.ID)
	if err != nil {
		h.logger.Error("saml metadata: load signing cert failed", zap.Int64("app_id", app.ID), zap.Error(err))
		response.InternalError(c, "failed to load signing certificate", err)
		return
	}

	samlCfg := h.parseSAMLConfig(app.ProtocolConfig)
	idp, err := h.newIDP(c, appCode, samlCfg, nil, cert)
	if err != nil {
		h.logger.Error("saml metadata: build idp failed", zap.String("app_code", appCode), zap.Error(err))
		response.InternalError(c, "failed to build SAML metadata", err)
		return
	}

	out, err := xml.MarshalIndent(idp.Metadata(), "", "  ")
	if err != nil {
		h.logger.Error("saml metadata: marshal failed", zap.String("app_code", appCode), zap.Error(err))
		response.InternalError(c, "marshal metadata", err)
		return
	}
	c.Data(http.StatusOK, "application/xml", append([]byte(xml.Header), out...))
}

// loadKeyAndCert loads the app's active signing key + parsed X.509 certificate,
// lazy-minting when absent (matching the legacy behaviour). Used by the crewjam
// IdP for both metadata and response signing.
func (h *Handler) loadKeyAndCert(ctx context.Context, appID int64) (*rsa.PrivateKey, *x509.Certificate, error) {
	opts, err := h.loadSignOptions(ctx, appID)
	if err != nil {
		return nil, nil, err
	}
	der, err := pemCertBytes(opts.CertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("decode cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert: %w", err)
	}
	return opts.Key, cert, nil
}

// newIDP constructs the crewjam IdentityProvider for an app + request, resolving
// the issuer/SSO/SLO URLs by request host.
func (h *Handler) newIDP(c *gin.Context, appCode string, cfg *SAMLConfig, key *rsa.PrivateKey, cert *x509.Certificate) (*crewjam.IdentityProvider, error) {
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	entityID := urls.Issuer
	ssoURL := fmt.Sprintf("%s/protocol/saml/%s/sso", entityID, appCode)
	sloURL := fmt.Sprintf("%s/protocol/saml/%s/slo", entityID, appCode)
	return buildIdentityProvider(cfg, key, cert, entityID, ssoURL, sloURL)
}

// ssoRedirect handles SSO via HTTP-Redirect binding.
func (h *Handler) ssoRedirect(c *gin.Context) {
	appCode := c.Param("app_code")
	samlRequest := c.Query("SAMLRequest")
	relayState := c.Query("RelayState")

	if samlRequest == "" {
		// IDP-Initiated SSO (no AuthnRequest)
		h.idpInitiatedSSO(c, appCode, relayState)
		return
	}

	// Decode SAMLRequest (base64 + deflate for redirect binding)
	requestID, err := extractRequestID(samlRequest)
	if err != nil {
		h.logger.Warn("saml sso (redirect): decode SAMLRequest failed", zap.String("app_code", appCode), zap.Error(err))
		response.BadRequest(c, 40001, "invalid SAMLRequest")
		return
	}

	h.processSSO(c, appCode, requestID, relayState)
}

// ssoPost handles SSO via HTTP-POST binding.
func (h *Handler) ssoPost(c *gin.Context) {
	appCode := c.Param("app_code")
	samlRequest := c.PostForm("SAMLRequest")
	relayState := c.PostForm("RelayState")

	if samlRequest == "" {
		h.idpInitiatedSSO(c, appCode, relayState)
		return
	}

	requestID, err := extractRequestID(samlRequest)
	if err != nil {
		h.logger.Warn("saml sso (post): decode SAMLRequest failed", zap.String("app_code", appCode), zap.Error(err))
		response.BadRequest(c, 40001, "invalid SAMLRequest")
		return
	}

	h.processSSO(c, appCode, requestID, relayState)
}

// processSSO is the shared SSO logic for both bindings.
func (h *Handler) processSSO(c *gin.Context, appCode, requestID, relayState string) {
	app, err := h.appRes.GetApp(c.Request.Context(), appCode)
	if err != nil || app == nil {
		if err != nil {
			h.logger.Warn("saml sso: resolve app failed", zap.String("app_code", appCode), zap.Error(err))
		}
		response.NotFound(c, 40401, "application not found")
		return
	}

	if app.Status != 1 {
		response.Error(c, http.StatusForbidden, 40301, "application is disabled", "")
		return
	}

	samlCfg := h.parseSAMLConfig(app.ProtocolConfig)

	// Session lookup: try the dedicated protocol cookie first, fall back
	// to the portal cookie. IdP-initiated SSO from the portal "我的应用"
	// page lands here with only the portal session present — bouncing
	// such users through /login defeats SSO. Both cookies resolve through
	// the same SessionResolver, so the assertion is built from whichever
	// session is valid.
	var ssoSess *resolver.SSOSession
	if sc, cerr := c.Cookie("mxid_proto_sid"); cerr == nil && sc != "" {
		ssoSess, _ = h.sessRes.GetSSOSession(c.Request.Context(), sc)
	}
	if ssoSess == nil {
		if pc, cerr := c.Cookie("mxid_portal_sid"); cerr == nil && pc != "" {
			ssoSess, _ = h.sessRes.GetSSOSession(c.Request.Context(), pc)
		}
	}
	if ssoSess == nil {
		h.redirectToLogin(c, appCode, requestID, relayState)
		return
	}

	// SSO login confirmation (product rule, Google-style). Only SP-initiated
	// flows confirm — those carry an AuthnRequest (requestID != ""). IdP-initiated
	// portal launches have no AuthnRequest (requestID == "") and stay seamless.
	//   sso_deny=1 → user cancelled: POST a signed SAML error Response (Responder
	//     / AuthnFailed) back to the SP's ACS (spec-compliant, not a bare page).
	//   otherwise consume the one-time token; if absent → bounce to the confirm
	//     page, whose approve replays /resume with sso_confirm and whose cancel
	//     appends sso_deny=1.
	if requestID != "" && h.confirm != nil {
		if c.Query("sso_deny") == "1" {
			h.writeSAMLError(c, appCode, app.ID, samlCfg, requestID, relayState)
			return
		}
		if !h.confirm.Consume(c.Request.Context(), c.Query("sso_confirm"), ssoSess.UserID, app.ID) {
			h.redirectToConsent(c, app.ID, appCode, requestID, relayState)
			return
		}
	}

	// Pin the SSO session's tenant so the user-identity read below is
	// tenant-scoped under the gorm isolation plugin (protocol group has no
	// AuthMiddleware).
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), ssoSess.TenantID))

	// Enforce the app-access policy BEFORE minting an assertion. Without this any
	// authenticated user could obtain a signed SAML assertion for any enabled
	// app, bypassing the admin's per-app allow/deny rules (the OIDC path already
	// enforces this via the bridge). Fail-closed: a checker error or a deny → 403.
	if h.access != nil {
		allowed, reason, aerr := h.access.CheckAppAccess(c.Request.Context(), ssoSess.UserID, app.ID, ssoSess.TenantID)
		if aerr != nil {
			h.logger.Error("saml sso: app-access check failed",
				zap.String("app_code", appCode), zap.Int64("user_id", ssoSess.UserID), zap.Error(aerr))
			response.Error(c, http.StatusForbidden, 40302, "access denied", "")
			return
		}
		if !allowed {
			h.logger.Warn("saml sso: access denied by policy",
				zap.String("app_code", appCode), zap.Int64("user_id", ssoSess.UserID), zap.String("reason", reason))
			response.Error(c, http.StatusForbidden, 40302, "access denied", reason)
			return
		}
	}

	// User authenticated — build assertion
	user, err := h.idRes.ResolveUser(c.Request.Context(), ssoSess.UserID)
	if err != nil {
		h.logger.Error("saml sso: resolve user identity failed",
			zap.String("app_code", appCode), zap.Int64("user_id", ssoSess.UserID), zap.Error(err))
		response.InternalError(c, "failed to resolve user identity", err)
		return
	}

	// Resolve subject according to app.subject_strategy. The strategy wins
	// over the legacy samlCfg.NameIDFormat — shared apps that picked
	// username_suffixed produce safe NameIDs across tenants.
	tenantCode := ""
	if h.tenantRes != nil && user.TenantID > 0 {
		tenantCode, _ = h.tenantRes.GetTenantCode(c.Request.Context(), user.TenantID)
	}
	subj, _ := resolver.ResolveSubject(c.Request.Context(), app.SubjectStrategy, resolver.SubjectInput{
		UserID:     user.ID,
		Username:   user.Username,
		Email:      user.Email,
		TenantID:   user.TenantID,
		TenantCode: tenantCode,
		ClientID:   app.ClientID,
	})
	var nameIDValue string
	if subj != nil && subj.Subject != "" {
		nameIDValue = subj.Subject
	} else {
		nameIDValue = h.resolveNameID(samlCfg.NameIDFormat, user)
	}

	// Build attribute map (adds tenant_code + adjusted username for cross-tenant disambiguation).
	attrs := h.buildAttributes(samlCfg, user)
	if tenantCode != "" {
		attrs["tenant_code"] = tenantCode
	}
	if subj != nil && subj.DisplayUsername != "" {
		attrs["username"] = subj.DisplayUsername
	}

	// Effective app roles (JIT elevations first) → emitted as a multi-value
	// attribute. Best-effort: a lookup failure just omits the role attribute.
	var roleCodes []string
	if h.appRoles != nil {
		roleCodes, _ = h.appRoles.ResolveAppRoles(c.Request.Context(), ssoSess.UserID, app.ID, ssoSess.TenantID)
	}

	h.emitCrewjamResponse(c, appCode, app.ID, ssoSess.UserID, samlCfg, requestID, relayState, nameIDValue, attrs, roleCodes)
}

// emitCrewjamResponse builds and writes the SAML Response via crewjam/saml,
// which signs the assertion (and response), handles NameID / Conditions /
// element ordering / canonicalisation, and renders the auto-submit POST form.
// Handles both SP-initiated (requestID set) and IdP-initiated (empty) flows.
func (h *Handler) emitCrewjamResponse(c *gin.Context, appCode string, appID, userID int64, samlCfg *SAMLConfig, requestID, relayState, nameIDValue string, attrs map[string]string, roleCodes []string) {
	key, cert, err := h.loadKeyAndCert(c.Request.Context(), appID)
	if err != nil {
		h.logger.Error("saml sso: load signing key failed", zap.Int64("app_id", appID), zap.Error(err))
		response.InternalError(c, "failed to load signing key", err)
		return
	}
	idp, err := h.newIDP(c, appCode, samlCfg, key, cert)
	if err != nil {
		h.logger.Error("saml sso: build idp failed", zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
		response.InternalError(c, "failed to build SAML identity provider", err)
		return
	}

	now := time.Now()
	customAttrs := attrsToCrewjam(attrs)
	if len(roleCodes) > 0 {
		roleAttr := samlCfg.RoleAttribute
		if roleAttr == "" {
			roleAttr = "roles"
		}
		vals := make([]crewjam.AttributeValue, len(roleCodes))
		for i, rc := range roleCodes {
			vals[i] = crewjam.AttributeValue{Type: "xs:string", Value: rc}
		}
		customAttrs = append(customAttrs, crewjam.Attribute{
			Name:       roleAttr,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     vals,
		})
	}
	session := &crewjam.Session{
		ID:               uuid.NewString(),
		CreateTime:       now,
		ExpireTime:       now.Add(time.Duration(samlCfg.SessionTTL) * time.Second),
		Index:            uuid.NewString(),
		NameID:           nameIDValue,
		NameIDFormat:     samlCfg.NameIDFormat,
		CustomAttributes: customAttrs,
	}

	// The raw SAMLRequest blob is only present on the SP's initial hit
	// (ssoRedirect/ssoPost). After a login or confirm bounce the flow resumes via
	// /resume (request_id only, no blob), and the login-confirm feature always
	// routes SP-initiated logins through /resume. So parse the blob only when it
	// is actually here; otherwise build the request manually (below) and stamp
	// the request ID so the Response still carries InResponseTo.
	hasRawRequest := c.Query("SAMLRequest") != "" || c.PostForm("SAMLRequest") != ""

	var req *crewjam.IdpAuthnRequest
	if requestID != "" && hasRawRequest {
		// SP-initiated with the AuthnRequest in hand: parse + validate it.
		req, err = crewjam.NewIdpAuthnRequest(idp, c.Request)
		if err != nil {
			h.logger.Warn("saml sso: parse AuthnRequest failed",
				zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
			response.BadRequest(c, 40001, "invalid SAML AuthnRequest")
			return
		}
		if err := req.Validate(); err != nil {
			h.logger.Warn("saml sso: validate AuthnRequest failed",
				zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
			response.BadRequest(c, 40001, "SAML AuthnRequest validation failed")
			return
		}
	} else {
		// No AuthnRequest blob: IdP-initiated (requestID == "") OR an SP-initiated
		// resume/confirm replay (requestID != ""). Assemble the request + ACS from
		// the SP's registered metadata — the assertion always targets the
		// configured ACS, never a request-supplied one.
		req = &crewjam.IdpAuthnRequest{IDP: idp, HTTPRequest: c.Request, RelayState: relayState, Now: now}
		req.ServiceProviderMetadata, err = idp.ServiceProviderProvider.GetServiceProvider(c.Request, samlCfg.SPEntityID)
		if err != nil {
			h.logger.Error("saml sso (idp-initiated): resolve sp metadata failed",
				zap.String("app_code", appCode), zap.Int64("app_id", appID),
				zap.String("sp_entity_id", samlCfg.SPEntityID), zap.Error(err))
			response.InternalError(c, "failed to resolve service provider metadata", err)
			return
		}
		for di := range req.ServiceProviderMetadata.SPSSODescriptors {
			desc := &req.ServiceProviderMetadata.SPSSODescriptors[di]
			acs := desc.AssertionConsumerServices
			for ai := range acs {
				if acs[ai].Binding == crewjam.HTTPPostBinding {
					// MakeAssertion derefs req.SPSSODescriptor (for
					// AttributeConsumingServices); SP-initiated gets it
					// from Validate(), so IdP-initiated must set it too or
					// MakeAssertion nil-panics.
					req.SPSSODescriptor = desc
					req.ACSEndpoint = &acs[ai]
					break
				}
			}
			if req.ACSEndpoint != nil {
				break
			}
		}
		if req.ACSEndpoint == nil {
			h.logger.Warn("saml sso (idp-initiated): no POST ACS endpoint for SP",
				zap.String("app_code", appCode), zap.Int64("app_id", appID),
				zap.String("sp_entity_id", samlCfg.SPEntityID))
			response.InternalError(c, "no compatible assertion consumer endpoint for this application")
			return
		}
		// SP-initiated resume/confirm replay: stamp the original AuthnRequest ID so
		// the Response carries InResponseTo, and an IssueInstant so the assertion's
		// NotBefore is derived sanely (IdP-initiated leaves both zero-valued).
		if requestID != "" {
			req.Request.ID = requestID
			req.Request.IssueInstant = now
		}
	}

	if err := (crewjam.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		h.logger.Error("saml sso: make assertion failed",
			zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
		response.InternalError(c, "failed to build SAML assertion", err)
		return
	}

	// Record the session index for IdP-initiated SLO (Task L3).
	// Best-effort: a Redis failure must not block the SSO response.
	if h.sessionIdx != nil {
		sessionTTL := time.Duration(samlCfg.SessionTTL) * time.Second
		if sessionTTL <= 0 {
			sessionTTL = 8 * time.Hour
		}
		ref := SAMLSessionRef{
			SessionIndex: session.Index,
			NameID:       session.NameID,
			SPEntityID:   samlCfg.SPEntityID,
			// Captured from the crewjam Session actually used to build this
			// assertion (session.NameIDFormat, set a few lines above from
			// samlCfg.NameIDFormat at assertion time) rather than re-read from
			// config later at SLO time, so a config change between SSO and
			// logout can't desync the LogoutRequest's NameID format from what
			// the SP was actually given.
			NameIDFormat: session.NameIDFormat,
		}
		if rerr := h.sessionIdx.Record(c.Request.Context(), userID, appID, ref, sessionTTL); rerr != nil {
			// Log but do not abort — SSO must succeed even if the index store is
			// down. The only cost is that IdP-initiated SLO can't reach this
			// session later.
			h.logger.Warn("saml: record session index failed",
				zap.Int64("user_id", userID), zap.Int64("app_id", appID), zap.Error(rerr))
		}
	}

	if err := req.WriteResponse(c.Writer); err != nil {
		h.logger.Error("saml sso: write saml response failed",
			zap.String("app_code", appCode), zap.Int64("app_id", appID), zap.Error(err))
		response.InternalError(c, "failed to write SAML response", err)
		return
	}
}

// idpInitiatedSSO handles IDP-Initiated SSO (no AuthnRequest).
func (h *Handler) idpInitiatedSSO(c *gin.Context, appCode, relayState string) {
	h.processSSO(c, appCode, "", relayState)
}

// slo handles Single Logout.
//
// Open-redirect hardening:
//  1. Parse Issuer from the SAML LogoutRequest (if present) and look up
//     the SP's configured SLOURL / ACSURL.
//  2. RelayState is only followed when:
//     (a) it matches the SP's SLOURL host exactly, OR
//     (b) the SP cannot be identified (no SAMLRequest, malformed XML)
//     AND the URL passes the baseline shape check.
//
// Without (a) the spec-allowed "return RelayState to the user agent" turns
// into an open redirect because RelayState is attacker-controlled.
func (h *Handler) slo(c *gin.Context) {
	// Authenticate an SP-initiated LogoutRequest BEFORE tearing down the SSO
	// session or emitting a signed LogoutResponse. When the SP has a signing
	// cert on file, a valid HTTP-Redirect binding signature is mandatory — a
	// forged/unsigned LogoutRequest must not log the user out (logout CSRF) or
	// elicit a signed LogoutResponse we could be tricked into reflecting.
	if err := h.verifySPLogoutRequestSig(c); err != nil {
		response.BadRequest(c, 40008, "invalid LogoutRequest signature")
		return
	}

	sessionCookie, _ := c.Cookie("mxid_proto_sid")

	if sessionCookie != "" {
		_ = h.sessRes.DeleteSSOSession(c.Request.Context(), sessionCookie)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("mxid_proto_sid", "", -1, "/", "", false, true)
	}

	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.PostForm("RelayState")
	}

	// SP-initiated SLO: a LogoutRequest is present. Answer with a signed
	// SAML LogoutResponse posted to the SP's SLS (HTTP-Redirect binding) so
	// the SP completes its own logout instead of hanging on the request.
	if redirectURL, ok := h.sloResponseRedirect(c, relayState); ok {
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// IdP-initiated / plain logout: no LogoutRequest to answer. Honour a
	// safe RelayState redirect, else report success.
	if relayState != "" && h.isAllowedSLORedirect(c, relayState) {
		c.Redirect(http.StatusFound, relayState)
		return
	}

	response.OK(c, gin.H{"message": "logged out"})
}

// verifySPLogoutRequestSig authenticates an SP-initiated LogoutRequest over the
// HTTP-Redirect binding. It returns nil (allow) when there is no LogoutRequest,
// when the SP can't be resolved, or when the SP has no signing cert configured
// (legacy SPs that don't sign logout — nothing to verify against). When a cert
// IS configured, a valid RSA-SHA256 redirect-binding signature is required and
// any missing/invalid signature is a hard error.
//
// Only the redirect binding (query-param signature) is authenticated here; a
// POST-binding LogoutRequest carries an enveloped XML signature instead, which
// is out of scope for this check.
func (h *Handler) verifySPLogoutRequestSig(c *gin.Context) error {
	if c.Query("SAMLRequest") == "" {
		return nil // no redirect-binding LogoutRequest to authenticate
	}
	app, err := h.appRes.GetApp(c.Request.Context(), c.Param("app_code"))
	if err != nil || app == nil {
		return nil // unknown SP — no cert to verify against; treat as plain logout
	}
	samlCfg := h.parseSAMLConfig(app.ProtocolConfig)
	if samlCfg.SPCert == "" {
		return nil // no SP cert on file — cannot verify, legacy allow
	}
	return verifyRedirectSignature(c.Request.URL.RawQuery, samlCfg.SPCert)
}

// sloResponseRedirect builds the SP SLS redirect URL carrying a signed SAML
// LogoutResponse for an SP-initiated SLO. Returns ("", false) when there is no
// LogoutRequest to answer, or the SP / signing material can't be resolved — the
// caller then falls back to a plain logout.
func (h *Handler) sloResponseRedirect(c *gin.Context, relayState string) (string, bool) {
	encoded := c.Query("SAMLRequest")
	if encoded == "" {
		encoded = c.PostForm("SAMLRequest")
	}
	if encoded == "" {
		return "", false
	}

	requestID, err := extractRequestID(encoded)
	if err != nil {
		return "", false
	}

	app, err := h.appRes.GetApp(c.Request.Context(), c.Param("app_code"))
	if err != nil || app == nil {
		return "", false
	}
	samlCfg := h.parseSAMLConfig(app.ProtocolConfig)
	if samlCfg.SLOURL == "" {
		return "", false
	}

	key, _, err := h.loadKeyAndCert(c.Request.Context(), app.ID)
	if err != nil {
		return "", false
	}

	issuer := h.resolveURLs(c.Request.Context(), c.Request.Host).Issuer
	redirectURL, err := buildLogoutResponseRedirect(samlCfg.SLOURL, issuer, requestID, relayState, key)
	if err != nil {
		return "", false
	}
	return redirectURL, true
}

// isAllowedSLORedirect runs the layered SLO redirect check described on
// slo(). The host-match against the SP's SLOURL is the load-bearing
// guarantee; the baseline-shape fallback only fires when no SP context
// is available and exists to keep dev / metadata-less flows working.
func (h *Handler) isAllowedSLORedirect(c *gin.Context, relayState string) bool {
	target, err := url.Parse(relayState)
	if err != nil || !isSafeSLORedirect(relayState) {
		return false
	}

	app := h.lookupSLOIssuer(c)
	if app == nil {
		// FAIL-CLOSED: the SP could not be identified (no/ malformed
		// SAMLRequest, or an Issuer that doesn't resolve to a known app),
		// so there is no registered SLO/ACS URL to bind RelayState to. We
		// must NOT redirect — an attacker can otherwise just omit the
		// SAMLRequest (plain GET /slo?RelayState=https://evil) to land in
		// this branch. The caller renders the local logged-out page.
		return false
	}

	// SP is known: RelayState must match the SP's registered SLO/ACS URL on
	// scheme + host. This binds the landing target to the SP that initiated
	// the logout instead of accepting any https host.
	samlCfg := h.parseSAMLConfig(app.ProtocolConfig)
	for _, candidate := range []string{samlCfg.SLOURL, samlCfg.ACSURL} {
		regURL, err := url.Parse(candidate)
		if err != nil || regURL.Host == "" {
			continue
		}
		if strings.EqualFold(regURL.Host, target.Host) &&
			strings.EqualFold(regURL.Scheme, target.Scheme) {
			return true
		}
	}
	return false
}

// lookupSLOIssuer pulls the SAMLRequest off the SLO request, extracts the
// Issuer element and resolves it to an AppConfig. Returns nil on any
// failure — caller treats that as "unknown SP" and falls back to the
// baseline shape check.
func (h *Handler) lookupSLOIssuer(c *gin.Context) *resolver.AppConfig {
	encoded := c.Query("SAMLRequest")
	if encoded == "" {
		encoded = c.PostForm("SAMLRequest")
	}
	if encoded == "" {
		return nil
	}
	issuer, err := extractRequestIssuer(encoded)
	if err != nil || issuer == "" {
		return nil
	}
	// AppResolver.GetApp uses identifier (code OR client_id OR
	// entity_id); the SP's SAML EntityID lives in protocol_config.
	// We probe by entity_id via the resolver's ProtocolConfig scan if
	// available; otherwise the lookup returns nil and we fall back.
	app, err := h.appRes.GetApp(c.Request.Context(), issuer)
	if err != nil {
		return nil
	}
	return app
}

// extractRequestIssuer decodes a SAML LogoutRequest / AuthnRequest and
// returns the saml:Issuer string. Same encoding sandwich as
// extractRequestID — pulls a different element. Returns empty when the
// payload does not carry an issuer.
func extractRequestIssuer(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(encoded); err != nil {
			if decoded, err = base64.URLEncoding.DecodeString(encoded); err != nil {
				if decoded, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
					return "", fmt.Errorf("decode SAMLRequest base64: %w", err)
				}
			}
		}
	}
	xmlBytes := decoded
	if inflated, ierr := io.ReadAll(flate.NewReader(bytes.NewReader(decoded))); ierr == nil && len(inflated) > 0 {
		xmlBytes = inflated
	}
	type request struct {
		Issuer string `xml:"Issuer"`
	}
	var req request
	if err := safeXMLDecode(xmlBytes, &req); err != nil {
		return "", fmt.Errorf("parse LogoutRequest: %w", err)
	}
	return strings.TrimSpace(req.Issuer), nil
}

// isSafeSLORedirect rejects schemes / shapes that turn the SLO endpoint
// into an open-redirect oracle. It does NOT verify that the target is a
// registered SP — SAML metadata stores SLOURL per app but the SLO request
// here lacks the issuer context to look it up reliably. This is the OWASP
// "block obviously dangerous shapes" baseline; high-assurance deployments
// should additionally check that the host appears in some app's SLOURL.
func isSafeSLORedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return false
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// Helper methods

func (h *Handler) parseSAMLConfig(raw json.RawMessage) *SAMLConfig {
	cfg := Defaults()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, cfg)
	}
	return cfg
}

func (h *Handler) resolveNameID(format string, user *resolver.IdentityInfo) string {
	switch format {
	case NameIDEmail:
		return user.Email
	case NameIDPersistent:
		return fmt.Sprintf("%d", user.ID)
	default:
		return user.Username
	}
}

func (h *Handler) buildAttributes(cfg *SAMLConfig, user *resolver.IdentityInfo) map[string]string {
	attrs := make(map[string]string)
	userMap := map[string]string{
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"phone":        user.Phone,
		"avatar":       user.Avatar,
	}

	for userAttr, samlAttr := range cfg.AttributeMapping {
		if val, ok := userMap[userAttr]; ok && val != "" {
			attrs[samlAttr] = val
		}
	}
	return attrs
}

// loadSignOptions fetches the active signing cert for the app and
// returns parsed key + PEM. Private key is master-key-decrypted upstream
// by the cert adapter; here we just parse PEM into *rsa.PrivateKey.
func (h *Handler) loadSignOptions(ctx context.Context, appID int64) (*SignOptions, error) {
	certs, err := h.appRes.ListCerts(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	if len(certs) == 0 {
		// Lazy mint to match metadata handler behaviour — operators expect
		// signing to "just work" once an app exists.
		minted, mErr := h.appRes.MintSigningCert(ctx, appID)
		if mErr != nil {
			return nil, fmt.Errorf("mint signing cert: %w", mErr)
		}
		certs = []*resolver.CertConfig{minted}
	}
	c := certs[0]
	block, _ := pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("private key PEM not decodable")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if any, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		if key, ok = any.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("private key not RSA")
		}
	} else {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return &SignOptions{Key: key, CertPEM: c.PublicKey}, nil
}

func (h *Handler) redirectToLogin(c *gin.Context, appCode, requestID, relayState string) {
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	base := urls.Portal
	if base == "" {
		base = urls.Issuer
	}
	loginURL := fmt.Sprintf("%s/login?protocol=saml&app_code=%s&request_id=%s&relay_state=%s",
		base, appCode, requestID, relayState)
	c.Redirect(http.StatusFound, loginURL)
}

// extractRequestID decodes a SAMLRequest and extracts the ID attribute.
//
// Encoding sandwich per SAML 2.0 bindings (§3.4.4.1 for HTTP-Redirect,
// §3.5.4 for HTTP-POST):
//
//	HTTP-Redirect: DEFLATE → base64 → URL-encode
//	HTTP-POST:     base64 → form-encode (no DEFLATE)
//
// We try multiple base64 alphabets (std + URL + raw) so a buggy SP that
// chose the wrong variant still works. After base64-decode we attempt
// DEFLATE inflate; if it fails we treat the bytes as the raw XML (POST
// binding path) and parse directly.
func extractRequestID(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(encoded); err != nil {
			if decoded, err = base64.URLEncoding.DecodeString(encoded); err != nil {
				if decoded, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
					return "", fmt.Errorf("decode SAMLRequest base64: %w", err)
				}
			}
		}
	}

	// Try DEFLATE inflate (HTTP-Redirect). flate.NewReader expects raw
	// deflate stream with no zlib wrapper — exactly what SAML 2.0 specifies.
	xmlBytes := decoded
	if inflated, ierr := io.ReadAll(flate.NewReader(bytes.NewReader(decoded))); ierr == nil && len(inflated) > 0 {
		xmlBytes = inflated
	}

	type AuthnRequest struct {
		ID string `xml:"ID,attr"`
	}
	var req AuthnRequest
	if err := safeXMLDecode(xmlBytes, &req); err != nil {
		return "", fmt.Errorf("parse AuthnRequest: %w", err)
	}
	if req.ID == "" {
		return "", fmt.Errorf("AuthnRequest missing ID attribute")
	}
	return req.ID, nil
}
