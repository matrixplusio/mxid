package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/safehttp"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/imkerbos/mxid/pkg/urlswap"
	"golang.org/x/crypto/bcrypt"
)

// ConsentChecker queries previously-granted scope consents. Implemented by
// the consent domain service; kept as a narrow interface here so the
// protocol package does not import the consent package directly.
type ConsentChecker interface {
	HasAll(ctx context.Context, tenantID, userID, appID int64, requested []string) (bool, error)
}

// userStatusActive mirrors user.StatusActive (1). Duplicated as a local const
// so the protocol layer doesn't import the user domain just to gate the
// refresh grant on account status.
const userStatusActive = 1

// httpDoer is the minimal interface used by sendBackchannelLogout so tests can
// substitute a plain http.Client while production always uses the SSRF-safe
// backchannelLogoutClient package var.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Handler serves OIDC protocol endpoints.
type Handler struct {
	issuer      string
	portalURL   string // SPA base URL for login / consent redirects
	urlProvider urlswap.Provider
	appRes      resolver.AppResolver
	idRes       resolver.IdentityResolver
	sessRes     resolver.SessionResolver
	tenantRes   resolver.TenantResolver
	consent     ConsentChecker
	access      AccessChecker
	appRoles    AppRoleResolver
	sessionMgr  *session.Manager
	store       *Store
	tokenIss    *TokenIssuer
	eventBus    *event.Bus
	// backchannelClient overrides the package-level backchannelLogoutClient
	// when non-nil. Used in tests to bypass the SSRF guard so an httptest RP
	// on loopback can receive logout_tokens.
	backchannelClient httpDoer
}

// SetURLProvider wires the runtime URL lookup. Empty / nil → stick with
// the issuer + portal URL captured at construction.
func (h *Handler) SetURLProvider(p urlswap.Provider) { h.urlProvider = p }

func (h *Handler) resolveURLs(ctx context.Context, reqHost string) urlswap.URLs {
	return urlswap.Resolve(ctx, h.urlProvider, urlswap.URLs{
		Issuer: h.issuer,
		Portal: h.portalURL,
	}, reqHost)
}

// AccessChecker is the contract /authorize uses to enforce per-app
// authorization. Lives in oidc package so we don't pull appaccess as a
// hard dependency — the appaccess module satisfies this via a thin
// adapter wired in main.go.
//
// Allowed=false → redirect with error or to a portal "no access" page.
// Reason should be human-readable enough to render in UI / log lines.
type AccessChecker interface {
	CheckAppAccess(ctx context.Context, userID, appID, tenantID int64) (allowed bool, reason string, err error)
}

// AppRoleResolver returns the role codes the user has for a given app.
// Emitted as the `app_roles` claim in id_token / userinfo so SPs can
// read them without writing JMESPath against the raw `groups` claim.
//
// Implemented by the approle module via a thin adapter in main.go.
type AppRoleResolver interface {
	ResolveAppRoles(ctx context.Context, userID, appID, tenantID int64) ([]string, error)
}

// NewHandler creates an OIDC handler.
//
// portalURL is the externally-reachable base of the portal SPA. Defaults
// to issuer when empty (prod single-domain mode); set explicitly in dev
// where Vite serves the portal on a separate port.
func NewHandler(
	issuer string,
	portalURL string,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
	consentChecker ConsentChecker,
	accessChecker AccessChecker,
	appRolesResolver AppRoleResolver,
	sessionMgr *session.Manager,
	store *Store,
	eventBus *event.Bus,
) *Handler {
	if portalURL == "" {
		portalURL = issuer
	}
	return &Handler{
		issuer:     issuer,
		portalURL:  portalURL,
		appRes:     appRes,
		idRes:      idRes,
		sessRes:    sessRes,
		tenantRes:  tenantRes,
		consent:    consentChecker,
		access:     accessChecker,
		appRoles:   appRolesResolver,
		sessionMgr: sessionMgr,
		store:      store,
		tokenIss:   NewTokenIssuer(issuer),
		eventBus:   eventBus,
	}
}

// resolveSubject computes the sub + display username + tenant_code for a
// token issuance. Pulls tenant code from TenantResolver, then delegates to
// resolver.ResolveSubject which applies the app's subject_strategy. Returns
// sane defaults on errors so token issuance never fails purely on lookup.
func (h *Handler) resolveSubject(ctx context.Context, app *resolver.AppConfig, info *resolver.IdentityInfo) *resolver.SubjectOutput {
	if app == nil || info == nil {
		return &resolver.SubjectOutput{Subject: ""}
	}
	tenantCode := ""
	if h.tenantRes != nil && info.TenantID > 0 {
		tenantCode, _ = h.tenantRes.GetTenantCode(ctx, info.TenantID)
	}
	out, err := resolver.ResolveSubject(ctx, app.SubjectStrategy, resolver.SubjectInput{
		UserID:     info.ID,
		Username:   info.Username,
		Email:      info.Email,
		TenantID:   info.TenantID,
		TenantCode: tenantCode,
		ClientID:   app.ClientID,
	})
	if err != nil || out == nil {
		// Fall back to opaque snowflake id — strictly safer than crashing.
		return &resolver.SubjectOutput{
			Subject:         strconv.FormatInt(info.ID, 10),
			DisplayUsername: info.Username,
			TenantCode:      tenantCode,
		}
	}
	return out
}

// emitAudit fires-and-forgets an OIDC token-lifecycle event onto the event
// bus. The audit domain subscribes and persists it to mxid_audit_log.
// Nil-safe: when the bus is not wired (tests / partial setups), the call
// silently no-ops.
func (h *Handler) emitAudit(ctx context.Context, eventType string, payload map[string]any) {
	if h.eventBus == nil {
		return
	}
	h.eventBus.Publish(ctx, event.Event{Type: eventType, Payload: payload})
}

// RegisterRoutes registers OIDC endpoints under the protocol group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	oidc := rg.Group("/oidc")
	{
		oidc.GET("/.well-known/openid-configuration", h.discovery)
		oidc.GET("/authorize", h.authorize)
		oidc.POST("/authorize", h.authorize)
		oidc.POST("/token", h.token)
		oidc.GET("/userinfo", h.userinfo)
		oidc.POST("/userinfo", h.userinfo)
		oidc.GET("/jwks", h.jwks)
		oidc.POST("/revoke", h.revoke)
		oidc.POST("/introspect", h.introspect)
		oidc.GET("/end-session", h.endSession)
	}
}

// discovery returns the OpenID Provider Configuration per OIDC Discovery 1.0.
//
// Milestone A capability set:
//   - response_types_supported: code only (auth code flow)
//   - grant_types_supported: authorization_code + refresh_token + client_credentials
//   - subject_types_supported: public only (pairwise lands in C)
//   - id_token_signing_alg_values_supported: RS256
//   - token_endpoint_auth_methods_supported: client_secret_basic, client_secret_post, none (PKCE-only public client)
//   - code_challenge_methods_supported: S256 only — `plain` is rejected to
//     align with OAuth 2.0 Security BCP §2.1.1 (OAuth 2.1 draft mandates this).
func (h *Handler) discovery(c *gin.Context) {
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	iss := urls.Issuer
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/protocol/oidc/authorize",
		"token_endpoint":                        iss + "/protocol/oidc/token",
		"userinfo_endpoint":                     iss + "/protocol/oidc/userinfo",
		"jwks_uri":                              iss + "/protocol/oidc/jwks",
		"revocation_endpoint":                   iss + "/protocol/oidc/revoke",
		"introspection_endpoint":                iss + "/protocol/oidc/introspect",
		"end_session_endpoint":                  iss + "/protocol/oidc/end-session",
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "groups", "offline_access"},
		"response_types_supported": []string{
			"code",
			"id_token",
			"token id_token",
			"code id_token",
			"code token",
			"code id_token token",
		},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported":              []string{"client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "HS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"at_hash", "c_hash", "azp", "amr", "acr",
			"name", "preferred_username", "picture", "locale", "updated_at",
			"email", "email_verified",
			"phone_number", "phone_number_verified",
			"groups",
		},
		// Back-channel logout (OpenID Connect Back-Channel Logout 1.0)
		"backchannel_logout_supported":         true,
		"backchannel_logout_session_supported": true,
	})
}

// authorize handles the authorization endpoint.
func (h *Handler) authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if clientID == "" || redirectURI == "" || responseType == "" {
		response.BadRequest(c, 40001, "missing required parameters: client_id, redirect_uri, response_type")
		return
	}

	// FAIL-CLOSED open-redirect guard: nothing below may redirect to
	// redirect_uri until it has been proven to belong to the resolved app's
	// registered allow-list. So we resolve the client and validate
	// redirect_uri FIRST. Any error before this point — unknown client_id,
	// unsupported response_type, disabled app — is rendered as a LOCAL HTTP
	// 400, NEVER as a redirect to the attacker-supplied redirect_uri.
	//
	// Resolve app by client_id. An unknown client_id has no allow-list to
	// validate against at all, so it can only ever be a local error.
	app, err := h.appRes.GetAppByClientID(c.Request.Context(), clientID)
	if err != nil || app == nil {
		response.BadRequest(c, 40002, "invalid_request")
		return
	}

	// Validate redirect_uri against THIS app's registered URIs before any
	// branch that would redirectError() to it.
	if !h.isValidRedirectURI(app, redirectURI) {
		response.BadRequest(c, 40002, "invalid redirect_uri")
		return
	}

	// From here on redirect_uri is pinned to the app's allow-list, so
	// redirectError() is a safe (registered-target) redirect.
	rtParts := parseResponseType(responseType)
	if !isResponseTypeSupported(rtParts) {
		h.redirectError(c, redirectURI, state, "unsupported_response_type", "response_type not supported")
		return
	}
	wantCode := rtParts["code"]
	wantIDToken := rtParts["id_token"]
	wantToken := rtParts["token"]

	if app.Status != 1 {
		h.redirectError(c, redirectURI, state, "access_denied", "application is disabled")
		return
	}

	// Parse OIDC config
	oidcCfg := h.parseOIDCConfig(app.ProtocolConfig)

	// PKCE — required when configured; mandatory for public clients (spa/native).
	publicClient := isPublicClient(app)
	if (oidcCfg.PKCERequired || publicClient) && codeChallenge == "" {
		h.redirectError(c, redirectURI, state, "invalid_request", "code_challenge required")
		return
	}
	// Reject deprecated `plain` method (OAuth 2.0 Security BCP §2.1.1; OAuth 2.1 mandates S256).
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		if codeChallengeMethod != "S256" {
			h.redirectError(c, redirectURI, state, "invalid_request", "code_challenge_method must be S256")
			return
		}
	}

	// prompt parameter handling (OIDC Core §3.1.2.1)
	prompt := c.Query("prompt")
	forceLogin := prompt == "login"

	// Check protocol session
	sessionCookie, err := c.Cookie("mxid_proto_sid")
	var ssoSess *resolver.SSOSession
	if !forceLogin && err == nil && sessionCookie != "" {
		ssoSess, _ = h.sessRes.GetSSOSession(c.Request.Context(), sessionCookie)
	}
	if ssoSess == nil {
		if prompt == "none" {
			h.redirectError(c, redirectURI, state, "login_required", "no active session")
			return
		}
		h.redirectToLogin(c, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
		return
	}

	// User authenticated — pin the SSO session's tenant onto the request
	// context so the downstream access-policy / consent / app-role reads (all
	// tenant-scoped tables) run under the gorm tenant-isolation plugin. The
	// protocol group has no AuthMiddleware to set this.
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), ssoSess.TenantID))

	// User authenticated — issue authorization code
	scopes := parseScopes(scope)

	// App access policy check.
	//
	// Runs BEFORE consent because if the user can't access the app at all,
	// there's no point asking them to consent to scopes. Result `reason`
	// is surfaced to the portal "no access" page so the user understands
	// why (e.g. "no group membership matches").
	if h.access != nil {
		allowed, reason, err := h.access.CheckAppAccess(c.Request.Context(), ssoSess.UserID, app.ID, ssoSess.TenantID)
		if err != nil {
			h.redirectError(c, redirectURI, state, "server_error", "access policy check failed")
			return
		}
		if !allowed {
			// Redirect to a portal page so the user gets a friendly message
			// instead of a JSON 403 from the SP redirect_uri.
			urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
			c.Redirect(http.StatusFound, urls.Portal+"/no-access?app="+app.Code+"&reason="+reason)
			return
		}
	}

	// Consent check (OIDC Core §3.1.2.4).
	// require_consent=true OR third-party app forces explicit user grant.
	// First-party apps with require_consent=false skip the prompt — matches
	// Auth0 / Okta first-party app behavior.
	if h.consent != nil && (app.RequireConsent || !app.IsFirstParty()) {
		ok, err := h.consent.HasAll(c.Request.Context(), ssoSess.TenantID, ssoSess.UserID, app.ID, scopes)
		if err != nil {
			h.redirectError(c, redirectURI, state, "server_error", "consent check failed")
			return
		}
		if !ok {
			if prompt == "none" {
				h.redirectError(c, redirectURI, state, "interaction_required", "consent required")
				return
			}
			h.redirectToConsent(c, app.ID, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
			return
		}
	}

	// Issue the response components dictated by response_type. Hybrid +
	// implicit flows return tokens directly in the URL fragment; pure auth
	// code flow returns only the code in the query string.
	respParams := map[string]string{}
	if state != "" {
		respParams["state"] = state
	}

	var codeStr string
	if wantCode {
		ac, err := h.store.CreateAuthCode(c.Request.Context(), &AuthCodeRequest{
			ClientID:            clientID,
			UserID:              ssoSess.UserID,
			TenantID:            ssoSess.TenantID,
			RedirectURI:         redirectURI,
			Scopes:              scopes,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			AuthTime:            ssoSess.CreatedAt.Unix(),
			AuthMethod:          ssoSess.AuthType,
			TTL:                 oidcCfg.AuthCodeTTL,
		})
		if err != nil {
			h.redirectError(c, redirectURI, state, "server_error", "failed to create authorization code")
			return
		}
		codeStr = ac.Code
		respParams["code"] = codeStr
	}

	// Track this app's participation in the SSO session for later
	// back-channel logout fan-out. Best effort.
	_ = h.store.TrackSSOApp(c.Request.Context(), sessionCookie, app.ID, time.Until(ssoSess.ExpiresAt))

	// For hybrid / implicit, mint id_token and/or access_token at /authorize.
	if wantIDToken || wantToken {
		key, kid, err := h.loadSigningKey(c, app.ID)
		if err != nil {
			h.redirectError(c, redirectURI, state, "server_error", "signing key unavailable")
			return
		}
		// Compute subject once for both AT and ID token at the authorize step.
		var hybridInfo *resolver.IdentityInfo
		hybridInfo, _ = h.idRes.ResolveUser(c.Request.Context(), ssoSess.UserID)
		hybridSubj := h.resolveSubject(c.Request.Context(), app, hybridInfo)

		var atTok string
		if wantToken {
			at, err := h.tokenIss.IssueAccessToken(&AccessTokenClaims{
				UserID:    ssoSess.UserID,
				TenantID:  ssoSess.TenantID,
				ClientID:  clientID,
				Scopes:    scopes,
				ExpiresIn: time.Duration(oidcCfg.AccessTokenTTL) * time.Second,
				Subject:   hybridSubj.Subject,
			}, key, kid)
			if err != nil {
				h.redirectError(c, redirectURI, state, "server_error", "failed to issue access token")
				return
			}
			atTok = at
			respParams["access_token"] = at
			respParams["token_type"] = "Bearer"
			respParams["expires_in"] = fmt.Sprintf("%d", oidcCfg.AccessTokenTTL)
		}
		if wantIDToken {
			claimsMap, _ := h.idRes.ResolveClaims(c.Request.Context(), ssoSess.UserID, scopes)
			if hybridInfo != nil {
				applyClaimMappers(claimsMap, oidcCfg.ClaimMappers, hybridInfo, scopes)
			}
			if hybridSubj.TenantCode != "" {
				claimsMap["tenant_code"] = hybridSubj.TenantCode
			}
			if hybridSubj.DisplayUsername != "" {
				claimsMap["preferred_username"] = hybridSubj.DisplayUsername
			}
			if h.appRoles != nil {
				if roleCodes, err := h.appRoles.ResolveAppRoles(c.Request.Context(), ssoSess.UserID, app.ID, ssoSess.TenantID); err == nil && len(roleCodes) > 0 {
					claimsMap["app_roles"] = roleCodes
				}
			}
			idTok, err := h.tokenIss.IssueIDToken(&IDTokenClaims{
				UserID:            ssoSess.UserID,
				ClientID:          clientID,
				Subject:           hybridSubj.Subject,
				Nonce:             nonce,
				Scopes:            scopes,
				Extra:             claimsMap,
				ExpiresIn:         idTokenTTLFromConfig(oidcCfg),
				AuthTime:          ssoSess.CreatedAt.Unix(),
				AMR:               authMethodToAMR(ssoSess.AuthType),
				ACR:               "0",
				AccessToken:       atTok,
				AuthorizationCode: codeStr,
			}, key, kid)
			if err != nil {
				h.redirectError(c, redirectURI, state, "server_error", "failed to issue id_token")
				return
			}
			respParams["id_token"] = idTok
		}
	}

	h.redirectAuthorizeResponse(c, redirectURI, respParams, wantIDToken || wantToken)
}

// redirectAuthorizeResponse encodes the authorize response parameters into
// the redirect URI per OIDC Core §3.1.2.5 / §3.3.2.5:
//
//   - Code-only response_type → query string
//   - Any response_type containing id_token or token → URL fragment
//
// Fragment encoding keeps tokens out of HTTP logs and Referer headers.
func (h *Handler) redirectAuthorizeResponse(c *gin.Context, redirectURI string, params map[string]string, useFragment bool) {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	encoded := q.Encode()
	if useFragment {
		c.Redirect(http.StatusFound, redirectURI+"#"+encoded)
		return
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, redirectURI+sep+encoded)
}

// token handles the token endpoint.
//
// Rate limiting is applied per client_id before the grant-specific dispatch
// so a single misbehaving RP cannot crowd out others. Limit is sourced from
// the app's protocol_config.rate_limit_per_min, with a sane IdP-wide
// default for un-configured apps.
func (h *Handler) token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	if clientID := h.peekClientID(c); clientID != "" {
		limit := DefaultTokenRateLimitPerMin
		if app, _ := h.appRes.GetAppByClientID(c.Request.Context(), clientID); app != nil {
			if cfg := h.parseOIDCConfig(app.ProtocolConfig); cfg.RateLimitPerMin > 0 {
				limit = cfg.RateLimitPerMin
			}
		}
		allowed, retryAfter, _ := checkRateLimit(c.Request.Context(), h.store.Redis(), clientID, limit)
		if !allowed {
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limited",
				"error_description": "client token-endpoint rate limit exceeded",
			})
			return
		}
	}

	switch grantType {
	case "authorization_code":
		h.tokenAuthorizationCode(c)
	case "refresh_token":
		h.tokenRefreshToken(c)
	case "client_credentials":
		h.tokenClientCredentials(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "unsupported grant_type",
		})
	}
}

// peekClientID extracts the asserted client_id from any of the four supported
// auth surfaces WITHOUT performing signature / secret verification. Used only
// for rate-limit bucketing so an unauthenticated flood targeting one client
// can be throttled before it hits the verification machinery.
func (h *Handler) peekClientID(c *gin.Context) string {
	if v := c.PostForm("client_id"); v != "" {
		return v
	}
	if user, _, ok := c.Request.BasicAuth(); ok {
		return user
	}
	if assertion := c.PostForm("client_assertion"); assertion != "" {
		parsed, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
		if err == nil {
			if mc, ok := parsed.Claims.(jwt.MapClaims); ok {
				if v, _ := mc["sub"].(string); v != "" {
					return v
				}
				if v, _ := mc["iss"].(string); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func (h *Handler) tokenAuthorizationCode(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	app, isPublic, authErr := h.authenticateClient(c)
	if authErr != "" {
		h.tokenError(c, "invalid_client", authErr)
		return
	}
	clientID := app.ClientID

	if code == "" {
		h.tokenError(c, "invalid_request", "missing code")
		return
	}

	// Consume auth code
	ac, err := h.store.ConsumeAuthCode(c.Request.Context(), code)
	if err != nil {
		h.tokenError(c, "invalid_grant", "invalid or expired authorization code")
		return
	}
	// Pin the auth-code's tenant so downstream claim/user/app-role reads are
	// tenant-scoped (protocol group has no AuthMiddleware).
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), ac.TenantID))

	// Validate client
	if ac.ClientID != clientID {
		h.tokenError(c, "invalid_grant", "client_id mismatch")
		return
	}

	if ac.RedirectURI != redirectURI {
		h.tokenError(c, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Verify PKCE if challenge was set
	if ac.CodeChallenge != "" {
		if codeVerifier == "" {
			h.tokenError(c, "invalid_grant", "code_verifier required")
			return
		}
		if !VerifyPKCE(codeVerifier, ac.CodeChallenge, ac.CodeChallengeMethod) {
			h.tokenError(c, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	// Client already authenticated above via authenticateClient — variable
	// `isPublic` indicates the auth method resolved to "none" (public client).
	// Public clients without PKCE must be rejected per OAuth 2.1 / OIDC BCP.
	if isPublic && ac.CodeChallenge == "" {
		h.tokenError(c, "invalid_request", "public client must use PKCE")
		return
	}

	// Load signing key
	key, kid, err := h.loadSigningKey(c, app.ID)
	if err != nil {
		h.tokenError(c, "server_error", "signing key unavailable")
		return
	}

	oidcCfg := h.parseOIDCConfig(app.ProtocolConfig)

	// Resolve scope-driven claims + apply per-app declarative mappers.
	claims, err := h.idRes.ResolveClaims(c.Request.Context(), ac.UserID, ac.Scopes)
	if err != nil {
		h.tokenError(c, "server_error", "failed to resolve claims")
		return
	}
	info, _ := h.idRes.ResolveUser(c.Request.Context(), ac.UserID)
	if info != nil {
		applyClaimMappers(claims, oidcCfg.ClaimMappers, info, ac.Scopes)
	}

	// Resolve subject + tenant_code per app.subject_strategy. tenant_code
	// goes into claims; sub override flows through into the token issuer.
	subj := h.resolveSubject(c.Request.Context(), app, info)
	if subj.TenantCode != "" {
		claims["tenant_code"] = subj.TenantCode
	}
	if subj.DisplayUsername != "" {
		claims["preferred_username"] = subj.DisplayUsername
	}

	// app_roles claim — IdP-side role mapping. SPs read this verbatim
	// instead of writing JMESPath against `groups`. See approle package.
	if h.appRoles != nil {
		if roleCodes, err := h.appRoles.ResolveAppRoles(c.Request.Context(), ac.UserID, app.ID, ac.TenantID); err == nil && len(roleCodes) > 0 {
			claims["app_roles"] = roleCodes
		}
	}

	accessTTL := time.Duration(oidcCfg.AccessTokenTTL) * time.Second

	// Issue access token
	accessToken, err := h.tokenIss.IssueAccessToken(&AccessTokenClaims{
		UserID:    ac.UserID,
		TenantID:  ac.TenantID,
		ClientID:  clientID,
		Scopes:    ac.Scopes,
		ExpiresIn: accessTTL,
		Subject:   subj.Subject,
	}, key, kid)
	if err != nil {
		h.tokenError(c, "server_error", "failed to issue access token")
		return
	}

	// Issue ID token with full OIDC Core §2 claim set.
	idToken, err := h.tokenIss.IssueIDToken(&IDTokenClaims{
		UserID:      ac.UserID,
		ClientID:    clientID,
		Subject:     subj.Subject,
		Nonce:       ac.Nonce,
		Scopes:      ac.Scopes,
		Extra:       claims,
		ExpiresIn:   accessTTL,
		AuthTime:    ac.AuthTime,
		AMR:         authMethodToAMR(ac.AuthMethod),
		ACR:         "0", // default ACR; B-milestone MFA flow will set higher
		AccessToken: accessToken,
	}, key, kid)
	if err != nil {
		h.tokenError(c, "server_error", "failed to issue id token")
		return
	}

	result := &TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   oidcCfg.AccessTokenTTL,
		IDToken:     idToken,
		Scope:       strings.Join(ac.Scopes, " "),
	}

	h.emitAudit(c.Request.Context(), event.OIDCTokenIssued, map[string]any{
		"client_id": clientID,
		"app_id":    app.ID,
		"user_id":   ac.UserID,
		"scopes":    ac.Scopes,
		"ip":        c.ClientIP(),
		"ua":        c.Request.UserAgent(),
		"grant":     "authorization_code",
	})

	// Issue refresh token. Auth context (auth_time / auth_method / nonce) is
	// carried so a refresh-issued id_token retains the original login moment.
	refreshTTL := time.Duration(oidcCfg.RefreshTokenTTL) * time.Second
	rt, err := h.store.CreateRefreshToken(c.Request.Context(), &CreateRefreshTokenRequest{
		ClientID:   clientID,
		UserID:     ac.UserID,
		TenantID:   ac.TenantID,
		Scopes:     ac.Scopes,
		AuthTime:   ac.AuthTime,
		AuthMethod: ac.AuthMethod,
		Nonce:      ac.Nonce,
		TTL:        refreshTTL,
	})
	if err == nil {
		result.RefreshToken = rt.Token
	}

	c.JSON(http.StatusOK, result)
}

func (h *Handler) tokenRefreshToken(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")

	app, _, authErr := h.authenticateClient(c)
	if authErr != "" {
		h.tokenError(c, "invalid_client", authErr)
		return
	}
	clientID := app.ClientID

	if refreshToken == "" {
		h.tokenError(c, "invalid_request", "missing refresh_token")
		return
	}

	rt, err := h.store.ConsumeRefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		// Reuse detection emits its own audit signal — sniff the err for the
		// known sentinel substring rather than threading a typed error
		// through the store API.
		if strings.Contains(err.Error(), "reuse detected") {
			h.emitAudit(c.Request.Context(), event.OIDCTokenReuse, map[string]any{
				"client_id": clientID,
				"ip":        c.ClientIP(),
				"ua":        c.Request.UserAgent(),
			})
		}
		h.tokenError(c, "invalid_grant", "invalid or expired refresh token")
		return
	}
	// Pin the refresh-token's tenant so downstream claim/user/app-role reads
	// are tenant-scoped.
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), rt.TenantID))
	if rt.ClientID != clientID {
		h.tokenError(c, "invalid_grant", "client_id mismatch")
		return
	}

	key, kid, err := h.loadSigningKey(c, app.ID)
	if err != nil {
		h.tokenError(c, "server_error", "signing key unavailable")
		return
	}

	oidcCfg := h.parseOIDCConfig(app.ProtocolConfig)
	accessTTL := time.Duration(oidcCfg.AccessTokenTTL) * time.Second

	// Resolve subject once for the refresh-issued AT + ID token.
	refreshInfo, _ := h.idRes.ResolveUser(c.Request.Context(), rt.UserID)

	// Offboarding / disabled-account guard: a refresh token must not keep
	// minting fresh access tokens once its owner is disabled (e.g. an
	// offboarded employee). The old token was already consumed above, so a
	// rejection here ends the family — no new sibling is issued. Closes the
	// gap where disabling a user left their refresh tokens live until expiry.
	if refreshInfo == nil || refreshInfo.Status != userStatusActive {
		h.tokenError(c, "invalid_grant", "user account is not active")
		return
	}

	refreshSubj := h.resolveSubject(c.Request.Context(), app, refreshInfo)

	// Issue new access token
	accessToken, err := h.tokenIss.IssueAccessToken(&AccessTokenClaims{
		UserID:    rt.UserID,
		TenantID:  rt.TenantID,
		ClientID:  clientID,
		Scopes:    rt.Scopes,
		ExpiresIn: accessTTL,
		Subject:   refreshSubj.Subject,
	}, key, kid)
	if err != nil {
		h.tokenError(c, "server_error", "failed to issue access token")
		return
	}

	// Issue new refresh token, inheriting the family so reuse detection
	// can revoke every sibling if an old token resurfaces.
	refreshTTL := time.Duration(oidcCfg.RefreshTokenTTL) * time.Second
	newRT, err := h.store.CreateRefreshToken(c.Request.Context(), &CreateRefreshTokenRequest{
		ClientID:   clientID,
		UserID:     rt.UserID,
		TenantID:   rt.TenantID,
		Scopes:     rt.Scopes,
		AuthTime:   rt.AuthTime,
		AuthMethod: rt.AuthMethod,
		Nonce:      rt.Nonce,
		FamilyID:   rt.FamilyID,
		TTL:        refreshTTL,
	})
	if err != nil {
		h.tokenError(c, "server_error", "failed to issue refresh token")
		return
	}

	// Reissue id_token on refresh (OIDC Core §12.1 — recommended). auth_time
	// and amr stay pinned to the original login moment.
	claims, _ := h.idRes.ResolveClaims(c.Request.Context(), rt.UserID, rt.Scopes)
	// refreshInfo is guaranteed non-nil by the disabled-account guard above.
	applyClaimMappers(claims, oidcCfg.ClaimMappers, refreshInfo, rt.Scopes)
	if refreshSubj.TenantCode != "" {
		claims["tenant_code"] = refreshSubj.TenantCode
	}
	if refreshSubj.DisplayUsername != "" {
		claims["preferred_username"] = refreshSubj.DisplayUsername
	}
	if h.appRoles != nil && app != nil {
		if roleCodes, err := h.appRoles.ResolveAppRoles(c.Request.Context(), rt.UserID, app.ID, rt.TenantID); err == nil && len(roleCodes) > 0 {
			claims["app_roles"] = roleCodes
		}
	}
	idToken, _ := h.tokenIss.IssueIDToken(&IDTokenClaims{
		UserID:      rt.UserID,
		ClientID:    clientID,
		Subject:     refreshSubj.Subject,
		Nonce:       rt.Nonce,
		Scopes:      rt.Scopes,
		Extra:       claims,
		ExpiresIn:   idTokenTTLFromConfig(oidcCfg),
		AuthTime:    rt.AuthTime,
		AMR:         authMethodToAMR(rt.AuthMethod),
		ACR:         "0",
		AccessToken: accessToken,
	}, key, kid)

	h.emitAudit(c.Request.Context(), event.OIDCTokenRefreshed, map[string]any{
		"client_id": clientID,
		"app_id":    app.ID,
		"user_id":   rt.UserID,
		"scopes":    rt.Scopes,
		"family":    rt.FamilyID,
		"ip":        c.ClientIP(),
		"ua":        c.Request.UserAgent(),
	})

	c.JSON(http.StatusOK, &TokenPair{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    oidcCfg.AccessTokenTTL,
		IDToken:      idToken,
		RefreshToken: newRT.Token,
		Scope:        strings.Join(rt.Scopes, " "),
	})
}

func (h *Handler) tokenClientCredentials(c *gin.Context) {
	app, isPublic, authErr := h.authenticateClient(c)
	if authErr != "" {
		h.tokenError(c, "invalid_client", authErr)
		return
	}
	if isPublic {
		h.tokenError(c, "unauthorized_client", "client_credentials grant requires confidential client")
		return
	}
	clientID := app.ClientID

	key, kid, err := h.loadSigningKey(c, app.ID)
	if err != nil {
		h.tokenError(c, "server_error", "signing key unavailable")
		return
	}

	oidcCfg := h.parseOIDCConfig(app.ProtocolConfig)
	accessTTL := time.Duration(oidcCfg.AccessTokenTTL) * time.Second

	scope := c.PostForm("scope")
	scopes := parseScopes(scope)

	accessToken, err := h.tokenIss.IssueAccessToken(&AccessTokenClaims{
		UserID:    0, // no user in client_credentials
		TenantID:  app.TenantID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresIn: accessTTL,
	}, key, kid)
	if err != nil {
		h.tokenError(c, "server_error", "failed to issue access token")
		return
	}

	c.JSON(http.StatusOK, &TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   oidcCfg.AccessTokenTTL,
		Scope:       strings.Join(scopes, " "),
	})
}

// userinfo returns claims about the authenticated user.
func (h *Handler) userinfo(c *gin.Context) {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	// We need to find the app's public key to validate
	// Parse token without verification to get client_id, then verify
	claims, err := h.validateBearerToken(c, tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": err.Error()})
		return
	}

	sub, _ := claims["sub"].(string)
	userID, _ := strconv.ParseInt(sub, 10, 64)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	// Pin the token's tenant so the claim/user reads are tenant-scoped.
	if tid, ok := claims["tenant_id"].(float64); ok && tid > 0 {
		c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), int64(tid)))
	}

	scopeVal, _ := claims["scope"].([]any)
	var scopes []string
	for _, s := range scopeVal {
		if str, ok := s.(string); ok {
			scopes = append(scopes, str)
		}
	}

	userClaims, err := h.idRes.ResolveClaims(c.Request.Context(), userID, scopes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Apply per-app declarative claim mappers so userinfo response stays in
	// lockstep with the id_token previously issued from the same app config.
	if clientID, _ := claims["client_id"].(string); clientID != "" {
		if app, _ := h.appRes.GetAppByClientID(c.Request.Context(), clientID); app != nil {
			oidcCfg := h.parseOIDCConfig(app.ProtocolConfig)
			if info, _ := h.idRes.ResolveUser(c.Request.Context(), userID); info != nil {
				applyClaimMappers(userClaims, oidcCfg.ClaimMappers, info, scopes)
			}
			// Mirror app_roles claim in userinfo as in id_token. SPs that
			// pull role only from userinfo (e.g. Grafana before reading
			// id_token) get the same answer.
			if h.appRoles != nil {
				tenantID, _ := claims["tenant_id"].(float64)
				if roleCodes, err := h.appRoles.ResolveAppRoles(c.Request.Context(), userID, app.ID, int64(tenantID)); err == nil && len(roleCodes) > 0 {
					userClaims["app_roles"] = roleCodes
				}
			}
		}
	}

	c.JSON(http.StatusOK, userClaims)
}

// jwks returns the JSON Web Key Set per OIDC Discovery 1.0 §5.
//
// MXID's keying model is per-application (each OIDC app owns its own RSA
// keypair). This endpoint aggregates the active + rotating signing keys
// of every enabled app into a single JWK Set so RPs only fetch one URL.
func (h *Handler) jwks(c *gin.Context) {
	certs, err := h.appRes.ListAllActiveSigningCerts(c.Request.Context())
	if err != nil {
		response.InternalError(c, "failed to load jwks")
		return
	}
	keys := make([]gin.H, 0, len(certs))
	for _, cert := range certs {
		jwk, err := publicCertToJWK(cert)
		if err != nil {
			continue // skip malformed certs rather than fail the whole set
		}
		keys = append(keys, jwk)
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// revoke handles token revocation.
func (h *Handler) revoke(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Try to revoke as refresh token
	_ = h.store.RevokeRefreshToken(c.Request.Context(), token)
	c.Status(http.StatusOK)
}

// introspect handles token introspection (RFC 7662).
func (h *Handler) introspect(c *gin.Context) {
	token := c.PostForm("token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if clientID == "" {
		var ok bool
		clientID, clientSecret, ok = c.Request.BasicAuth()
		if !ok {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
	}

	// Verify client. Route through verifyClientSecret (bcrypt + constant-time
	// legacy compare) so /introspect matches the token-endpoint auth semantics
	// and never leaks the secret via string-compare timing.
	app, err := h.appRes.GetAppByClientID(c.Request.Context(), clientID)
	if err != nil || app == nil || !verifyClientSecret(app.ClientSecret, clientSecret) {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	if token == "" {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	// Try to validate as JWT access token
	certs, err := h.appRes.ListCerts(c.Request.Context(), app.ID)
	if err != nil || len(certs) == 0 {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	pubKey, err := ParseRSAPublicKey(certs[0].PublicKey)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	claims, err := h.tokenIss.ValidateAccessToken(token, pubKey)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active":    true,
		"sub":       claims["sub"],
		"client_id": claims["client_id"],
		"scope":     claims["scope"],
		"exp":       claims["exp"],
		"iat":       claims["iat"],
		"iss":       claims["iss"],
		"token_type": "Bearer",
	})
}

// endSession handles RP-Initiated Logout per OIDC RP-Initiated Logout 1.0.
//
// In addition to terminating the local SSO session, this fans out a
// back-channel logout notification to every RP that authenticated against
// this session (OpenID Connect Back-Channel Logout 1.0): a signed JWT
// logout_token is POSTed to each RP's `backchannel_logout_uri`.
//
// Fan-out runs in a detached goroutine — we do not block the user-visible
// logout on RP responsiveness, but errors are logged for audit follow-up.
func (h *Handler) endSession(c *gin.Context) {
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	clientID := c.Query("client_id")
	sessionCookie, _ := c.Cookie("mxid_proto_sid")

	// Snapshot the participating apps BEFORE deleting the session so the
	// fan-out has the data it needs AND we can validate the post_logout
	// redirect against the actual RPs in this session.
	var appIDs []int64
	if sessionCookie != "" {
		appIDs, _ = h.store.ListSSOApps(c.Request.Context(), sessionCookie)
		userID := int64(0)
		if sess, _ := h.sessRes.GetSSOSession(c.Request.Context(), sessionCookie); sess != nil {
			userID = sess.UserID
		}

		_ = h.sessRes.DeleteSSOSession(c.Request.Context(), sessionCookie)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("mxid_proto_sid", "", -1, "/", "", false, true)

		if len(appIDs) > 0 && userID != 0 {
			go h.fanOutBackchannelLogout(appIDs, userID, sessionCookie)
		}
	}

	// Open-redirect guard: post_logout_redirect_uri MUST exactly match one
	// of the requested RP's registered redirect_uris. If we cannot prove
	// the URL belongs to a legitimate RP, drop the redirect and render the
	// terminal "logged out" page instead. Without this check an attacker
	// can chain ?post_logout_redirect_uri=https://evil/ for phishing.
	if postLogoutRedirectURI != "" && h.isAllowedPostLogoutRedirect(c, clientID, appIDs, postLogoutRedirectURI) {
		c.Redirect(http.StatusFound, postLogoutRedirectURI)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// isAllowedPostLogoutRedirect returns true when the supplied URL is
// registered against either (a) the RP identified by client_id, or (b) any
// app that participated in the SSO session about to terminate. Failing
// closed for an unknown URL is the deliberate design — the spec allows
// us to skip the redirect when validation fails.
func (h *Handler) isAllowedPostLogoutRedirect(c *gin.Context, clientID string, sessionAppIDs []int64, uri string) bool {
	ctx := c.Request.Context()
	if clientID != "" {
		if app, err := h.appRes.GetAppByClientID(ctx, clientID); err == nil && app != nil {
			if ValidateRedirectURI(uri, app.RedirectURIs) == nil {
				return true
			}
		}
	}
	for _, appID := range sessionAppIDs {
		app, err := h.appRes.GetAppByID(ctx, appID)
		if err != nil || app == nil {
			continue
		}
		if ValidateRedirectURI(uri, app.RedirectURIs) == nil {
			return true
		}
	}
	return false
}

// LogoutUserBackchannel fans out a back-channel logout to every RP the user
// has an active protocol SSO session with — used by offboarding to proactively
// drop the departing user's session inside each participating app.
//
// Must be called BEFORE the user's protocol sessions are killed: the per-RP
// app sets are keyed by SSO session id, which we derive from the user's live
// protocol sessions. The collection (session + app-set reads) runs
// synchronously so it sees the data before the kill; the actual logout_token
// POSTs are dispatched on a detached goroutine so a slow RP never blocks the
// offboard. Best-effort — apps that don't implement back-channel logout, or
// that we can't reach, fall through to failing closed on their next token
// validation.
func (h *Handler) LogoutUserBackchannel(ctx context.Context, userID int64) {
	protoSessions, err := h.sessionMgr.ListByUser(ctx, session.NamespaceProtocol, userID)
	if err != nil || len(protoSessions) == 0 {
		return
	}
	type target struct {
		sid    string
		appIDs []int64
	}
	var targets []target
	for _, s := range protoSessions {
		// Consume-once read of the SSO session's participating apps. Done now,
		// before the session is killed, so the set is still present.
		appIDs, _ := h.store.ListSSOApps(ctx, s.ID)
		if len(appIDs) > 0 {
			targets = append(targets, target{sid: s.ID, appIDs: appIDs})
		}
	}
	if len(targets) == 0 {
		return
	}
	go func() {
		for _, t := range targets {
			h.fanOutBackchannelLogout(t.appIDs, userID, t.sid)
		}
	}()
}

// LogoutUserAppBackchannel sends a back-channel logout_token only to the RP
// identified by appID, for every protocol SSO session of the user where that
// app participated. Used by JIT elevation expiry/revoke to drop an elevated
// role from one downstream app without logging the user out of their other
// apps.
//
// Best-effort + async: the logout_token POST runs on a detached goroutine so
// a slow RP never blocks the caller. If the app has no backchannel_logout_uri
// configured, the call is a no-op.
//
// Must be called BEFORE the user's protocol sessions are killed (same
// constraint as LogoutUserBackchannel) so the SSO-app tracking sets are still
// present in Redis.
func (h *Handler) LogoutUserAppBackchannel(ctx context.Context, userID, appID int64) {
	protoSessions, err := h.sessionMgr.ListByUser(ctx, session.NamespaceProtocol, userID)
	if err != nil || len(protoSessions) == 0 {
		return
	}

	type target struct {
		sid string
	}
	var targets []target

	for _, s := range protoSessions {
		// Non-destructive read: we only want to check membership and send a
		// logout_token to the single target app. The session's tracking set must
		// remain intact so a subsequent full logout (LogoutUserBackchannel /
		// endSession) can still fan out to all other participating RPs.
		appIDs, _ := h.store.PeekSSOApps(ctx, s.ID)
		if slices.Contains(appIDs, appID) {
			targets = append(targets, target{sid: s.ID})
		}
	}

	if len(targets) == 0 {
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, t := range targets {
			h.sendBackchannelLogout(bgCtx, appID, userID, t.sid)
		}
	}()
}

// fanOutBackchannelLogout posts a signed logout_token to every RP's
// configured backchannel_logout_uri. Detached from the request context so
// per-RP latency does not block the user; uses a fresh context with a
// modest timeout.
func (h *Handler) fanOutBackchannelLogout(appIDs []int64, userID int64, sid string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, appID := range appIDs {
		h.sendBackchannelLogout(ctx, appID, userID, sid)
	}
}

// sendBackchannelLogout signs and POSTs a logout_token to a single RP.
func (h *Handler) sendBackchannelLogout(ctx context.Context, appID, userID int64, sid string) {
	// Load app config (need client_id + backchannel_logout_uri + signing key).
	// AppResolver does not expose lookup by id, so we use the cert path which
	// caches per-app context. Falls back to silent skip if anything is missing.
	signingCerts, err := h.appRes.ListCerts(ctx, appID)
	if err != nil || len(signingCerts) == 0 {
		return
	}
	// We need client_id and backchannel_logout_uri — derived from the app row.
	// The resolver's CertConfig does not carry these, so we ask GetCert to
	// access app's protocol_config via a fresh GetApp lookup. The cleanest
	// path is to call appRes.GetAppByClientID, but we have only app.ID.
	//
	// As a pragmatic compromise this milestone, the back-channel target URL
	// is fetched by walking certs → app via a small helper added below.
	cfg := h.lookupAppByID(ctx, appID)
	if cfg == nil {
		return
	}
	oidcCfg := h.parseOIDCConfig(cfg.ProtocolConfig)
	if oidcCfg.BackchannelLogoutURI == "" {
		return
	}

	key, err := ParseRSAPrivateKey(signingCerts[0].PrivateKey)
	if err != nil {
		return
	}
	kid := signingCerts[0].KID
	if kid == "" {
		kid = fmt.Sprintf("%d", signingCerts[0].ID)
	}

	now := time.Now()
	mapClaims := jwt.MapClaims{
		"iss": h.issuer,
		"aud": cfg.ClientID,
		"iat": now.Unix(),
		"jti": fmt.Sprintf("logout-%d-%d", appID, now.UnixNano()),
		"sub": fmt.Sprintf("%d", userID),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if oidcCfg.BackchannelLogoutSessionRequired && sid != "" {
		mapClaims["sid"] = sid
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "logout+jwt"
	signed, err := token.SignedString(key)
	if err != nil {
		return
	}

	form := url.Values{}
	form.Set("logout_token", signed)
	req, err := http.NewRequestWithContext(ctx, "POST", oidcCfg.BackchannelLogoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	doer := httpDoer(backchannelLogoutClient)
	if h.backchannelClient != nil {
		doer = h.backchannelClient
	}
	resp, err := doer.Do(req)
	if err != nil {
		// Includes the SSRF-guard block case (backchannel_logout_uri resolving
		// to an internal/disallowed address, or a non-https scheme). This is a
		// best-effort notification; the caller ignores the error, but blocking
		// here prevents the signed logout_token from being POSTed to an internal
		// address.
		return
	}
	_ = resp.Body.Close()
}

// backchannelLogoutClient is the SSRF-safe client for POSTing signed
// logout_tokens to an admin-configured backchannel_logout_uri (per-app,
// arbitrary host). The IP/scheme guard prevents the token from being replayed
// to an internal address, including via redirect.
var backchannelLogoutClient = safehttp.New(safehttp.WithTimeout(5 * time.Second))

// lookupAppByID walks an app ID to its full AppConfig via the resolver.
func (h *Handler) lookupAppByID(ctx context.Context, appID int64) *resolver.AppConfig {
	cfg, err := h.appRes.GetAppByID(ctx, appID)
	if err != nil {
		return nil
	}
	return cfg
}

// Helper methods

// isPublicClient returns true for OIDC client types that MUST NOT authenticate
// with a shared secret (OAuth 2.0 BCP §2.1). Public clients are required to
// use PKCE on the authorization endpoint.
func isPublicClient(app *resolver.AppConfig) bool {
	return app.ClientType == "spa" || app.ClientType == "native"
}

// idTokenTTLFromConfig picks the id_token lifetime from the app's protocol
// config, falling back to the access_token lifetime when ID-token-specific
// TTL is unset. Returns time.Duration ready to plug into IssueIDToken.
func idTokenTTLFromConfig(cfg *OIDCConfig) time.Duration {
	if cfg.IDTokenTTL > 0 {
		return time.Duration(cfg.IDTokenTTL) * time.Second
	}
	return time.Duration(cfg.AccessTokenTTL) * time.Second
}

// authMethodToAMR translates the internal auth_type string (recorded on the
// SSO session at login time) into RFC 8176 "amr" claim values.
//
// Returns nil when the method is unknown so the id_token simply omits amr
// rather than emit a misleading value.
func authMethodToAMR(authType string) []string {
	switch authType {
	case "local", "password":
		return []string{"pwd"}
	case "ldap":
		return []string{"pwd"}
	case "totp":
		return []string{"otp"}
	case "webauthn":
		return []string{"hwk"}
	case "social", "oauth":
		return []string{"federated"}
	}
	return nil
}

// verifyClientSecret matches plaintext against the bcrypt hash stored on the
// app row. Falls back to plain string equality for legacy rows that pre-date
// the bcrypt migration so a partial rollout does not lock out clients.
func verifyClientSecret(storedHash, plaintext string) bool {
	if storedHash == "" {
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(plaintext)) == nil {
		return true
	}
	// Legacy plaintext compatibility (only matches when stored value is the
	// literal plaintext, not a hash). Constant-time compare so the legacy-row
	// path doesn't leak the secret length/prefix via early-exit timing the way
	// Go's string == does.
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(plaintext)) == 1
}

// authenticateClient resolves and authenticates the calling RP at the token
// endpoint. Supports four standard methods:
//
//   - client_secret_basic: HTTP Basic header (default for confidential)
//   - client_secret_post : client_id + client_secret in form body
//   - client_secret_jwt  : RFC 7523 JWT signed with shared secret (HS256)
//   - private_key_jwt    : RFC 7523 JWT signed with RP's private key (RS256)
//   - none               : public client (SPA/native), PKCE-only
//
// Returns the resolved app + a boolean indicating whether the auth method
// is "none" (caller can still require PKCE in that branch).
func (h *Handler) authenticateClient(c *gin.Context) (*resolver.AppConfig, bool, string) {
	assertionType := c.PostForm("client_assertion_type")
	assertion := c.PostForm("client_assertion")

	if assertionType == ClientAssertionType && assertion != "" {
		// JWT-bearer client auth. Sniff client_id from the assertion so we can
		// load the app config and dispatch to the right verifier.
		parsed, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
		if err != nil {
			return nil, false, "invalid client_assertion"
		}
		mc, _ := parsed.Claims.(jwt.MapClaims)
		clientID, _ := mc["sub"].(string)
		if clientID == "" {
			clientID, _ = mc["iss"].(string)
		}
		if clientID == "" {
			return nil, false, "client_assertion missing iss/sub"
		}
		app, err := h.appRes.GetAppByClientID(c.Request.Context(), clientID)
		if err != nil || app == nil {
			return nil, false, "unknown client"
		}
		expectedAud := h.issuer + "/protocol/oidc/token"
		if err := VerifyClientAssertion(c.Request.Context(), h.store.Redis(), app, assertion, expectedAud); err != nil {
			return nil, false, err.Error()
		}
		return app, false, ""
	}

	// Classic form / basic auth path.
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	if clientID == "" {
		var ok bool
		clientID, clientSecret, ok = c.Request.BasicAuth()
		if !ok {
			return nil, false, "client authentication required"
		}
	}
	if clientID == "" {
		return nil, false, "client_id required"
	}

	app, err := h.appRes.GetAppByClientID(c.Request.Context(), clientID)
	if err != nil || app == nil {
		return nil, false, "unknown client"
	}

	// Public clients (token_endpoint_auth_method=none) may omit a secret.
	if isPublicClient(app) || clientSecret == "" && app.ClientSecret == "" {
		return app, true, ""
	}
	if !verifyClientSecret(app.ClientSecret, clientSecret) {
		return nil, false, "invalid client credentials"
	}
	return app, false, ""
}

func (h *Handler) loadSigningKey(c *gin.Context, appID int64) (*rsa.PrivateKey, string, error) {
	cert, err := h.appRes.GetCert(c.Request.Context(), appID, "signing")
	if err != nil {
		return nil, "", err
	}
	key, err := ParseRSAPrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, "", err
	}
	// Prefer the persisted kid (matches JWKS output) and fall back to the
	// numeric cert ID only for legacy rows without a kid populated.
	kid := cert.KID
	if kid == "" {
		kid = fmt.Sprintf("%d", cert.ID)
	}
	return key, kid, nil
}

func (h *Handler) parseOIDCConfig(raw json.RawMessage) *OIDCConfig {
	cfg := Defaults()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, cfg)
	}
	return cfg
}

func (h *Handler) isValidRedirectURI(app *resolver.AppConfig, uri string) bool {
	return ValidateRedirectURI(uri, app.RedirectURIs) == nil
}

func (h *Handler) redirectToLogin(c *gin.Context, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) {
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	authorizeURL := buildAuthorizeURL(urls.Issuer, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
	loginURL := fmt.Sprintf("%s/login?return_to=%s", urls.Portal, url.QueryEscape(authorizeURL))
	c.Redirect(http.StatusFound, loginURL)
}

// redirectToConsent kicks the user to the portal SPA's consent page, with
// the full authorize URL packed into `return_to` so the SPA can resume the
// original /protocol/oidc/authorize call once the user clicks 同意.
//
// The portal SPA reads return_to, posts to /api/v1/portal/consent to record
// the grant, then window.location=return_to to retry authorize — which now
// finds the consent row and proceeds to issue the code.
func (h *Handler) redirectToConsent(c *gin.Context, appID int64, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) {
	urls := h.resolveURLs(c.Request.Context(), c.Request.Host)
	authorizeURL := buildAuthorizeURL(urls.Issuer, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
	consentURL := fmt.Sprintf("%s/consent?app_id=%d&scope=%s&return_to=%s",
		urls.Portal,
		appID,
		url.QueryEscape(scope),
		url.QueryEscape(authorizeURL),
	)
	c.Redirect(http.StatusFound, consentURL)
}

// buildAuthorizeURL reassembles a fully-qualified /protocol/oidc/authorize
// URL from its parameter components, used as `return_to` for SPA-side login
// and consent flows so the user can resume the OIDC dance after interaction.
func buildAuthorizeURL(issuer, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) string {
	u := url.URL{Path: "/protocol/oidc/authorize"}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	if state != "" {
		q.Set("state", state)
	}
	if nonce != "" {
		q.Set("nonce", nonce)
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", codeChallengeMethod)
	}
	u.RawQuery = q.Encode()
	return issuer + u.String()
}

// ensure context import is referenced (used in ConsentChecker interface)
var _ context.Context

func (h *Handler) redirectError(c *gin.Context, redirectURI, state, errCode, errDesc string) {
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	location := fmt.Sprintf("%s%serror=%s&error_description=%s", redirectURI, sep, errCode, errDesc)
	if state != "" {
		location += "&state=" + state
	}
	c.Redirect(http.StatusFound, location)
}

func (h *Handler) tokenError(c *gin.Context, errCode, errDesc string) {
	c.JSON(http.StatusBadRequest, gin.H{
		"error":             errCode,
		"error_description": errDesc,
	})
}

func (h *Handler) validateBearerToken(c *gin.Context, tokenStr string) (map[string]any, error) {
	// Parse unverified to get client_id
	parser := new(jwt.Parser)
	unverified, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	unverifiedClaims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	clientID, _ := unverifiedClaims["client_id"].(string)
	if clientID == "" {
		aud, _ := unverifiedClaims["aud"].(string)
		clientID = aud
	}
	if clientID == "" {
		return nil, fmt.Errorf("no client_id in token")
	}

	// Resolve app and get public key
	app, err := h.appRes.GetAppByClientID(c.Request.Context(), clientID)
	if err != nil || app == nil {
		return nil, fmt.Errorf("unknown client")
	}

	certs, err := h.appRes.ListCerts(c.Request.Context(), app.ID)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("no signing keys")
	}

	pubKey, err := ParseRSAPublicKey(certs[0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	claims, err := h.tokenIss.ValidateAccessToken(tokenStr, pubKey)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

func parseScopes(scope string) []string {
	if scope == "" {
		return []string{"openid"}
	}
	return strings.Fields(scope)
}
