package cas

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/ssoflow"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/imkerbos/mxid/pkg/urlswap"
	"go.uber.org/zap"
)

// httpDoer is the minimal HTTP interface used by SingleLogout so tests can
// substitute a plain http.Client while production always uses the SSRF-safe
// casLogoutClient package var.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// AppRoleResolver returns a user's effective app-role codes for an app, JIT
// (time-bound) elevations first. Structurally identical to the OIDC/SAML
// resolvers so one adapter serves all three.
type AppRoleResolver interface {
	ResolveAppRoles(ctx context.Context, userID, appID, tenantID int64) ([]string, error)
}

// Handler serves CAS protocol endpoints.
type Handler struct {
	issuer          string
	portalURL       string
	urlProvider     urlswap.Provider
	appRes          resolver.AppResolver
	idRes           resolver.IdentityResolver
	sessRes         resolver.SessionResolver
	tenantRes       resolver.TenantResolver
	store           *TicketStore
	serviceRegistry *ServiceRegistry
	logger          *zap.Logger
	// confirm mints/consumes the one-time SSO login-confirmation token. Set by
	// Register. nil = confirmation feature off (every login is seamless).
	confirm *ssoflow.ConfirmStore
	// appRoles resolves the user's effective app roles (JIT elevations first) to
	// emit as a multi-value CAS attribute. nil = no role attribute.
	appRoles AppRoleResolver
	// backchannelClient overrides the package-level casLogoutClient when
	// non-nil. Used in tests so an httptest SP on loopback can receive SLO
	// POSTs; production always uses the SSRF-safe client.
	backchannelClient httpDoer
}

// SetURLProvider installs the runtime URL lookup. nil = stick with
// config defaults (legacy behaviour).
func (h *Handler) SetURLProvider(p urlswap.Provider) { h.urlProvider = p }

func (h *Handler) resolveURLs(c *gin.Context) urlswap.URLs {
	return urlswap.Resolve(c.Request.Context(), h.urlProvider, urlswap.URLs{
		Issuer: h.issuer,
		Portal: h.portalURL,
	}, c.Request.Host)
}

// NewHandler creates a CAS handler. portalURL is where the user-facing
// login page lives (separate SPA host in dev, same host in prod); used to
// build the bounce URL when /login lacks a protocol session.
func NewHandler(
	issuer string,
	portalURL string,
	appRes resolver.AppResolver,
	idRes resolver.IdentityResolver,
	sessRes resolver.SessionResolver,
	tenantRes resolver.TenantResolver,
	store *TicketStore,
	serviceRegistry *ServiceRegistry,
	logger *zap.Logger,
) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Handler{
		issuer:          issuer,
		portalURL:       portalURL,
		appRes:          appRes,
		idRes:           idRes,
		sessRes:         sessRes,
		tenantRes:       tenantRes,
		store:           store,
		serviceRegistry: serviceRegistry,
		logger:          logger,
	}
}

// RegisterRoutes registers CAS endpoints.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	cas := rg.Group("/cas/:app_code")
	{
		cas.GET("/login", h.login)
		cas.GET("/validate", h.validate)
		cas.GET("/serviceValidate", h.serviceValidate)
		cas.GET("/p3/serviceValidate", h.p3ServiceValidate)
		cas.GET("/proxy", h.proxy)
		cas.GET("/proxyValidate", h.proxyValidate)
		cas.GET("/p3/proxyValidate", h.p3ProxyValidate)
		cas.GET("/logout", h.logout)
	}
}

// login handles the CAS login endpoint.
func (h *Handler) login(c *gin.Context) {
	appCode := c.Param("app_code")
	service := c.Query("service")

	if service == "" {
		response.BadRequest(c, 40001, "missing service parameter")
		return
	}

	app, err := h.appRes.GetApp(c.Request.Context(), appCode)
	if err != nil || app == nil {
		response.NotFound(c, 40401, "application not found")
		return
	}

	if app.Status != 1 {
		response.Error(c, http.StatusForbidden, 40301, "application is disabled", "")
		return
	}

	casCfg := h.parseCASConfig(app.ProtocolConfig)

	// Validate service URL
	if !h.isValidService(casCfg, service) {
		response.BadRequest(c, 40002, "invalid service URL")
		return
	}

	// Check for protocol session
	sessionCookie, err := c.Cookie("mxid_proto_sid")
	if err != nil || sessionCookie == "" {
		h.redirectToLogin(c, appCode, service)
		return
	}

	ssoSess, err := h.sessRes.GetSSOSession(c.Request.Context(), sessionCookie)
	if err != nil || ssoSess == nil {
		h.redirectToLogin(c, appCode, service)
		return
	}
	// Pin the SSO session's tenant so the user read is tenant-scoped.
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), ssoSess.TenantID))

	// SSO login confirmation (product rule, same as OIDC/SAML).
	//   idp_initiated=1 (portal app-list launch) → SEAMLESS: issue the ticket.
	//   SP-initiated (the CAS client sent the user to /login) → confirm EVERY
	//     time via the one-time token. sso_deny=1 → user cancelled: bounce back
	//     to the service with NO ticket (the client shows its own login again).
	if c.Query("sso_deny") == "1" {
		c.Redirect(http.StatusFound, service)
		return
	}
	if c.Query("idp_initiated") != "1" && h.confirm != nil {
		if !h.confirm.Consume(c.Request.Context(), c.Query("sso_confirm"), ssoSess.UserID, app.ID) {
			h.redirectToConsent(c, app.ID, appCode, service)
			return
		}
	}

	// User authenticated — resolve user and issue ticket
	user, err := h.idRes.ResolveUser(c.Request.Context(), ssoSess.UserID)
	if err != nil {
		response.InternalError(c, "failed to resolve user", err)
		return
	}

	// Resolve principal per app.subject_strategy. Shared apps default to
	// username_suffixed so two tenants' "kerbos" don't collide in
	// downstream CAS clients that key by principal.
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
	principal := user.Username
	if subj != nil && subj.Subject != "" {
		principal = subj.Subject
	}

	ticket, err := h.store.CreateTicket(
		c.Request.Context(),
		ssoSess.UserID,
		ssoSess.TenantID,
		service,
		principal,
		casCfg.TicketTTL,
	)
	if err != nil {
		response.InternalError(c, "failed to create service ticket", err)
		return
	}

	// Redirect to service with ticket
	sep := "?"
	if strings.Contains(service, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, fmt.Sprintf("%s%sticket=%s", service, sep, ticket.Ticket))
}

// validate handles CAS 1.0 validation (plain text response).
func (h *Handler) validate(c *gin.Context) {
	ticket := c.Query("ticket")
	service := c.Query("service")

	if ticket == "" || service == "" {
		c.String(http.StatusOK, "no\n\n")
		return
	}

	st, err := h.store.ConsumeTicket(c.Request.Context(), ticket)
	if err != nil {
		c.String(http.StatusOK, "no\n\n")
		return
	}

	if st.Service != service {
		c.String(http.StatusOK, "no\n\n")
		return
	}

	c.String(http.StatusOK, "yes\n%s\n", st.Username)
}

// CAS 2.0 XML response types.

// ServiceResponse wraps CAS 2.0/3.0 XML responses.
type ServiceResponse struct {
	XMLName xml.Name `xml:"cas:serviceResponse"`
	Xmlns   string   `xml:"xmlns:cas,attr"`
	Success *AuthenticationSuccess `xml:"cas:authenticationSuccess,omitempty"`
	Failure *AuthenticationFailure `xml:"cas:authenticationFailure,omitempty"`
}

// AuthenticationSuccess represents a successful validation. Field order mirrors
// the CAS XML schema: user, attributes (p3), proxyGrantingTicket, proxies.
type AuthenticationSuccess struct {
	User                 string      `xml:"cas:user"`
	Attributes           *Attributes `xml:"cas:attributes,omitempty"`
	ProxyGrantingTicket  string      `xml:"cas:proxyGrantingTicket,omitempty"`
	Proxies              *ProxyList  `xml:"cas:proxies,omitempty"`
}

// ProxyList is the ordered <cas:proxies> chain in a proxyValidate response —
// each <cas:proxy> is a proxying service's pgtUrl, most-recent first.
type ProxyList struct {
	Proxies []string `xml:"cas:proxy"`
}

// AuthenticationFailure represents a failed validation.
type AuthenticationFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// ProxyResponse wraps the /proxy endpoint's XML response.
type ProxyResponse struct {
	XMLName xml.Name      `xml:"cas:serviceResponse"`
	Xmlns   string        `xml:"xmlns:cas,attr"`
	Success *ProxySuccess `xml:"cas:proxySuccess,omitempty"`
	Failure *ProxyFailure `xml:"cas:proxyFailure,omitempty"`
}

// ProxySuccess carries the freshly minted proxy ticket.
type ProxySuccess struct {
	ProxyTicket string `xml:"cas:proxyTicket"`
}

// ProxyFailure is the /proxy error envelope.
type ProxyFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// Attributes holds CAS 3.0 user attributes.
type Attributes struct {
	Items []AttributeItem
}

// AttributeItem is a single CAS attribute.
type AttributeItem struct {
	Name  string
	Value string
}

// MarshalXML custom marshals CAS attributes.
func (a *Attributes) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "cas:attributes"}
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	for _, item := range a.Items {
		elem := xml.StartElement{Name: xml.Name{Local: "cas:" + item.Name}}
		if err := e.EncodeElement(item.Value, elem); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// serviceValidate handles CAS 2.0 validation (XML response, no attributes).
func (h *Handler) serviceValidate(c *gin.Context) {
	h.doValidate(c, false, false)
}

// p3ServiceValidate handles CAS 3.0 validation (XML response with attributes).
func (h *Handler) p3ServiceValidate(c *gin.Context) {
	h.doValidate(c, true, false)
}

// proxyValidate handles CAS 2.0 /proxyValidate — like serviceValidate but also
// accepts a proxy ticket (PT-) and reports the <cas:proxies> chain.
func (h *Handler) proxyValidate(c *gin.Context) {
	h.doValidate(c, false, true)
}

// p3ProxyValidate handles CAS 3.0 /p3/proxyValidate (attributes + proxies).
func (h *Handler) p3ProxyValidate(c *gin.Context) {
	h.doValidate(c, true, true)
}

// doValidate is the shared ticket-validation path. allowProxy toggles whether a
// proxy ticket (PT-) is accepted: /serviceValidate must REJECT a PT (only
// /proxyValidate accepts one) per the CAS spec.
func (h *Handler) doValidate(c *gin.Context, includeAttributes, allowProxy bool) {
	ticket := c.Query("ticket")
	service := c.Query("service")

	if ticket == "" || service == "" {
		h.xmlFailure(c, "INVALID_REQUEST", "missing ticket or service parameter")
		return
	}

	st, err := h.store.ConsumeTicket(c.Request.Context(), ticket)
	if err != nil {
		h.xmlFailure(c, "INVALID_TICKET", "ticket not recognized or expired")
		return
	}

	// A proxy ticket may only be validated at /proxyValidate. The ticket is
	// already consumed (single-use) — a PT replayed at /serviceValidate is burned
	// AND rejected.
	if st.IsProxy && !allowProxy {
		h.xmlFailure(c, "INVALID_TICKET", "proxy ticket presented to serviceValidate")
		return
	}

	if st.Service != service {
		h.xmlFailure(c, "INVALID_SERVICE", "service mismatch")
		return
	}

	// Resolve the app to get its numeric ID for the service registry.
	// appCode is always present on this route (/:app_code/serviceValidate).
	appCode := c.Param("app_code")
	app, appErr := h.appRes.GetApp(c.Request.Context(), appCode)

	// Parse app protocol config once; reused for registry TTL and attributes.
	var casCfg *CASConfig
	if appErr == nil && app != nil {
		casCfg = h.parseCASConfig(app.ProtocolConfig)
	}

	// Record the validated service in the per-user registry so L5 (SLO) can
	// fan-out back-channel logout to every service the user authenticated to.
	// Use a fixed TTL (casSLORegistryTTL = 8d) instead of deriving from the
	// service-ticket TTL: the ticket TTL is O(seconds) but a JIT grant can
	// live up to 7 days, and we must be able to find the service at SLO time.
	// Best-effort: a registry failure must not break the ticket validation.
	if h.serviceRegistry != nil && casCfg != nil {
		_ = h.serviceRegistry.RecordService(c.Request.Context(), st.UserID, app.ID, service, ticket, casSLORegistryTTL)
	}

	success := &AuthenticationSuccess{
		User: st.Username,
	}

	// CAS 3.0: include user attributes
	if includeAttributes && casCfg != nil {
		// Pin the ticket's tenant so the user read is tenant-scoped.
		c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), st.TenantID))
		user, err := h.idRes.ResolveUser(c.Request.Context(), st.UserID)
		if err == nil {
			attrs := h.buildAttributes(casCfg, user)
			// Inject tenant_code so consumers can disambiguate users
			// from different tenants when this is a shared app.
			if h.tenantRes != nil && user.TenantID > 0 {
				if tc, _ := h.tenantRes.GetTenantCode(c.Request.Context(), user.TenantID); tc != "" {
					attrs.Items = append(attrs.Items, AttributeItem{
						Name:  "tenant_code",
						Value: tc,
					})
				}
			}
			// Effective app roles (JIT elevations first) as a multi-value
			// attribute — one <cas:roleAttr> element per role. Best-effort.
			if h.appRoles != nil {
				if roles, rerr := h.appRoles.ResolveAppRoles(c.Request.Context(), st.UserID, app.ID, st.TenantID); rerr == nil {
					roleAttr := casCfg.RoleAttribute
					if roleAttr == "" {
						roleAttr = "roles"
					}
					for _, rc := range roles {
						attrs.Items = append(attrs.Items, AttributeItem{Name: roleAttr, Value: rc})
					}
				}
			}
			if len(attrs.Items) > 0 {
				success.Attributes = attrs
			}
		}
	} else if includeAttributes {
		// appErr != nil or app == nil — attributes silently omitted; ticket
		// validation itself still succeeds.
		_ = appErr
	}

	// Proxy chain: a proxy ticket reports the ordered list of services that
	// proxied the authentication, most-recent first.
	if st.IsProxy && len(st.Proxies) > 0 {
		success.Proxies = &ProxyList{Proxies: st.Proxies}
	}

	// pgtUrl: if the validating service requested a proxy-granting ticket and the
	// app has proxy enabled, mint one via the SSRF-safe, allow-listed callback.
	// Best-effort (CAS spec §2.5.4): on any failure the PGT is simply omitted and
	// the ticket validation itself still succeeds.
	if pgtURL := c.Query("pgtUrl"); pgtURL != "" && casCfg != nil && app != nil {
		if iou := h.maybeIssuePGT(c, casCfg, app, st, pgtURL); iou != "" {
			success.ProxyGrantingTicket = iou
		}
	}

	resp := &ServiceResponse{
		Xmlns:   "http://www.yale.edu/tp/cas",
		Success: success,
	}

	xmlBytes, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		h.xmlFailure(c, "INTERNAL_ERROR", "failed to generate response")
		return
	}

	c.Data(http.StatusOK, "application/xml; charset=utf-8", append([]byte(xml.Header), xmlBytes...))
}

// logout handles CAS logout.
func (h *Handler) logout(c *gin.Context) {
	sessionCookie, _ := c.Cookie("mxid_proto_sid")
	if sessionCookie != "" {
		_ = h.sessRes.DeleteSSOSession(c.Request.Context(), sessionCookie)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("mxid_proto_sid", "", -1, "/", "", false, true)
	}

	service := c.Query("service")
	// FAIL-CLOSED: only follow ?service= on logout when it matches the
	// calling SP's registered ServiceURLs. The route carries :app_code, so
	// unlike the old comment claimed we DO have an app context here — resolve
	// it and bind the service to that app's allow-list. Without this guard
	// /cas/:app_code/logout?service=https://evil is an open redirect on the
	// IdP origin. Empty allow-list => no match => render the local logged-out
	// page instead of redirecting.
	if service != "" {
		appCode := c.Param("app_code")
		if app, err := h.appRes.GetApp(c.Request.Context(), appCode); err == nil && app != nil {
			casCfg := h.parseCASConfig(app.ProtocolConfig)
			if h.isValidService(casCfg, service) {
				c.Redirect(http.StatusFound, service)
				return
			}
		}
	}

	response.OK(c, gin.H{"message": "logged out"})
}

// Helper methods

func (h *Handler) parseCASConfig(raw json.RawMessage) *CASConfig {
	cfg := Defaults()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, cfg)
	}
	return cfg
}

func (h *Handler) isValidService(cfg *CASConfig, service string) bool {
	// FAIL-CLOSED: an empty ServiceURLs allow-list means the SP has not
	// registered any landing URL, so there is nothing to bind the service
	// (and the freshly-minted service ticket appended to it) to. We MUST
	// reject rather than fall back to a shape-only check that accepts any
	// https host — that fallback is an open redirect AND a service-ticket
	// leak to an attacker-chosen host.
	if len(cfg.ServiceURLs) == 0 {
		return false
	}
	requested, err := parseAbsoluteHTTP(service)
	if err != nil {
		return false
	}
	for _, allowed := range cfg.ServiceURLs {
		reg, err := parseAbsoluteHTTP(allowed)
		if err != nil {
			continue
		}
		// Scheme + host + port must match exactly (case-insensitive on
		// scheme/host). Path may extend the registered path so a single
		// "https://app.com/cas" entry covers /cas, /cas/, /cas/foo etc.
		// — the classic prefix-bypass `https://app.com.evil.com` no
		// longer matches because the parsed Host differs.
		if !strings.EqualFold(requested.Scheme, reg.Scheme) ||
			!strings.EqualFold(requested.Host, reg.Host) {
			continue
		}
		if requested.Path == reg.Path ||
			strings.HasPrefix(requested.Path, strings.TrimRight(reg.Path, "/")+"/") {
			return true
		}
	}
	return false
}

// parseAbsoluteHTTP parses an http(s) absolute URL and rejects anything
// with a userinfo component (which is a known smuggling vector).
func parseAbsoluteHTTP(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		return nil, errInvalidServiceURL
	}
	if u.User != nil {
		return nil, errInvalidServiceURL
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errInvalidServiceURL
	}
	if u.Fragment != "" {
		return nil, errInvalidServiceURL
	}
	return u, nil
}

var errInvalidServiceURL = errInvalidService{}

type errInvalidService struct{}

func (errInvalidService) Error() string { return "invalid service url" }

func (h *Handler) redirectToLogin(c *gin.Context, appCode, service string) {
	urls := h.resolveURLs(c)
	base := urls.Portal
	if base == "" {
		base = urls.Issuer
	}
	loginURL := fmt.Sprintf("%s/login?protocol=cas&app_code=%s&service=%s",
		base, appCode, service)
	c.Redirect(http.StatusFound, loginURL)
}

// redirectToConsent bounces the user to the portal confirm page for an
// SP-initiated CAS login. return_to is the CAS /login URL (on the issuer host)
// so the page's approve replays it carrying sso_confirm, and the page's cancel
// appends sso_deny=1. No scope param — CAS has none, so the page renders a pure
// "log in to App X?" confirmation.
func (h *Handler) redirectToConsent(c *gin.Context, appID int64, appCode, service string) {
	urls := h.resolveURLs(c)
	base := urls.Portal
	if base == "" {
		base = urls.Issuer
	}
	loginURL := fmt.Sprintf("%s/protocol/cas/%s/login?service=%s",
		urls.Issuer, url.PathEscape(appCode), url.QueryEscape(service))
	consentURL := fmt.Sprintf("%s/consent?app_id=%d&return_to=%s",
		base, appID, url.QueryEscape(loginURL))
	c.Redirect(http.StatusFound, consentURL)
}

func (h *Handler) buildAttributes(cfg *CASConfig, user *resolver.IdentityInfo) *Attributes {
	userMap := map[string]string{
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"phone":        user.Phone,
	}

	attrs := &Attributes{}
	for userAttr, casAttr := range cfg.AttributeMapping {
		if val, ok := userMap[userAttr]; ok && val != "" {
			attrs.Items = append(attrs.Items, AttributeItem{
				Name:  casAttr,
				Value: val,
			})
		}
	}
	return attrs
}

func (h *Handler) xmlFailure(c *gin.Context, code, message string) {
	resp := &ServiceResponse{
		Xmlns: "http://www.yale.edu/tp/cas",
		Failure: &AuthenticationFailure{
			Code:    code,
			Message: message,
		},
	}

	xmlBytes, _ := xml.MarshalIndent(resp, "", "  ")
	c.Data(http.StatusOK, "application/xml; charset=utf-8", append([]byte(xml.Header), xmlBytes...))
}
