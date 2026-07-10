package app

import (
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/saml"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/pagination"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler handles HTTP requests for the app domain.
type Handler struct {
	svc      *Service
	tenantID int64
}

// NewHandler creates a new app handler.
func NewHandler(svc *Service, tenantID int64) *Handler {
	return &Handler{svc: svc, tenantID: tenantID}
}

// RegisterRoutes registers app routes on the given router group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	apps := rg.Group("/apps")
	{
		apps.GET("", authz.Require("app.read", nil), h.List)
		apps.POST("", authz.Require("app.create", nil), h.Create)
		apps.GET("/:id", authz.Require("app.read", nil), h.Get)
		apps.PUT("/:id", authz.Require("app.update", nil), h.Update)
		apps.DELETE("/:id", authz.Require("app.delete", nil), h.Delete)
		apps.PUT("/:id/status", authz.Require("app.update", nil), h.UpdateStatus)
		apps.GET("/:id/config", authz.Require("app.read", nil), h.GetProtocolConfig)
		apps.PUT("/:id/config", authz.Require("app.update", nil), h.UpdateProtocolConfig)
		apps.GET("/:id/access", authz.Require("app.read", nil), h.ListAccess)
		apps.POST("/:id/access", authz.Require("app.access.manage", nil), h.AddAccess)
		apps.DELETE("/:id/access/:aid", authz.Require("app.access.manage", nil), h.RemoveAccess)
		apps.GET("/:id/certs", authz.Require("app.read", nil), h.ListCerts)
		apps.POST("/:id/certs", authz.Require("app.cert.manage", nil), h.CreateCert)
		apps.DELETE("/:id/certs/:cid", authz.Require("app.cert.manage", nil), h.DeleteCert)
		apps.POST("/:id/regenerate-secret", authz.Require("app.cert.manage", nil), h.RegenerateClientSecret)
		apps.POST("/:id/rotate-signing-key", authz.Require("app.cert.manage", nil), h.RotateSigningKey)
		apps.GET("/:id/quickstart/:lang", authz.Require("app.read", nil), h.Quickstart)
		// SAML SP metadata one-shot import. Body is the raw XML document.
		apps.POST("/:id/saml/import-metadata", authz.Require("app.update", nil), h.ImportSAMLMetadata)
	}

	groups := rg.Group("/app-groups")
	{
		groups.GET("", authz.Require("app.read", nil), h.ListGroups)
		groups.POST("", authz.Require("app.create", nil), h.CreateGroup)
		groups.PUT("/:id", authz.Require("app.update", nil), h.UpdateGroup)
		groups.DELETE("/:id", authz.Require("app.delete", nil), h.DeleteGroup)
		groups.GET("/:id/apps", authz.Require("app.read", nil), h.ListAppsInGroup)
		groups.POST("/:id/apps", authz.Require("app.update", nil), h.AddAppToGroup)
		groups.DELETE("/:id/apps/:aid", authz.Require("app.update", nil), h.RemoveAppFromGroup)
	}

	templates := rg.Group("/app-templates")
	{
		templates.GET("", authz.Require("app.read", nil), h.ListTemplates)
		templates.GET("/:key", authz.Require("app.read", nil), h.GetTemplate)
	}
}

// ListAppsInGroup handles GET /app-groups/:id/apps — returns the apps
// currently linked to this group (joined from mxid_app_group_rel).
func (h *Handler) ListAppsInGroup(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	rels, err := h.svc.ListAppsByGroup(c.Request.Context(), groupID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	if len(rels) == 0 {
		response.OK(c, []*AppResponse{})
		return
	}
	ids := make([]int64, len(rels))
	for i, r := range rels {
		ids[i] = r.AppID
	}
	apps, err := h.svc.GetByIDs(c.Request.Context(), ids)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	resp := make([]*AppResponse, len(apps))
	for i, a := range apps {
		resp[i] = ToAppResponse(a)
	}
	response.OK(c, resp)
}

// ListAppsRequest holds query parameters for listing apps.
type ListAppsRequest struct {
	Search   string  `form:"search"`
	Protocol *string `form:"protocol"`
	Status   *int    `form:"status"`
}

// --- App Handlers ---

// List handles GET /apps.
func (h *Handler) List(c *gin.Context) {
	p := pagination.Parse(c)

	var req ListAppsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	params := ListAppParams{
		Page:     p.Page,
		PageSize: p.PageSize,
		Search:   req.Search,
		Protocol: req.Protocol,
		Status:   req.Status,
	}

	apps, total, err := h.svc.List(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), params)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]*AppResponse, len(apps))
	for i, a := range apps {
		items[i] = ToAppResponse(a)
	}

	response.Paginated(c, items, total, p.Page, p.PageSize)
}

// Create handles POST /apps.
//
// On success the response includes the one-time plaintext client_secret for
// confidential OIDC clients. It is NEVER returned again.
func (h *Handler) Create(c *gin.Context) {
	var req CreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	result, err := h.svc.Create(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	resp := ToAppResponse(result.App)
	resp.ClientSecret = result.ClientSecretPlain
	response.Created(c, resp)
}

// Get handles GET /apps/:id.
func (h *Handler) Get(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	application, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, ToAppResponse(application))
}

// Update handles PUT /apps/:id.
func (h *Handler) Update(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	application, err := h.svc.Update(c.Request.Context(), id, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, ToAppResponse(application))
}

// Delete handles DELETE /apps/:id.
func (h *Handler) Delete(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// UpdateStatus handles PUT /apps/:id/status.
func (h *Handler) UpdateStatus(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	if err := h.svc.UpdateStatus(c.Request.Context(), id, req.Status); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// GetProtocolConfig handles GET /apps/:id/config.
func (h *Handler) GetProtocolConfig(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	config, err := h.svc.GetProtocolConfig(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, config)
}

// UpdateProtocolConfig handles PUT /apps/:id/config.
func (h *Handler) UpdateProtocolConfig(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateProtocolConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	if err := h.svc.UpdateProtocolConfig(c.Request.Context(), id, req.ProtocolConfig); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// --- Access Handlers ---

// ListAccess handles GET /apps/:id/access.
func (h *Handler) ListAccess(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	accesses, err := h.svc.ListAccess(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]*AppAccessResponse, len(accesses))
	for i, a := range accesses {
		items[i] = ToAppAccessResponse(a)
	}

	response.OK(c, items)
}

// AddAccess handles POST /apps/:id/access.
func (h *Handler) AddAccess(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req AddAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	access, err := h.svc.AddAccess(c.Request.Context(), id, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.Created(c, ToAppAccessResponse(access))
}

// RemoveAccess handles DELETE /apps/:id/access/:aid.
func (h *Handler) RemoveAccess(c *gin.Context) {
	aid, ok := ginutil.ParseInt64Param(c, "aid")
	if !ok {
		return
	}

	if err := h.svc.RemoveAccess(c.Request.Context(), aid); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// --- Cert Handlers ---

// ListCerts handles GET /apps/:id/certs.
func (h *Handler) ListCerts(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	certs, err := h.svc.ListCerts(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]*AppCertResponse, len(certs))
	for i, cert := range certs {
		items[i] = ToAppCertResponse(cert)
	}

	response.OK(c, items)
}

// CreateCert handles POST /apps/:id/certs (stub for now).
func (h *Handler) CreateCert(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	cert, err := h.svc.CreateCert(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.Created(c, ToAppCertResponse(cert))
}

// DeleteCert handles DELETE /apps/:id/certs/:cid.
func (h *Handler) DeleteCert(c *gin.Context) {
	cid, ok := ginutil.ParseInt64Param(c, "cid")
	if !ok {
		return
	}

	if err := h.svc.DeleteCert(c.Request.Context(), cid); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// --- Group Handlers ---

// ListGroups handles GET /app-groups.
func (h *Handler) ListGroups(c *gin.Context) {
	groups, err := h.svc.ListGroups(c.Request.Context(), tenantctx.FromContext(c, h.tenantID))
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]*AppGroupResponse, len(groups))
	for i, g := range groups {
		items[i] = ToAppGroupResponse(g)
	}

	response.OK(c, items)
}

// CreateGroup handles POST /app-groups.
func (h *Handler) CreateGroup(c *gin.Context) {
	var req AppGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	group, err := h.svc.CreateGroup(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.Created(c, ToAppGroupResponse(group))
}

// UpdateGroup handles PUT /app-groups/:id.
func (h *Handler) UpdateGroup(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateAppGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	group, err := h.svc.UpdateGroup(c.Request.Context(), id, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, ToAppGroupResponse(group))
}

// DeleteGroup handles DELETE /app-groups/:id.
func (h *Handler) DeleteGroup(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	if err := h.svc.DeleteGroup(c.Request.Context(), id); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// AddAppToGroup handles POST /app-groups/:id/apps.
func (h *Handler) AddAppToGroup(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req AddAppToGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	if err := h.svc.AddAppToGroup(c.Request.Context(), groupID, req.AppID); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.Created(c, nil)
}

// RemoveAppFromGroup handles DELETE /app-groups/:id/apps/:aid.
func (h *Handler) RemoveAppFromGroup(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	appID, ok := ginutil.ParseInt64Param(c, "aid")
	if !ok {
		return
	}

	if err := h.svc.RemoveAppFromGroup(c.Request.Context(), groupID, appID); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// ListTemplates handles GET /app-templates — the built-in onboarding catalog.
func (h *Handler) ListTemplates(c *gin.Context) {
	response.OK(c, ToTemplateListItems(Templates()))
}

// GetTemplate handles GET /app-templates/:key — full template detail.
func (h *Handler) GetTemplate(c *gin.Context) {
	tpl, err := GetTemplate(c.Param("key"))
	if err != nil {
		if errors.Is(err, ErrTemplateNotFound) {
			response.NotFound(c, 40407, "template not found")
			return
		}
		response.InternalError(c, "get template failed", err)
		return
	}
	response.OK(c, tpl)
}

// handleServiceError maps service errors to HTTP responses.
// handleServiceError maps a domain error to its response via the errcode
// registry (see errcodes.go for the app-domain bindings).
func (h *Handler) handleServiceError(c *gin.Context, err error) {
	response.MapError(c, err)
}

// RotateSigningKey handles POST /apps/:id/rotate-signing-key.
//
// Mints a new RSA-2048 signing key and demotes the previous active key to
// rotating. JWKS continues to publish both keys until the previous key
// expires so RPs that cached the old public material can still verify
// in-flight id_tokens.
func (h *Handler) RotateSigningKey(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	cert, err := h.svc.RotateSigningKey(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, ToAppCertResponse(cert))
}

// ImportSAMLMetadata handles POST /apps/:id/saml/import-metadata.
//
// Body: the raw SP metadata XML (EntityDescriptor). Capped at 256 KB so a
// malicious upload can't OOM the parser.
//
// Returns the resulting protocol_config map so the SPA can immediately
// refresh the form without re-fetching.
func (h *Handler) ImportSAMLMetadata(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	const maxMetadataBytes = 256 * 1024
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxMetadataBytes)
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		response.BadRequest(c, 40001, "read body: "+err.Error())
		return
	}
	if len(raw) == 0 {
		response.BadRequest(c, 40002, "empty metadata document")
		return
	}
	cfg, err := h.svc.ImportSAMLSPMetadata(c.Request.Context(), id, raw)
	if err != nil {
		// Schema errors are 400 (operator-fixable); everything else is 500.
		// 40011 (NOT 40003) — 40003 collides with the frontend's global
		// totpCodeReused localization; the SAML schema message is safe to show.
		var schemaErr saml.ErrInvalidSPMetadata
		if errors.As(err, &schemaErr) {
			response.BadRequest(c, 40011, err.Error())
			return
		}
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, cfg)
}

// RegenerateClientSecret handles POST /apps/:id/regenerate-secret.
//
// The plaintext client_secret is returned exactly once. Subsequent reads
// expose only the bcrypt hash (in fact never echoed in any response).
func (h *Handler) RegenerateClientSecret(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	result, err := h.svc.RotateClientSecret(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	response.OK(c, map[string]string{
		"client_secret": result.ClientSecretPlain,
	})
}

// Quickstart handles GET /apps/:id/quickstart/:lang. Returns a
// copy-pasteable code sample for integrating the app's OIDC client
// in the requested language. lang ∈ {curl, go, node, python}.
func (h *Handler) Quickstart(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	lang := c.Param("lang")

	application, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	if application.Protocol != ProtocolOIDC {
		response.BadRequest(c, 40011, "quickstart available for OIDC apps only")
		return
	}

	sample, err := renderQuickstart(lang, application, c.Request.Host, isHTTPS(c.Request.URL.Scheme))
	if err != nil {
		response.BadRequest(c, 40012, err.Error())
		return
	}
	response.OK(c, map[string]string{
		"language": lang,
		"sample":   sample,
	})
}

func isHTTPS(scheme string) bool { return scheme == "https" }
