package provisioning

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Module bundles the provisioning service + handler.
type Module struct {
	Service *Service
	handler *Handler
}

// Register builds the provisioning module from the bootstrap app.
func Register(app *bootstrap.App) *Module {
	svc := NewService(NewRepository(app.DB), app.MasterKey)
	return &Module{Service: svc, handler: NewHandler(svc, app.Config.Tenant.DefaultID)}
}

// RegisterRoutes mounts the per-app provisioning config endpoints on the console
// group (after its middleware chain).
func (m *Module) RegisterRoutes(app *bootstrap.App) {
	m.handler.RegisterRoutes(app.ConsoleGroup)
}

// Handler serves the per-app provisioning config API.
type Handler struct {
	svc      *Service
	tenantID int64
}

// NewHandler builds the handler.
func NewHandler(svc *Service, defaultTenantID int64) *Handler {
	return &Handler{svc: svc, tenantID: defaultTenantID}
}

// RegisterRoutes mounts GET/PUT /apps/:id/provisioning. Gated by app.read /
// app.update; the SCIM connector that uses this config is EE + license-gated.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/apps/:id/provisioning", authz.Require("app.read", nil), h.Get)
	rg.PUT("/apps/:id/provisioning", authz.Require("app.update", nil), h.Put)
}

// Get returns the app's provisioning config (token never echoed).
func (h *Handler) Get(c *gin.Context) {
	appID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid app id")
		return
	}
	v, err := h.svc.Get(c.Request.Context(), appID)
	if err != nil {
		response.InternalError(c, "load provisioning config failed")
		return
	}
	response.OK(c, v)
}

type putProvisioningRequest struct {
	Enabled   bool   `json:"enabled"`
	Connector string `json:"connector"`
	BaseURL   string `json:"base_url"`
	Token     string `json:"token"` // blank = keep existing
}

// Put updates the app's provisioning config.
func (h *Handler) Put(c *gin.Context) {
	appID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid app id")
		return
	}
	var req putProvisioningRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	if err := h.svc.Save(c.Request.Context(), SaveInput{
		AppID:     appID,
		TenantID:  tenantctx.FromContext(c, h.tenantID),
		Enabled:   req.Enabled,
		Connector: req.Connector,
		BaseURL:   req.BaseURL,
		Token:     req.Token,
	}); err != nil {
		response.InternalError(c, "save provisioning config failed")
		return
	}
	response.OK(c, gin.H{"saved": true})
}
