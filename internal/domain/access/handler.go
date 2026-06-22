package access

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/middleware"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler exposes the JIT privileged-access endpoints for the console (admin)
// and portal (end-user) gateways.
type Handler struct {
	svc        *Service
	defaultTID int64
}

// NewHandler constructs a Handler. defaultTID is the single-tenant fallback
// used when no tenant_id is present in the request context (CE mode).
func NewHandler(svc *Service, defaultTID int64) *Handler {
	return &Handler{svc: svc, defaultTID: defaultTID}
}

func (h *Handler) tenantID(c *gin.Context) int64 {
	return tenantctx.FromContext(c, h.defaultTID)
}

func (h *Handler) userID(c *gin.Context) int64 {
	if v, ok := c.Get("user_id"); ok {
		if id, ok := v.(int64); ok {
			return id
		}
	}
	return 0
}

// RegisterConsole wires admin-facing JIT routes onto rg.
// All routes are gated by the conditional_access feature flag plus the
// appropriate authz permission.
//
//	GET    /access-eligibilities            — access.eligibility.manage
//	POST   /access-eligibilities            — access.eligibility.manage
//	DELETE /access-eligibilities/:id        — access.eligibility.manage
//	GET    /access-requests                 — access.request.approve
//	POST   /access-requests/:id/approve     — access.request.approve
//	POST   /access-requests/:id/reject      — access.request.approve
//	POST   /access-requests/:id/revoke      — access.request.approve
func (h *Handler) RegisterConsole(rg *gin.RouterGroup) {
	el := rg.Group("/access-eligibilities",
		middleware.RequireFeature(license.FeatureConditionalAccess),
		authz.Require("access.eligibility.manage", nil),
	)
	{
		el.GET("", h.listEligibility)
		el.POST("", h.createEligibility)
		el.DELETE("/:id", h.deleteEligibility)
	}

	rq := rg.Group("/access-requests",
		middleware.RequireFeature(license.FeatureConditionalAccess),
		authz.Require("access.request.approve", nil),
	)
	{
		rq.GET("", h.listRequests)
		rq.POST("/:id/approve", h.approve)
		rq.POST("/:id/reject", h.reject)
		rq.POST("/:id/revoke", h.revoke)
	}
}

// RegisterPortal wires end-user-facing JIT routes onto rg.
// All routes are gated by the conditional_access feature flag.
// Individual request ownership is enforced inside the service layer.
//
//	GET  /access-eligibilities        — list eligibilities visible to the caller
//	GET  /access-requests             — list my requests
//	POST /access-requests             — create a request
//	POST /access-requests/:id/cancel  — cancel my pending request
func (h *Handler) RegisterPortal(rg *gin.RouterGroup) {
	feat := middleware.RequireFeature(license.FeatureConditionalAccess)

	rg.GET("/access-eligibilities", feat, h.myEligibilities)

	rq := rg.Group("/access-requests", feat)
	{
		rq.GET("", h.myRequests)
		rq.POST("", h.createRequest)
		rq.POST("/:id/cancel", h.cancel)
	}
}

// ─── console handlers ─────────────────────────────────────────────────────────

func (h *Handler) createEligibility(c *gin.Context) {
	var body CreateEligibilityRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, err.Error())
		return
	}
	uid := h.userID(c)
	e, err := h.svc.CreateEligibility(c.Request.Context(), h.tenantID(c), &uid, body)
	if err != nil {
		response.BadRequest(c, 40003, err.Error())
		return
	}
	response.Created(c, e)
}

func (h *Handler) listEligibility(c *gin.Context) {
	// h.svc.repo is unexported but handler is in the same package — compiles cleanly.
	rows, err := h.svc.repo.ListEligibility(c.Request.Context(), h.tenantID(c))
	if err != nil {
		response.InternalError(c, "list eligibility failed")
		return
	}
	response.OK(c, rows)
}

func (h *Handler) deleteEligibility(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.svc.repo.DeleteEligibility(c.Request.Context(), id, h.tenantID(c)); err != nil {
		response.InternalError(c, "delete failed")
		return
	}
	response.NoContent(c)
}

func (h *Handler) listRequests(c *gin.Context) {
	status := c.DefaultQuery("status", StatusPending)
	rows, err := h.svc.repo.ListRequestsByStatus(c.Request.Context(), h.tenantID(c), status)
	if err != nil {
		response.InternalError(c, "list requests failed")
		return
	}
	response.OK(c, rows)
}

func (h *Handler) approve(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var body DecisionRequest
	_ = c.ShouldBindJSON(&body)
	out, err := h.svc.Approve(c.Request.Context(), h.tenantID(c), id, h.userID(c), body.Reason)
	if err != nil {
		response.BadRequest(c, 40004, err.Error())
		return
	}
	response.OK(c, out)
}

func (h *Handler) reject(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var body DecisionRequest
	_ = c.ShouldBindJSON(&body)
	if err := h.svc.Reject(c.Request.Context(), h.tenantID(c), id, h.userID(c), body.Reason); err != nil {
		response.BadRequest(c, 40005, err.Error())
		return
	}
	response.OK(c, gin.H{"status": StatusRejected})
}

func (h *Handler) revoke(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.svc.Revoke(c.Request.Context(), h.tenantID(c), id, h.userID(c)); err != nil {
		response.BadRequest(c, 40006, err.Error())
		return
	}
	response.OK(c, gin.H{"status": StatusRevoked})
}

// ─── portal handlers ──────────────────────────────────────────────────────────

func (h *Handler) myEligibilities(c *gin.Context) {
	rows, err := h.svc.ListEligibilityForRequester(c.Request.Context(), h.tenantID(c), h.userID(c))
	if err != nil {
		response.InternalError(c, "list failed")
		return
	}
	response.OK(c, rows)
}

func (h *Handler) myRequests(c *gin.Context) {
	rows, err := h.svc.repo.ListRequestsByRequester(c.Request.Context(), h.userID(c), h.tenantID(c))
	if err != nil {
		response.InternalError(c, "list failed")
		return
	}
	response.OK(c, rows)
}

func (h *Handler) createRequest(c *gin.Context) {
	var body CreateAccessRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, err.Error())
		return
	}
	out, err := h.svc.CreateRequest(c.Request.Context(), h.tenantID(c), h.userID(c), body)
	if err != nil {
		response.BadRequest(c, 40003, err.Error())
		return
	}
	response.OK(c, out)
}

func (h *Handler) cancel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.svc.Cancel(c.Request.Context(), h.tenantID(c), id, h.userID(c)); err != nil {
		response.BadRequest(c, 40006, err.Error())
		return
	}
	response.OK(c, gin.H{"status": StatusCancelled})
}
