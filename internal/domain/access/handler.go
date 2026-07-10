package access

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/middleware"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// StepUpEnforcer lets the approve handler force a fresh step-up MFA challenge
// on eligibilities configured with require_stepup=true — a PAM guarantee that
// must hold even when the tenant's ambient MFA policy would not otherwise
// gate this route. Implemented by authn.StepUpChecker (structural match, no
// import needed on the authn side) and wired in app/run.go from the same
// collaborators as authn.StepUpMiddleware.
type StepUpEnforcer interface {
	// Fresh reports whether the current console session has a step-up MFA
	// within the tenant's configured step-up window.
	Fresh(c *gin.Context, tenantID int64) bool
	// HasMFA reports whether userID has any MFA factor enrolled.
	HasMFA(ctx context.Context, userID int64) (bool, error)
}

// Handler exposes the JIT privileged-access endpoints for the console (admin)
// and portal (end-user) gateways.
type Handler struct {
	svc        *Service
	defaultTID int64
	stepUp     StepUpEnforcer
}

// NewHandler constructs a Handler. defaultTID is the single-tenant fallback
// used when no tenant_id is present in the request context (CE mode).
// stepUp may be nil — approve then falls back to the eligibility's
// require_stepup being unenforceable at this layer (only the global
// StepUpMiddleware applies), which production wiring must never do; tests
// that don't care about step-up may still pass nil for eligibilities with
// require_stepup=false.
func NewHandler(svc *Service, defaultTID int64, stepUp StepUpEnforcer) *Handler {
	return &Handler{svc: svc, defaultTID: defaultTID, stepUp: stepUp}
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
//	PUT    /access-eligibilities/:id        — access.eligibility.manage
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
		el.PUT("/:id", h.updateEligibility)
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

// Error codes. Request-body bind failures keep their per-operation literal
// codes below; every SERVICE error now flows through response.MapError, which
// renders the domain sentinel bound in errcodes.go — so the failure cause maps
// to a stable code by error identity, not by call site, and an unexpected/DB
// error becomes a logged 500 instead of leaking its text under a 400.
//
// Bind-failure codes (literal, this file):
//	40002 — createEligibility: bad request body
//	40008 — createRequest (portal): bad request body
//	40010 — updateEligibility: bad request body
//	40101 — createRequest (portal): no authenticated user in context
//
// Service-error codes (bound sentinels, see errcodes.go):
//	40020 — invalid eligibility configuration (ErrInvalidEligibility)
//	40021 — request not allowed by policy (ErrRequestNotAllowed)
//	40022 — request no longer pending (ErrRequestNotPending)
//	40023 — request cannot be cancelled (ErrRequestNotCancellable)
//	40024 — grant cannot be revoked (ErrGrantNotRevocable)
//	40012 — approve: self-approval refused, SoD (ErrSelfApproval, 403)
//	40013 — approve: approver not eligible (ErrApproverNotEligible, 403)
//	40410 — request not found (ErrRequestNotFound)
//	40411 — eligibility not found (ErrEligibilityNotFound)

// ─── console handlers ─────────────────────────────────────────────────────────

func (h *Handler) createEligibility(c *gin.Context) {
	var body CreateEligibilityRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	uid := h.userID(c)
	e, err := h.svc.CreateEligibility(c.Request.Context(), h.tenantID(c), &uid, body)
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.Created(c, e)
}

func (h *Handler) updateEligibility(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body CreateEligibilityRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40010, "invalid request body")
		return
	}
	e, err := h.svc.UpdateEligibility(c.Request.Context(), h.tenantID(c), id, body)
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, e)
}

func (h *Handler) listEligibility(c *gin.Context) {
	// h.svc.repo is unexported but handler is in the same package — compiles cleanly.
	rows, err := h.svc.repo.ListEligibility(c.Request.Context(), h.tenantID(c))
	if err != nil {
		response.InternalError(c, "list eligibility failed", err)
		return
	}
	response.OK(c, rows)
}

func (h *Handler) deleteEligibility(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteEligibility(c.Request.Context(), id, h.tenantID(c)); err != nil {
		response.InternalError(c, "delete failed", err)
		return
	}
	response.NoContent(c)
}

func (h *Handler) listRequests(c *gin.Context) {
	status := c.DefaultQuery("status", StatusPending)
	rows, err := h.svc.repo.ListRequestsByStatus(c.Request.Context(), h.tenantID(c), status)
	if err != nil {
		response.InternalError(c, "list requests failed", err)
		return
	}
	response.OK(c, rows)
}

func (h *Handler) approve(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body DecisionRequest
	_ = c.ShouldBindJSON(&body)

	ctx := c.Request.Context()
	tenantID := h.tenantID(c)

	// PAM guarantee: an eligibility marked require_stepup=true demands a fresh
	// step-up MFA on the APPROVER regardless of the tenant's ambient MFA
	// policy mode — the global StepUpMiddleware already covers this route
	// when the policy applies, but require_stepup must hold unconditionally.
	req, err := h.svc.repo.GetRequest(ctx, id, tenantID)
	if err != nil {
		response.MapError(c, err)
		return
	}
	elig, err := h.svc.repo.GetEligibility(ctx, req.EligibilityID, tenantID)
	if err != nil {
		response.MapError(c, err)
		return
	}
	if elig.RequireStepUp && (h.stepUp == nil || !h.stepUp.Fresh(c, tenantID)) {
		if h.stepUp == nil {
			response.Forbidden(c, authn.CodeStepUpRequired, "step-up mfa required for this operation")
			return
		}
		enrolled, mfaErr := h.stepUp.HasMFA(ctx, h.userID(c))
		if mfaErr != nil {
			response.InternalError(c, "mfa status check failed", mfaErr)
			return
		}
		if !enrolled {
			response.Forbidden(c, authn.CodeMFAEnrollRequired, "mfa enrollment required for this operation")
			return
		}
		response.Forbidden(c, authn.CodeStepUpRequired, "step-up mfa required for this operation")
		return
	}

	out, err := h.svc.Approve(ctx, tenantID, id, h.userID(c), body.Reason)
	if err != nil {
		// MapError routes each bound sentinel to its code: ErrSelfApproval and
		// ErrApproverNotEligible are separation-of-duties refusals bound to 403
		// (40012/40013, localized by the console), ErrRequestNotPending to 400,
		// and any unexpected/DB error to a logged 500 that never leaks internals.
		response.MapError(c, err)
		return
	}
	response.OK(c, out)
}

func (h *Handler) reject(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body DecisionRequest
	_ = c.ShouldBindJSON(&body)
	if err := h.svc.Reject(c.Request.Context(), h.tenantID(c), id, h.userID(c), body.Reason); err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, gin.H{"status": StatusRejected})
}

func (h *Handler) revoke(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := h.svc.Revoke(c.Request.Context(), h.tenantID(c), id, h.userID(c)); err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, gin.H{"status": StatusRevoked})
}

// ─── portal handlers ──────────────────────────────────────────────────────────

func (h *Handler) myEligibilities(c *gin.Context) {
	rows, err := h.svc.ListEligibilityForRequester(c.Request.Context(), h.tenantID(c), h.userID(c))
	if err != nil {
		response.InternalError(c, "list failed", err)
		return
	}
	response.OK(c, rows)
}

func (h *Handler) myRequests(c *gin.Context) {
	rows, err := h.svc.repo.ListRequestsByRequester(c.Request.Context(), h.userID(c), h.tenantID(c))
	if err != nil {
		response.InternalError(c, "list failed", err)
		return
	}
	response.OK(c, rows)
}

func (h *Handler) createRequest(c *gin.Context) {
	var body CreateAccessRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40008, "invalid request body")
		return
	}
	uid := h.userID(c)
	if uid == 0 {
		// Auth middleware normally guarantees a caller identity; defend here so
		// a misconfigured route never creates a request with requester_id=0.
		response.Unauthorized(c, 40101, "authentication required")
		return
	}
	out, err := h.svc.CreateRequest(c.Request.Context(), h.tenantID(c), uid, body)
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.Created(c, out)
}

func (h *Handler) cancel(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := h.svc.Cancel(c.Request.Context(), h.tenantID(c), id, h.userID(c)); err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, gin.H{"status": StatusCancelled})
}
