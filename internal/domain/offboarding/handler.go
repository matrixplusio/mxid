package offboarding

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler exposes the offboarding console API.
type Handler struct {
	svc      *Service
	tenantID int64 // default tenant for single-tenant deployments
}

// NewHandler creates the offboarding HTTP handler.
func NewHandler(svc *Service, defaultTenantID int64) *Handler {
	return &Handler{svc: svc, tenantID: defaultTenantID}
}

// RegisterRoutes mounts the offboard action + review-panel reads.
//
// The offboard action is gated by user.update (a user-management write, also
// high-risk → covered by the console step-up MFA chain). The review panel is
// read-only under user.read; marking an item done is a user.update.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/users/:id/offboard", authz.Require("user.update", nil), h.Offboard)

	off := rg.Group("/offboarding")
	{
		off.GET("/tasks", authz.Require("user.read", nil), h.ListTasks)
		off.GET("/tasks/:id/items", authz.Require("user.read", nil), h.ListItems)
		off.POST("/items/:id/done", authz.Require("user.update", nil), h.MarkItemDone)
	}
}

// Offboard handles POST /users/:id/offboard — one-click access cutoff for a
// departing user (disable account + back-channel logout + kill all sessions),
// plus a review checklist of the user's app footprint.
func (h *Handler) Offboard(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid user id")
		return
	}
	if err := h.svc.Offboard(c.Request.Context(), id, actorID(c)); err != nil {
		response.InternalError(c, "offboard failed")
		return
	}
	response.OK(c, gin.H{"offboarded": true})
}

// ListTasks handles GET /offboarding/tasks — the review panel listing.
func (h *Handler) ListTasks(c *gin.Context) {
	tenantID := tenantctx.FromContext(c, h.tenantID)
	limit := atoiDefault(c.Query("page_size"), 20)
	page := atoiDefault(c.Query("page"), 1)
	if page < 1 {
		page = 1
	}
	tasks, total, err := h.svc.ListTasks(c.Request.Context(), tenantID, limit, (page-1)*limit)
	if err != nil {
		response.InternalError(c, "list offboarding tasks failed")
		return
	}
	response.OK(c, gin.H{"items": tasks, "total": total, "page": page, "page_size": limit})
}

// ListItems handles GET /offboarding/tasks/:id/items.
func (h *Handler) ListItems(c *gin.Context) {
	taskID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid task id")
		return
	}
	tenantID := tenantctx.FromContext(c, h.tenantID)
	items, err := h.svc.ListItems(c.Request.Context(), tenantID, taskID)
	if err != nil {
		response.InternalError(c, "list offboarding items failed")
		return
	}
	response.OK(c, gin.H{"items": items})
}

// MarkItemDone handles POST /offboarding/items/:id/done.
func (h *Handler) MarkItemDone(c *gin.Context) {
	itemID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid item id")
		return
	}
	tenantID := tenantctx.FromContext(c, h.tenantID)
	if err := h.svc.MarkItemDone(c.Request.Context(), tenantID, itemID, actorID(c)); err != nil {
		response.InternalError(c, "mark item done failed")
		return
	}
	response.OK(c, gin.H{"done": true})
}

func actorID(c *gin.Context) int64 {
	if v, ok := c.Get("user_id"); ok {
		if id, ok := v.(int64); ok {
			return id
		}
	}
	return 0
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}
