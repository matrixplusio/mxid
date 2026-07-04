package org

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/pagination"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler handles HTTP requests for organizations.
type Handler struct {
	service  *Service
	tenantID int64
}

// NewHandler creates a new organization handler.
func NewHandler(service *Service, tenantID int64) *Handler {
	return &Handler{
		service:  service,
		tenantID: tenantID,
	}
}

// GetTree returns the full organization tree.
func (h *Handler) GetTree(c *gin.Context) {
	tree, err := h.service.GetTree(c.Request.Context(), tenantctx.FromContext(c, h.tenantID))
	if err != nil {
		response.InternalError(c, "failed to get organization tree", err)
		return
	}
	response.OK(c, tree)
}

// Create creates a new organization.
func (h *Handler) Create(c *gin.Context) {
	var req CreateOrgRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	org, err := h.service.Create(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), &req)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.Created(c, ToOrgResponse(org))
}

// Get retrieves a single organization by ID.
func (h *Handler) Get(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40002, "invalid organization id")
		return
	}

	org, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, ToOrgResponse(org))
}

// Update updates an organization.
func (h *Handler) Update(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40002, "invalid organization id")
		return
	}

	var req UpdateOrgRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	org, err := h.service.Update(c.Request.Context(), id, &req)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, ToOrgResponse(org))
}

// Delete soft-deletes an organization.
func (h *Handler) Delete(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40002, "invalid organization id")
		return
	}

	if err := h.service.Delete(c.Request.Context(), id); err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, nil)
}

// Move moves an organization to a new parent.
func (h *Handler) Move(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40002, "invalid organization id")
		return
	}

	var req MoveOrgRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	if err := h.service.Move(c.Request.Context(), id, &req); err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, nil)
}

// GetMembers returns paginated members of an organization.
func (h *Handler) GetMembers(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40002, "invalid organization id")
		return
	}

	p := pagination.Parse(c)
	userIDs, total, err := h.service.GetMembers(c.Request.Context(), id, p.Page, p.PageSize)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.Paginated(c, userIDs, total, p.Page, p.PageSize)
}

// AddMember adds a user to an organization.
func (h *Handler) AddMember(c *gin.Context) {
	id, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40002, "invalid organization id")
		return
	}

	var req AddMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	if err := h.service.AddMember(c.Request.Context(), id, &req); err != nil {
		response.MapError(c, err)
		return
	}

	response.Created(c, nil)
}

// RemoveMember removes a user from an organization.
func (h *Handler) RemoveMember(c *gin.Context) {
	orgID, err := parseID(c, "id")
	if err != nil {
		response.BadRequest(c, 40002, "invalid organization id")
		return
	}

	userID, err := parseID(c, "uid")
	if err != nil {
		response.BadRequest(c, 40003, "invalid user id")
		return
	}

	if err := h.service.RemoveMember(c.Request.Context(), userID, orgID); err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, nil)
}

// parseID parses an int64 ID from a URL parameter.
func parseID(c *gin.Context, param string) (int64, error) {
	return strconv.ParseInt(c.Param(param), 10, 64)
}
