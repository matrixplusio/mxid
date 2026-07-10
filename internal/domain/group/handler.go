package group

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/idstr"
	"github.com/imkerbos/mxid/pkg/pagination"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// Handler handles HTTP requests for user groups.
type Handler struct {
	service  *Service
	tenantID int64
}

// NewHandler creates a new user group handler.
func NewHandler(service *Service, tenantID int64) *Handler {
	return &Handler{
		service:  service,
		tenantID: tenantID,
	}
}

// List returns paginated user groups.
func (h *Handler) List(c *gin.Context) {
	p := pagination.Parse(c)
	keyword := c.Query("keyword")
	groups, total, err := h.service.List(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), keyword, p.Page, p.PageSize)
	if err != nil {
		response.InternalError(c, "failed to list user groups", err)
		return
	}

	response.Paginated(c, groups, total, p.Page, p.PageSize)
}

// ListByUser returns every group the given user belongs to.
//
// Routed as GET /users/:id/groups in the user-scoped section of the API so
// callers don't need to know which domain owns the join. The frontend uses
// this on the user detail page.
func (h *Handler) ListByUser(c *gin.Context) {
	userID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	groups, err := h.service.ListByUserID(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), userID)
	if err != nil {
		response.InternalError(c, "failed to list groups for user", err)
		return
	}

	response.OK(c, groups)
}

// Create creates a new user group.
func (h *Handler) Create(c *gin.Context) {
	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	g, err := h.service.Create(c.Request.Context(), tenantctx.FromContext(c, h.tenantID), &req)
	if err != nil {
		response.InternalError(c, "failed to create user group", err)
		return
	}

	response.Created(c, ToGroupResponse(g, 0))
}

// Get retrieves a single user group by ID.
func (h *Handler) Get(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	g, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		response.MapError(c, err)
		return
	}

	count, err := h.service.CountMembers(c.Request.Context(), g.ID)
	if err != nil {
		response.InternalError(c, "failed to count members", err)
		return
	}

	response.OK(c, ToGroupResponse(g, count))
}

// Update updates a user group.
func (h *Handler) Update(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	g, err := h.service.Update(c.Request.Context(), id, &req)
	if err != nil {
		response.MapError(c, err)
		return
	}

	count, err := h.service.CountMembers(c.Request.Context(), g.ID)
	if err != nil {
		response.InternalError(c, "failed to count members", err)
		return
	}

	response.OK(c, ToGroupResponse(g, count))
}

// Delete soft-deletes a user group. Pass ?force=true to delete a group that
// still has members (members are cascaded via the FK ON DELETE CASCADE).
func (h *Handler) Delete(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	force := c.Query("force") == "true"

	if err := h.service.Delete(c.Request.Context(), id, force); err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, nil)
}

// GetMembers returns paginated members of a group with enriched user info.
func (h *Handler) GetMembers(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	p := pagination.Parse(c)
	members, total, err := h.service.GetMembers(c.Request.Context(), id, p.Page, p.PageSize)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.Paginated(c, members, total, p.Page, p.PageSize)
}

// AddMember adds a user to a group.
func (h *Handler) AddMember(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
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

// BatchAddMembers adds many users to a group in one call. Users that already
// belong appear in `skipped`, not as failures.
func (h *Handler) BatchAddMembers(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req BatchMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	userIDs, err := idstr.ParseList(req.UserIDs)
	if err != nil {
		// Malformed id list is a bad request body, not a service error. 40001
		// (not 40003) — 40003 collides with the frontend's global
		// totpCodeReused localization and would misrender the message.
		response.BadRequest(c, 40001, "invalid user id list")
		return
	}

	res, err := h.service.AddMembers(c.Request.Context(), id, userIDs)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, res)
}

// RemoveMember removes a user from a group.
func (h *Handler) RemoveMember(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	userID, ok := ginutil.ParseInt64Param(c, "uid")
	if !ok {
		return
	}

	if err := h.service.RemoveMember(c.Request.Context(), groupID, userID); err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, nil)
}

// BatchRemoveMembers removes many users from a group in one call. Users that
// were not members appear in `skipped`.
func (h *Handler) BatchRemoveMembers(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req BatchMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	userIDs, err := idstr.ParseList(req.UserIDs)
	if err != nil {
		// Malformed id list is a bad request body, not a service error. 40001
		// (not 40003) — 40003 collides with the frontend's global
		// totpCodeReused localization and would misrender the message.
		response.BadRequest(c, 40001, "invalid user id list")
		return
	}

	res, err := h.service.RemoveMembers(c.Request.Context(), id, userIDs)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, res)
}

// GetRule handles GET /groups/:id/rule. 404 when the group has no rule
// (a static group, or a dynamic group whose rule was just removed).
func (h *Handler) GetRule(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	rule, err := h.service.GetRule(c.Request.Context(), id)
	if err != nil {
		response.MapError(c, err)
		return
	}
	resp, err := toRuleResponse(rule)
	if err != nil {
		response.InternalError(c, "failed to decode rule", err)
		return
	}
	response.OK(c, resp)
}

// UpsertRule handles PUT /groups/:id/rule. Validates the rule, persists it,
// flips the group to dynamic, and runs an initial sync.
func (h *Handler) UpsertRule(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	expr, err := ValidateRule(body)
	if err != nil {
		// 40010 (codeBadRule), NOT 40003 — 40003 collides with the frontend's
		// global totpCodeReused localization. Rule errors carry safe, specific
		// messages (bad field/operator/value, or a JSON decode error).
		response.BadRequest(c, 40010, err.Error())
		return
	}
	rule, err := h.service.UpsertRule(c.Request.Context(), id, expr)
	if err != nil {
		response.MapError(c, err)
		return
	}
	resp, derr := toRuleResponse(rule)
	if derr != nil {
		response.InternalError(c, "failed to decode rule", derr)
		return
	}
	response.OK(c, resp)
}

// DeleteRule handles DELETE /groups/:id/rule. Removes the rule and flips
// the group back to static. Existing members are preserved.
func (h *Handler) DeleteRule(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := h.service.DeleteRule(c.Request.Context(), id); err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, nil)
}

// SyncRule handles POST /groups/:id/sync. Recomputes membership from the
// attached rule. Returns a report with how many users were added/removed.
func (h *Handler) SyncRule(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	report, err := h.service.SyncRule(c.Request.Context(), id)
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, report)
}

// RuleFields handles GET /groups/rule-fields. Returns the allow-list of
// fields and their permitted comparison operators so the frontend rule
// editor knows what to render in the dropdowns.
func (h *Handler) RuleFields(c *gin.Context) {
	response.OK(c, AllowedRuleFields())
}

// toRuleResponse decodes a stored UserGroupRule into the API view.
func toRuleResponse(rule *UserGroupRule) (*RuleResponse, error) {
	var expr RuleExpr
	if err := json.Unmarshal(rule.Expr, &expr); err != nil {
		return nil, fmt.Errorf("unmarshal rule: %w", err)
	}
	return &RuleResponse{
		GroupID:         rule.GroupID,
		Expr:            expr,
		Status:          rule.Status,
		LastSyncAt:      rule.LastSyncAt,
		LastSyncAdded:   rule.LastSyncAdded,
		LastSyncRemoved: rule.LastSyncRemoved,
		LastSyncError:   rule.LastSyncError,
	}, nil
}
