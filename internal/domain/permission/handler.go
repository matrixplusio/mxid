package permission

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/idstr"
	"github.com/imkerbos/mxid/pkg/pagination"
	"github.com/imkerbos/mxid/pkg/response"
)

// Handler handles HTTP requests for the permission domain.
type Handler struct {
	svc *Service
}

// NewHandler creates a new permission handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes registers permission routes on the given router group.
//
// Role and permission management routes are gated globally — there's no
// natural scope target on a role definition (a role lives at the tenant
// level). The privilege-escalation guard on POST /roles/:id/members is
// enforced inside the service: it checks the caller's effective permissions
// against the role being assigned and refuses if the caller would be
// handing out perms beyond their own set.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	roles := rg.Group("/roles")
	{
		roles.GET("", authz.Require("role.read", nil), h.ListRoles)
		roles.POST("", authz.Require("role.create", nil), h.CreateRole)
		roles.GET("/:id", authz.Require("role.read", nil), h.GetRole)
		roles.PUT("/:id", authz.Require("role.update", nil), h.UpdateRole)
		roles.DELETE("/:id", authz.Require("role.delete", nil), h.DeleteRole)
		roles.GET("/:id/permissions", authz.Require("role.read", nil), h.GetPermissions)
		roles.PUT("/:id/permissions", authz.Require("role.permission.manage", nil), h.SetPermissions)
		roles.GET("/:id/members", authz.Require("role.read", nil), h.ListMembers)
		roles.POST("/:id/members", authz.Require("role.assign", nil), h.AddMember)
		roles.DELETE("/:id/members/:mid", authz.Require("role.assign", nil), h.RemoveMember)
	}

	rg.GET("/permissions", authz.Require("role.read", nil), h.ListAllPermissions)
}

// checkAssignAllowed enforces the privilege-escalation guard on POST
// /roles/:id/members. Compares the role being assigned against the caller's
// effective permissions resolved by authz.
//
// Pulls authz.Service from gin context (installed at app boot) so this
// package does not import authz-aware app wiring — the dependency arrives
// at request time through the middleware chain.
//
// Returns nil if assignment is allowed.
func (h *Handler) checkAssignAllowed(c *gin.Context, roleID int64, req *AddMemberRequest) error {
	svc := authz.FromContext(c)
	if svc == nil {
		// Engine not installed (e.g. tests). Fail open here would defeat
		// the point of the guard — fail closed.
		return errAssignBlocked("authz engine unavailable")
	}
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(int64)
	uid, _ := c.Get("user_id")
	callerID, _ := uid.(int64)
	if callerID == 0 {
		return errAssignBlocked("caller not authenticated")
	}

	// 1. Compute caller's full permission set.
	callerPerms, err := svc.PermissionsForUser(c.Request.Context(), tenantID, callerID)
	if err != nil {
		return errAssignBlocked("caller permission lookup failed")
	}
	// Wildcard caller (super_admin) can assign anything.
	if _, ok := callerPerms["*"]; ok {
		return nil
	}

	// 2. Resolve the role's permission codes.
	rolePerms, err := h.svc.GetRolePermissions(c.Request.Context(), roleID)
	if err != nil {
		return errAssignBlocked("role permission lookup failed")
	}

	// 3. Subset check: every permission the role grants must already be
	// held by the caller.
	for _, p := range rolePerms {
		if _, ok := callerPerms[p.Code]; !ok {
			return errAssignBlocked("cannot grant permission you do not hold: " + p.Code)
		}
	}

	// 4. If the binding is scoped, verify the caller's binding for each
	// granted perm actually covers the target scope. Implemented by
	// running an authz.Check per perm against the requested scope target.
	if req.ScopeType != nil && req.ScopeID != nil {
		target := scopeToTarget(*req.ScopeType, *req.ScopeID)
		for _, p := range rolePerms {
			ok, err := svc.Check(c.Request.Context(), tenantID, callerID, p.Code, target)
			if err != nil || !ok {
				return errAssignBlocked("scope of grant exceeds your own: " + p.Code)
			}
		}
	}
	return nil
}

// scopeToTarget maps a binding scope (org / group) into an authz target so
// privilege-escalation checks can reuse the same engine path as runtime
// permission checks.
func scopeToTarget(scopeType string, scopeID int64) *authz.ScopeTarget {
	switch scopeType {
	case "org":
		return authz.TargetOrg(scopeID)
	case "group":
		return authz.TargetGroup(scopeID)
	}
	return nil
}

// errAssignBlocked is a small wrapper so call sites can return early with
// a uniform 403 reason.
func errAssignBlocked(msg string) error {
	return fmt.Errorf("privilege escalation blocked: %s", msg)
}

// ListRoles handles GET /roles.
func (h *Handler) ListRoles(c *gin.Context) {
	p := pagination.Parse(c)

	params := RoleListParams{
		Page:     p.Page,
		PageSize: p.PageSize,
	}

	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(int64)
	roles, total, err := h.svc.ListRoles(c.Request.Context(), tenantID, params)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]*RoleResponse, len(roles))
	for i, r := range roles {
		count, _ := h.svc.CountMembers(c.Request.Context(), r.ID)
		items[i] = ToRoleResponse(r, nil, count)
	}

	response.Paginated(c, items, total, p.Page, p.PageSize)
}

// CreateRole handles POST /roles.
func (h *Handler) CreateRole(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(int64)
	role, err := h.svc.CreateRole(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.Created(c, ToRoleResponse(role, nil, 0))
}

// GetRole handles GET /roles/:id.
func (h *Handler) GetRole(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	role, err := h.svc.GetRole(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	// Include permissions
	perms, _ := h.svc.GetRolePermissions(c.Request.Context(), id)
	permResps := make([]PermissionResponse, len(perms))
	for i, p := range perms {
		permResps[i] = ToPermissionResponse(p)
	}

	// Include member count
	count, _ := h.svc.CountMembers(c.Request.Context(), id)

	response.OK(c, ToRoleResponse(role, permResps, count))
}

// UpdateRole handles PUT /roles/:id.
func (h *Handler) UpdateRole(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	role, err := h.svc.UpdateRole(c.Request.Context(), id, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, ToRoleResponse(role, nil, 0))
}

// DeleteRole handles DELETE /roles/:id.
func (h *Handler) DeleteRole(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	if err := h.svc.DeleteRole(c.Request.Context(), id); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// GetPermissions handles GET /roles/:id/permissions.
func (h *Handler) GetPermissions(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	perms, err := h.svc.GetRolePermissions(c.Request.Context(), id)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]PermissionResponse, len(perms))
	for i, p := range perms {
		items[i] = ToPermissionResponse(p)
	}

	response.OK(c, items)
}

// SetPermissions handles PUT /roles/:id/permissions.
func (h *Handler) SetPermissions(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	var req UpdatePermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	permIDs, err := idstr.ParseList(req.PermissionIDs)
	if err != nil {
		response.BadRequest(c, 40002, err.Error())
		return
	}

	if err := h.svc.SetRolePermissions(c.Request.Context(), id, permIDs); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// ListMembers handles GET /roles/:id/members.
func (h *Handler) ListMembers(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	p := pagination.Parse(c)
	params := MemberListParams{
		Page:     p.Page,
		PageSize: p.PageSize,
	}

	members, total, err := h.svc.ListMembers(c.Request.Context(), id, params)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.Paginated(c, members, total, p.Page, p.PageSize)
}

// AddMember handles POST /roles/:id/members.
//
// Privilege-escalation guard: the caller cannot grant a role whose permission
// set is broader than their own (you can't make someone an admin if you
// aren't one). If the binding carries a scope, the caller must also already
// have the role's permissions covering that scope.
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

	// Privilege-escalation check.
	if err := h.checkAssignAllowed(c, id, &req); err != nil {
		response.Error(c, http.StatusForbidden, 40300, err.Error(), "")
		return
	}

	binding, err := h.svc.AddMember(c.Request.Context(), id, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.Created(c, binding)
}

// RemoveMember handles DELETE /roles/:id/members/:mid.
func (h *Handler) RemoveMember(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	mid, ok := ginutil.ParseInt64Param(c, "mid")
	if !ok {
		return
	}

	if err := h.svc.RemoveMember(c.Request.Context(), id, mid); err != nil {
		h.handleServiceError(c, err)
		return
	}

	response.OK(c, nil)
}

// ListAllPermissions handles GET /permissions.
func (h *Handler) ListAllPermissions(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(int64)
	perms, err := h.svc.ListAllPermissions(c.Request.Context(), tenantID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	items := make([]PermissionResponse, len(perms))
	for i, p := range perms {
		items[i] = ToPermissionResponse(p)
	}

	response.OK(c, items)
}

// handleServiceError maps service errors to HTTP responses.
// handleServiceError maps a domain error to its response via the errcode
// registry (see errcodes.go for the permission-domain bindings).
func (h *Handler) handleServiceError(c *gin.Context, err error) {
	response.MapError(c, err)
}
