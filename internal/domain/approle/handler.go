package approle

import (
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

// SubjectResolver — same contract used by appaccess.
type SubjectResolver interface {
	Resolve(ctx *gin.Context, subjectType string, id int64) (name, code string)
}

// AppLabelResolver returns name + code of an app or app-group by id, so
// the user-group reverse view can render which app a binding targets
// without N+1 round trips.
type AppLabelResolver interface {
	App(ctx *gin.Context, id int64) (name, code string)
	AppGroup(ctx *gin.Context, id int64) (name, code string)
}

type Handler struct {
	service    *Service
	resolver   SubjectResolver
	apps       AppLabelResolver
	defaultTID int64
}

func NewHandler(svc *Service, r SubjectResolver, apps AppLabelResolver, defaultTID int64) *Handler {
	return &Handler{service: svc, resolver: r, apps: apps, defaultTID: defaultTID}
}

func (h *Handler) Register(rg *gin.RouterGroup) {
	// Per-app routes
	app := rg.Group("/apps/:id/roles")
	{
		app.GET("", authz.Require("app.read", nil), h.listRolesForApp)
		app.POST("", authz.Require("app.role.manage", nil), h.createRoleForApp)
		app.PUT("/:role_id", authz.Require("app.role.manage", nil), h.updateRole)
		app.DELETE("/:role_id", authz.Require("app.role.manage", nil), h.deleteRole)
	}
	appB := rg.Group("/apps/:id/role-bindings")
	{
		appB.GET("", authz.Require("app.read", nil), h.listBindingsForApp)
		appB.POST("", authz.Require("app.role.manage", nil), h.createBindingForApp)
		appB.DELETE("/:binding_id", authz.Require("app.role.manage", nil), h.deleteBinding)
	}

	// Per-app-group routes
	grp := rg.Group("/app-groups/:id/roles")
	{
		grp.GET("", authz.Require("app.read", nil), h.listRolesForAppGroup)
		grp.POST("", authz.Require("app.role.manage", nil), h.createRoleForAppGroup)
		grp.PUT("/:role_id", authz.Require("app.role.manage", nil), h.updateRole)
		grp.DELETE("/:role_id", authz.Require("app.role.manage", nil), h.deleteRole)
	}
	grpB := rg.Group("/app-groups/:id/role-bindings")
	{
		grpB.GET("", authz.Require("app.read", nil), h.listBindingsForAppGroup)
		grpB.POST("", authz.Require("app.role.manage", nil), h.createBindingForAppGroup)
		grpB.DELETE("/:binding_id", authz.Require("app.role.manage", nil), h.deleteBinding)
	}

	// Reverse view: user-group sees its app role bindings.
	rg.GET("/groups/:id/app-role-bindings", authz.Require("app.read", nil), h.listBindingsForUserGroup)
	rg.GET("/users/:id/app-role-bindings", authz.Require("app.read", nil), h.listBindingsForUser)

	// Aggregation: enumerate the role catalogs + bindings of EVERY member
	// app in an app-group, in a single response. Used by the group's
	// "角色管理" tab to show admins what each member app has configured
	// without making them dive into each app individually.
	rg.GET("/app-groups/:id/member-apps-roles", authz.Require("app.read", nil), h.listMemberAppsRoles)
}

func (h *Handler) tenantID(c *gin.Context) int64 {
	return tenantctx.FromContext(c, h.defaultTID)
}

func (h *Handler) userID(c *gin.Context) *int64 {
	if v, ok := c.Get("user_id"); ok {
		if id, ok := v.(int64); ok {
			return &id
		}
	}
	return nil
}

/* ─── Roles ─── */

func (h *Handler) listRolesForApp(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	rows, err := h.service.ListRoles(c.Request.Context(), OwnerApp, id, h.tenantID(c))
	if err != nil {
		response.InternalError(c, "", err)
		return
	}
	response.OK(c, rows)
}

func (h *Handler) listRolesForAppGroup(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	rows, err := h.service.ListRoles(c.Request.Context(), OwnerAppGroup, id, h.tenantID(c))
	if err != nil {
		response.InternalError(c, "", err)
		return
	}
	response.OK(c, rows)
}

type createRoleBody struct {
	Code        string `json:"code" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	IsDefault   bool   `json:"is_default"`
	SortOrder   int    `json:"sort_order"`
}

func (h *Handler) createRoleForApp(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body createRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	r, err := h.service.CreateRole(c.Request.Context(), CreateRoleRequest{
		AppID:       &id,
		TenantID:    h.tenantID(c),
		Code:        body.Code,
		Name:        body.Name,
		Description: body.Description,
		IsDefault:   body.IsDefault,
		SortOrder:   body.SortOrder,
		CreatedBy:   h.userID(c),
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, r)
}

func (h *Handler) createRoleForAppGroup(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body createRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	r, err := h.service.CreateRole(c.Request.Context(), CreateRoleRequest{
		AppGroupID:  &id,
		TenantID:    h.tenantID(c),
		Code:        body.Code,
		Name:        body.Name,
		Description: body.Description,
		IsDefault:   body.IsDefault,
		SortOrder:   body.SortOrder,
		CreatedBy:   h.userID(c),
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, r)
}

type updateRoleBody struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	IsDefault   *bool   `json:"is_default"`
	SortOrder   *int    `json:"sort_order"`
}

func (h *Handler) updateRole(c *gin.Context) {
	roleID, ok := ginutil.ParseInt64Param(c, "role_id")
	if !ok {
		return
	}
	var body updateRoleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	r, err := h.service.UpdateRole(c.Request.Context(), UpdateRoleRequest{
		ID:          roleID,
		TenantID:    h.tenantID(c),
		Name:        body.Name,
		Description: body.Description,
		IsDefault:   body.IsDefault,
		SortOrder:   body.SortOrder,
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, r)
}

func (h *Handler) deleteRole(c *gin.Context) {
	roleID, ok := ginutil.ParseInt64Param(c, "role_id")
	if !ok {
		return
	}
	if err := h.service.DeleteRole(c.Request.Context(), roleID, h.tenantID(c)); err != nil {
		response.InternalError(c, "", err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

/* ─── Bindings ─── */

func (h *Handler) listBindingsForApp(c *gin.Context) {
	h.listBindings(c, OwnerApp)
}
func (h *Handler) listBindingsForAppGroup(c *gin.Context) {
	h.listBindings(c, OwnerAppGroup)
}

func (h *Handler) listBindings(c *gin.Context, owner Owner) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	bindings, err := h.service.ListBindings(c.Request.Context(), owner, id, h.tenantID(c))
	if err != nil {
		response.InternalError(c, "", err)
		return
	}
	roles, _ := h.service.ListRoles(c.Request.Context(), owner, id, h.tenantID(c))
	roleByID := map[int64]*AppRole{}
	for _, r := range roles {
		roleByID[r.ID] = r
	}
	views := make([]*BindingView, 0, len(bindings))
	for _, b := range bindings {
		v := &BindingView{Binding: b}
		if r := roleByID[b.AppRoleID]; r != nil {
			v.RoleCode = r.Code
			v.RoleName = r.Name
		}
		if h.resolver != nil {
			v.SubjectName, v.SubjectCode = h.resolver.Resolve(c, b.SubjectType, b.SubjectID)
		}
		views = append(views, v)
	}
	response.OK(c, views)
}

type createBindingBody struct {
	AppRoleID   int64  `json:"app_role_id,string" binding:"required"`
	SubjectType string `json:"subject_type" binding:"required"`
	SubjectID   int64  `json:"subject_id,string" binding:"required"`
}

func (h *Handler) createBindingForApp(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body createBindingBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	b, err := h.service.AddBinding(c.Request.Context(), AddBindingRequest{
		AppID:       &id,
		TenantID:    h.tenantID(c),
		AppRoleID:   body.AppRoleID,
		SubjectType: body.SubjectType,
		SubjectID:   body.SubjectID,
		CreatedBy:   h.userID(c),
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, b)
}

func (h *Handler) createBindingForAppGroup(c *gin.Context) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	var body createBindingBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40002, "invalid request body")
		return
	}
	b, err := h.service.AddBinding(c.Request.Context(), AddBindingRequest{
		AppGroupID:  &id,
		TenantID:    h.tenantID(c),
		AppRoleID:   body.AppRoleID,
		SubjectType: body.SubjectType,
		SubjectID:   body.SubjectID,
		CreatedBy:   h.userID(c),
	})
	if err != nil {
		response.MapError(c, err)
		return
	}
	response.OK(c, b)
}

func (h *Handler) deleteBinding(c *gin.Context) {
	bindingID, ok := ginutil.ParseInt64Param(c, "binding_id")
	if !ok {
		return
	}
	if err := h.service.DeleteBinding(c.Request.Context(), bindingID, h.tenantID(c)); err != nil {
		response.InternalError(c, "", err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

/* ─── Reverse: who is bound to what ─── */

// listBindingsForUserGroup — GET /groups/:id/app-role-bindings — returns
// every binding row where subject_type='group' and subject_id=id. Used
// by the user-group detail page so admins can see + manage "this group's
// app role memberships" in one place.
func (h *Handler) listBindingsForUserGroup(c *gin.Context) {
	h.listBindingsForSubject(c, "group")
}

// listBindingsForUser — GET /users/:id/app-role-bindings — direct-bound
// roles for one user. Does NOT include transitive bindings via groups
// (intentional: keeps the view simple; transitive is computed via
// /apps/:id/role-bindings + member queries).
func (h *Handler) listBindingsForUser(c *gin.Context) {
	h.listBindingsForSubject(c, "user")
}

func (h *Handler) listBindingsForSubject(c *gin.Context, subjectType string) {
	id, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	bindings, err := h.service.ListBindingsBySubject(c.Request.Context(), subjectType, id, h.tenantID(c))
	if err != nil {
		response.InternalError(c, "", err)
		return
	}
	views := make([]*ReverseBindingView, 0, len(bindings))
	for _, b := range bindings {
		v := &ReverseBindingView{Binding: b}
		// Resolve role name+code.
		if role, err := h.service.GetRole(c.Request.Context(), b.AppRoleID, b.TenantID); err == nil {
			v.RoleCode = role.Code
			v.RoleName = role.Name
		}
		// Resolve target app or app-group label.
		if h.apps != nil {
			if b.AppID != nil {
				v.TargetType = "app"
				v.TargetID = *b.AppID
				v.TargetName, v.TargetCode = h.apps.App(c, *b.AppID)
			} else if b.AppGroupID != nil {
				v.TargetType = "app-group"
				v.TargetID = *b.AppGroupID
				v.TargetName, v.TargetCode = h.apps.AppGroup(c, *b.AppGroupID)
			}
		}
		views = append(views, v)
	}
	response.OK(c, views)
}

// MemberAppRoles is one app's role catalog + binding list, used by the
// app-group aggregation view to render a per-app summary.
type MemberAppRoles struct {
	AppID    int64          `json:"app_id,string"`
	AppName  string         `json:"app_name"`
	AppCode  string         `json:"app_code"`
	Roles    []*AppRole     `json:"roles"`
	Bindings []*BindingView `json:"bindings"`
}

func (h *Handler) listMemberAppsRoles(c *gin.Context) {
	groupID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	appIDs, err := h.service.MemberAppIDs(c.Request.Context(), groupID)
	if err != nil {
		response.InternalError(c, "", err)
		return
	}
	tid := h.tenantID(c)
	result := make([]*MemberAppRoles, 0, len(appIDs))
	for _, appID := range appIDs {
		entry := &MemberAppRoles{AppID: appID}
		if h.apps != nil {
			entry.AppName, entry.AppCode = h.apps.App(c, appID)
		}
		entry.Roles, _ = h.service.ListRoles(c.Request.Context(), OwnerApp, appID, tid)
		// Bindings enriched with subject + role names — reuse list helper.
		bindings, _ := h.service.ListBindings(c.Request.Context(), OwnerApp, appID, tid)
		roleByID := map[int64]*AppRole{}
		for _, role := range entry.Roles {
			roleByID[role.ID] = role
		}
		views := make([]*BindingView, 0, len(bindings))
		for _, b := range bindings {
			v := &BindingView{Binding: b}
			if role := roleByID[b.AppRoleID]; role != nil {
				v.RoleCode = role.Code
				v.RoleName = role.Name
			}
			if h.resolver != nil {
				v.SubjectName, v.SubjectCode = h.resolver.Resolve(c, b.SubjectType, b.SubjectID)
			}
			views = append(views, v)
		}
		entry.Bindings = views
		result = append(result, entry)
	}
	response.OK(c, result)
}

// ReverseBindingView decorates a binding with the human-readable target
// (which app / app-group it grants role in) so reverse views render with
// one round trip.
type ReverseBindingView struct {
	*Binding
	RoleCode   string `json:"role_code"`
	RoleName   string `json:"role_name"`
	TargetType string `json:"target_type"`
	TargetID   int64  `json:"target_id,string"`
	TargetName string `json:"target_name"`
	TargetCode string `json:"target_code"`
}
