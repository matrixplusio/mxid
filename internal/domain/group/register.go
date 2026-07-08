package group

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/authz"
)

// Module exposes the group components so cross-domain wiring (e.g.
// effective roles needing a group lookup) can call into the service after
// Register returns.
type Module struct {
	Repo    Repository
	Service *Service
	Handler *Handler
}

// Register wires the user group module into the application.
//
// Authz: write routes are gated against group-scoped permissions so admins
// bound to scope=group(X) can only mutate that specific group. Read routes
// are global-scoped for simplicity; the handler filters list output by the
// caller's bindings.
func Register(app *bootstrap.App) *Module {
	repo := NewRepository(app.DB)
	svc := NewService(repo, app.IDGen, app.EventBus, app.Logger)
	// React to org membership changes: recompute dynamic groups whose rule keys
	// on org membership so the roster stays live without a manual re-sync.
	svc.SubscribeEvents()
	handler := NewHandler(svc, app.Config.Tenant.DefaultID)

	groups := app.ConsoleGroup.Group("/groups")
	{
		groups.GET("", authz.Require("group.read", nil), handler.List)
		groups.POST("", authz.Require("group.create", nil), handler.Create)
		// /groups/rule-fields stays before /:id so the static segment wins.
		groups.GET("/rule-fields", authz.Require("group.read", nil), handler.RuleFields)
		groups.GET("/:id", authz.Require("group.read", scopeGroupID), handler.Get)
		groups.PUT("/:id", authz.Require("group.update", scopeGroupID), handler.Update)
		groups.DELETE("/:id", authz.Require("group.delete", scopeGroupID), handler.Delete)
		groups.GET("/:id/members", authz.Require("group.read", scopeGroupID), handler.GetMembers)
		groups.POST("/:id/members", authz.Require("group.member.manage", scopeGroupID), handler.AddMember)
		groups.POST("/:id/members/batch", authz.Require("group.member.manage", scopeGroupID), handler.BatchAddMembers)
		groups.DELETE("/:id/members/batch", authz.Require("group.member.manage", scopeGroupID), handler.BatchRemoveMembers)
		groups.DELETE("/:id/members/:uid", authz.Require("group.member.manage", scopeGroupID), handler.RemoveMember)

		groups.GET("/:id/rule", authz.Require("group.read", scopeGroupID), handler.GetRule)
		groups.PUT("/:id/rule", authz.Require("group.rule.manage", scopeGroupID), handler.UpsertRule)
		groups.DELETE("/:id/rule", authz.Require("group.rule.manage", scopeGroupID), handler.DeleteRule)
		groups.POST("/:id/sync", authz.Require("group.rule.manage", scopeGroupID), handler.SyncRule)
	}

	// Cross-domain: list groups a user belongs to. Gated by user.read because
	// it lives on the /users path and is consumed by the user-detail page.
	app.ConsoleGroup.GET("/users/:id/groups", authz.Require("user.read", nil), handler.ListByUser)

	return &Module{
		Repo:    repo,
		Service: svc,
		Handler: handler,
	}
}

// scopeGroupID parses :id and returns a group-scoped target.
func scopeGroupID(c *gin.Context) *authz.ScopeTarget {
	v, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return nil
	}
	return authz.TargetGroup(v)
}
