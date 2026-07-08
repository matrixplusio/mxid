package org

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/authz"
)

// Module exposes the org components so cross-domain wiring (e.g. effective
// roles needing an org ancestor lookup) can call into the service after
// Register returns.
type Module struct {
	Repo    Repository
	Service *Service
	Handler *Handler
}

// Register wires the organization module into the application.
//
// Every write route is gated by authz.Require with an org-scoped target so
// org-scoped admin roles (e.g. dept_admin@org=X) only authorise operations
// inside their subtree. Read routes use the global perm; per-org read
// filtering is delegated to the handler/service (defence in depth).
func Register(app *bootstrap.App) *Module {
	repo := NewRepository(app.DB)
	svc := NewService(repo, app.IDGen, app.EventBus)
	handler := NewHandler(svc, app.Config.Tenant.DefaultID)

	orgs := app.ConsoleGroup.Group("/orgs")
	{
		orgs.GET("", authz.Require("org.read", nil), handler.GetTree)
		orgs.POST("", authz.Require("org.create", nil), handler.Create)
		orgs.GET("/:id", authz.Require("org.read", scopeOrgID), handler.Get)
		orgs.PUT("/:id", authz.Require("org.update", scopeOrgID), handler.Update)
		orgs.DELETE("/:id", authz.Require("org.delete", scopeOrgID), handler.Delete)
		orgs.PUT("/:id/move", authz.Require("org.update", scopeOrgID), handler.Move)
		orgs.GET("/:id/members", authz.Require("org.read", scopeOrgID), handler.GetMembers)
		orgs.POST("/:id/members", authz.Require("org.member.add", scopeOrgID), handler.AddMember)
		orgs.DELETE("/:id/members/:uid", authz.Require("org.member.remove", scopeOrgID), handler.RemoveMember)
	}

	// Cross-domain: list orgs a user belongs to. Gated by user.read because it
	// lives on the /users path and feeds the user-detail page's Org tab.
	app.ConsoleGroup.GET("/users/:id/orgs", authz.Require("user.read", nil), handler.ListUserOrgs)

	return &Module{Repo: repo, Service: svc, Handler: handler}
}

// scopeOrgID parses :id and returns an org-scoped target. Used as the
// scopeFn for org-resource routes — dept_admin@org=X only passes when X is
// an ancestor of the requested org.
func scopeOrgID(c *gin.Context) *authz.ScopeTarget {
	v, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return nil
	}
	return authz.TargetOrg(v)
}
