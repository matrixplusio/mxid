package permission

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
)

// Module exposes the permission components so cross-domain wiring (e.g.
// effective roles needing a group lookup) can call into the service after
// Register returns.
type Module struct {
	Repo    Repository
	Service *Service
	Handler *Handler
}

// Register wires up the permission domain module and registers routes.
func Register(app *bootstrap.App) *Module {
	repo := NewGormRepository(app.DB)
	svc := NewService(repo, app.IDGen, app.EventBus, app.Config.Tenant.DefaultID)
	h := NewHandler(svc)
	h.RegisterRoutes(app.ConsoleGroup)

	return &Module{Repo: repo, Service: svc, Handler: h}
}

// RegisterEffectiveRolesRoute mounts GET /users/:id/roles. Called by main
// after the group and org modules are available so we can inject the lookups
// without creating an import cycle. orgs may be nil if org-inherited
// permissions are intentionally disabled in a deployment.
func RegisterEffectiveRolesRoute(app *bootstrap.App, svc *Service, groups GroupLookup, orgs OrgLookup, tenantID int64) {
	// Gated with user.read: this reads another user's effective roles, so it
	// requires the same permission as any other user-detail read (previously it
	// carried no authz.Require at all — an open admin endpoint).
	app.ConsoleGroup.GET("/users/:id/roles", authz.Require("user.read", nil), func(c *gin.Context) {
		uid, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			response.BadRequest(c, 40001, "invalid user id")
			return
		}
		items, err := svc.EffectiveRolesForUser(c.Request.Context(), tenantID, uid, groups, orgs)
		if err != nil {
			response.InternalError(c, "list effective roles", err)
			return
		}
		response.OK(c, items)
	})
}
