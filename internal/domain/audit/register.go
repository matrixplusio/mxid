package audit

import "github.com/imkerbos/mxid/internal/bootstrap"

// Module exposes the audit service so cross-domain adapters (e.g. the
// portal login-history querier) can query the same log the console admin
// sees, without reaching into the gorm repo directly.
type Module struct {
	Service *Service
	Repo    Repository
}

// Register wires up the audit domain module and registers routes.
func Register(app *bootstrap.App) *Module {
	repo := NewGormRepository(app.DB)
	svc := NewService(repo, app.IDGen, app.EventBus, app.Logger, app.Config.Tenant.DefaultID)

	svc.SetChainBridge(app.DB, NewCapturer(app.IDGen))

	svc.SubscribeEvents()

	h := NewHandler(svc, app.Config.Tenant.DefaultID)
	h.RegisterRoutes(app.ConsoleGroup)

	return &Module{Service: svc, Repo: repo}
}
