package authn

import (
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/session"
)

// Module holds the wired authn components for use by other modules.
type Module struct {
	Engine     *Engine
	Handler    *Handler
	SessionMgr *session.Manager
	// AdminSession is mounted by the caller AFTER the console auth/authz/tenant
	// middleware chain is installed — see run.go. It must NOT be registered from
	// within Register (which runs before that chain is `.Use`d), or its routes
	// escape authentication entirely.
	AdminSession *AdminSessionHandler
}

// Register wires up the authentication module and registers routes.
// It accepts adapter interfaces that bridge the user repository without
// importing the user package, thereby avoiding circular imports.
//
// mfaVerifier may be nil; the MFA gate is then skipped (used in tests).
// Production wiring in cmd/server must pass a non-nil verifier — otherwise
// users with verified TOTP factors silently bypass second-factor checks.
func Register(
	app *bootstrap.App,
	sessionMgr *session.Manager,
	authQuerier UserAuthQuerier,
	userQuerier UserQuerier,
	mfaVerifier MFAVerifier,
) *Module {
	// Create local provider
	localProvider := NewLocalProvider(authQuerier, app.Config.Security.Password.ExpireDays)

	// Create engine
	engine := NewEngine(
		sessionMgr,
		app.EventBus,
		app.IDGen,
		&app.Config.Security.Login,
		userQuerier,
		app.Redis,
	)
	engine.RegisterProvider(localProvider)
	engine.SetMFAVerifier(mfaVerifier)

	// Create captcha service
	captchaSvc := NewCaptchaService(app.Redis)

	// Create handler
	handler := NewHandler(
		engine,
		captchaSvc,
		app.Config.Tenant.DefaultID,
		app.Config.Session.CookieSecure,
		app.Config.Session.CookieDomain,
		app.Config.Session.CrossSiteCookies,
	)

	// Register routes
	handler.RegisterConsoleRoutes(app.ConsoleGroup)
	handler.RegisterPortalRoutes(app.PortalGroup)

	// Admin-side per-user session ops live in authn (the only module holding
	// the session manager) but are mounted by run.go under the /users path
	// AFTER the console auth/authz/tenant middleware chain — NOT here, which
	// runs before that chain is installed.
	return &Module{
		Engine:       engine,
		Handler:      handler,
		SessionMgr:   sessionMgr,
		AdminSession: NewAdminSessionHandler(sessionMgr),
	}
}
