package offboarding

import (
	"context"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/imkerbos/mxid/pkg/session"
)

// Module holds the wired offboarding components.
type Module struct {
	Service *Service
	Handler *Handler
}

// LogoutNotifierFunc adapts a plain function to the LogoutNotifier interface,
// so callers can pass e.g. the OIDC handler's LogoutUserBackchannel method
// directly. A nil func is a no-op.
type LogoutNotifierFunc func(ctx context.Context, userID int64)

// NotifyLogout implements LogoutNotifier.
func (f LogoutNotifierFunc) NotifyLogout(ctx context.Context, userID int64) {
	if f != nil {
		f(ctx, userID)
	}
}

// Register builds the offboarding orchestrator from the already-constructed
// user service and session manager, plus the shared event bus / logger, an
// optional back-channel logout notifier and an optional app-footprint source
// (pass nil to skip either). Route registration is deferred (see
// RegisterRoutes) until the console group's middleware chain (auth + step-up +
// authz) is in place.
func Register(app *bootstrap.App, userSvc *user.Service, sessionMgr *session.Manager, logout LogoutNotifier, footprint AppFootprint) *Module {
	svc := NewService(
		&userDisabler{svc: userSvc},
		&sessionKiller{mgr: sessionMgr},
		&userLookup{svc: userSvc},
		logout,
		footprint,
		NewRepository(app.DB),
		app.IDGen,
		app.EventBus,
		app.Logger,
	)
	return &Module{Service: svc, Handler: NewHandler(svc, app.Config.Tenant.DefaultID)}
}

// RegisterRoutes mounts the offboarding routes on the console group. Must be
// called after the console middleware chain is finalised so the per-route
// authz.Require closure and the step-up middleware both apply.
func (m *Module) RegisterRoutes(app *bootstrap.App) {
	m.Handler.RegisterRoutes(app.ConsoleGroup)
}

// --- adapters: bridge the domain interfaces onto the concrete user/session
// services without the offboarding domain importing them directly. ---

type userDisabler struct{ svc *user.Service }

func (a *userDisabler) Disable(ctx context.Context, userID int64) error {
	return a.svc.UpdateStatus(ctx, userID, user.StatusDisabled)
}

type sessionKiller struct{ mgr *session.Manager }

// KillAllByUser drops every active session for the user across all three
// session namespaces, returning the total removed. A failure in one namespace
// is recorded but does not stop the others — partial cleanup beats none.
func (a *sessionKiller) KillAllByUser(ctx context.Context, userID int64) (int, error) {
	namespaces := []string{session.NamespaceConsole, session.NamespacePortal, session.NamespaceProtocol}
	total := 0
	var firstErr error
	for _, ns := range namespaces {
		sessions, err := a.mgr.ListByUser(ctx, ns, userID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		total += len(sessions)
		if err := a.mgr.DeleteAllByUser(ctx, ns, userID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return total, firstErr
}

type userLookup struct{ svc *user.Service }

func (a *userLookup) Lookup(ctx context.Context, userID int64) (username, email string, tenantID int64, err error) {
	u, err := a.svc.GetByID(ctx, userID)
	if err != nil {
		return "", "", 0, err
	}
	if u.Email != nil {
		email = *u.Email
	}
	return u.Username, email, u.TenantID, nil
}
