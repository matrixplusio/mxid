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

// Register builds the offboarding orchestrator from the already-constructed
// user service and session manager, plus the shared event bus / logger. Route
// registration is deferred (see RegisterRoutes) until the console group's
// middleware chain (auth + step-up + authz) is in place.
func Register(app *bootstrap.App, userSvc *user.Service, sessionMgr *session.Manager) *Module {
	svc := NewService(
		&userDisabler{svc: userSvc},
		&sessionKiller{mgr: sessionMgr},
		&userLookup{svc: userSvc},
		app.EventBus,
		app.Logger,
	)
	return &Module{Service: svc, Handler: NewHandler(svc)}
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

func (a *userLookup) Lookup(ctx context.Context, userID int64) (string, int64, error) {
	u, err := a.svc.GetByID(ctx, userID)
	if err != nil {
		return "", 0, err
	}
	return u.Username, u.TenantID, nil
}
