package authz

import (
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// DENY-BY-DEFAULT GATEWAY
//
// Problem this solves: a console route that simply forgets to declare an
// authz.Require ships as an OPEN admin endpoint (the root cause of the
// app/idp/audit modules being silently unprotected). We cannot rely on every
// future route author remembering to gate their handler, so the gateway makes
// "no permission declared" mean "denied" rather than "open".
//
// Registry model (keys are "METHOD FULLPATH", e.g. "POST /api/v1/console/apps"):
//
//   - Protect(method, fullPath, perm)  — the STABLE, deterministic registration
//     API. Modules call it at mount time (right where they mount the route) so
//     the registry is complete BEFORE the first request. This is what hard
//     deny-by-default relies on. Pair it with authz.Require on the same route:
//     Protect tells the gateway "this route IS gated"; Require does the actual
//     permission/scope enforcement.
//
//   - authz.Require / RequireAny ALSO self-register the route the first time the
//     handler runs (request-time). gin group middleware (the gateway) runs
//     BEFORE a route's own Require, so under HARD mode this self-registration is
//     too late to save the first request — it exists only to keep the AuditOnly
//     log accurate without forcing every legacy call site to add a Protect().
//
//   - AllowPublic / AllowPublicPrefix — the documented escape hatch for console-
//     mounted routes that intentionally need no admin permission (health, the
//     SSE event stream, the portal-on-console self-service surfaces that carry
//     their own session auth).
//
// Gateway() consults the registry post-routing (c.FullPath() is already set by
// gin before any group middleware runs). A matched console route that is NEITHER
// protected NOR allow-listed is flagged: logged-and-allowed in AuditOnly mode,
// or DENIED 403 in hard mode.

// declaredKey marks (within a single request) that a Require/RequireAny actually
// executed on this route, i.e. the route DID declare a permission. Exposed for
// potential post-hoc auditing; the gateway decision itself uses the registry.
const declaredKey = "mxid:authz:declared"

// routeRegistry is the process-global set of protected console routes plus the
// intentionally-public allow-list. Keys are "METHOD FULLPATH".
type routeRegistry struct {
	mu        sync.RWMutex
	protected map[string]string // route key -> permission code ("" for RequireAny / explicit)
	allow     map[string]bool   // route key -> intentionally public (no perm)
	allowPfx  []string          // path prefixes that are intentionally public
}

var registry = &routeRegistry{
	protected: make(map[string]string),
	allow:     make(map[string]bool),
}

func routeKey(method, fullPath string) string {
	return method + " " + fullPath
}

// Protect registers (method, fullPath) as requiring a permission. This is the
// stable, deterministic registration API — call it at mount time alongside the
// route so the gateway recognises the route as gated from boot. `perm` is
// recorded for diagnostics; the actual enforcement still comes from the
// authz.Require on the route (or any equivalent gate). Pass "" if the route is
// gated by RequireAny or a custom middleware.
//
//	rg.POST("/apps", authz.Require("app.create", nil), h.Create)
//	authz.Protect(http.MethodPost, "/api/v1/console/apps", "app.create")
func Protect(method, fullPath, perm string) {
	registry.mu.Lock()
	registry.protected[routeKey(method, fullPath)] = perm
	registry.mu.Unlock()
}

// AllowPublic marks an exact (method, fullPath) console route as intentionally
// needing no permission. Use sparingly — the documented escape hatch from
// deny-by-default.
func AllowPublic(method, fullPath string) {
	registry.mu.Lock()
	registry.allow[routeKey(method, fullPath)] = true
	registry.mu.Unlock()
}

// AllowPublicPrefix marks every console route whose FULLPATH starts with prefix
// as intentionally public — for whole sub-surfaces that ride on the console
// group but carry their own auth (portal-on-console self-service, the SSE event
// stream, uploads).
func AllowPublicPrefix(prefix string) {
	registry.mu.Lock()
	registry.allowPfx = append(registry.allowPfx, prefix)
	registry.mu.Unlock()
}

// requestRegister is called by Require/RequireAny at request time so any gated
// route self-registers (keeps AuditOnly logs accurate). perm "" is used by
// RequireAny.
func requestRegister(method, fullPath, perm string) {
	if fullPath == "" {
		return
	}
	key := routeKey(method, fullPath)
	registry.mu.RLock()
	_, known := registry.protected[key]
	registry.mu.RUnlock()
	if known {
		return
	}
	registry.mu.Lock()
	if _, ok := registry.protected[key]; !ok {
		registry.protected[key] = perm
	}
	registry.mu.Unlock()
}

func (r *routeRegistry) isAllowed(method, fullPath string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.allow[routeKey(method, fullPath)] {
		return true
	}
	for _, p := range r.allowPfx {
		if strings.HasPrefix(fullPath, p) {
			return true
		}
	}
	return false
}

func (r *routeRegistry) isProtected(method, fullPath string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.protected[routeKey(method, fullPath)]
	return ok
}

// IsRegistered reports whether (method, fullPath) is known to the gateway —
// either allow-listed or registered as protected. A boot-time coverage audit
// uses it to flag any governed console route that would 403 under hard mode
// because nobody declared it (Protect / AllowPublic). Exported for that audit;
// the gateway's own decision path uses isAllowed/isProtected directly.
func IsRegistered(method, fullPath string) bool {
	return registry.isAllowed(method, fullPath) || registry.isProtected(method, fullPath)
}

// GatewayConfig configures the deny-by-default gateway.
type GatewayConfig struct {
	// Logger receives the loud "unprotected route" warnings. nil drops them
	// (tolerated for tests).
	Logger *zap.Logger

	// AuditOnly, when true, makes the gateway LOG an unprotected route loudly
	// but still let the request through (it does NOT 403). Safe rollout posture:
	// enable the gateway, watch logs for any console-mounted surface that
	// legitimately carries its own (non-admin) auth, AllowPublic/Protect those,
	// then flip AuditOnly=false to turn on hard deny-by-default.
	AuditOnly bool
}

// Gateway returns the deny-by-default middleware. Mount on the console group
// AFTER AuthMiddleware + authz.Install, BEFORE the module routes:
//
//	a.ConsoleGroup.Use(authz.Gateway(authz.GatewayConfig{Logger: logger, AuditOnly: true}))
//
// c.FullPath() is already the matched route pattern when this runs (gin sets it
// before any group middleware). Decision:
//   - FullPath == "" (NoRoute): pass — gin's NoRoute returns 404.
//   - allow-listed: pass.
//   - protected (registered): pass — the route's own Require enforces the perm.
//   - otherwise: unprotected. Log loudly; allow in AuditOnly, else 403.
func Gateway(cfg GatewayConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		fp := c.FullPath()
		method := c.Request.Method

		if fp == "" {
			c.Next()
			return
		}
		if registry.isAllowed(method, fp) {
			c.Next()
			return
		}
		if registry.isProtected(method, fp) {
			c.Next()
			return
		}

		// Unprotected console route — nobody declared a permission for it.
		if cfg.AuditOnly {
			if cfg.Logger != nil {
				cfg.Logger.Warn("authz gateway [audit-only]: UNPROTECTED console route allowed through — "+
					"declare authz.Require + Protect, or AllowPublic it, before enabling hard deny",
					zap.String("method", method),
					zap.String("route", fp),
				)
			}
			c.Next()
			return
		}
		if cfg.Logger != nil {
			cfg.Logger.Error("authz gateway: BLOCKED unprotected console route — "+
				"no permission declared; add authz.Require + Protect or AllowPublic it",
				zap.String("method", method),
				zap.String("route", fp),
			)
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"code":    40301,
			"message": "route is not authorized (deny-by-default): no permission declared for " + method + " " + fp,
		})
	}
}
