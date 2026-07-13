package authn

import (
	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// actorTypeForNamespace maps a session namespace to the audit actor type:
// console sessions are admin operators, portal sessions are end users.
func actorTypeForNamespace(namespace string) string {
	if namespace == session.NamespaceConsole {
		return auditctx.TypeAdmin
	}
	return auditctx.TypeUser
}

// cookieForNamespace returns the cookie name for a given session namespace.
func cookieForNamespace(namespace string) string {
	switch namespace {
	case session.NamespaceConsole:
		return CookieConsole
	case session.NamespacePortal:
		return CookiePortal
	default:
		return ""
	}
}

// AuthMiddleware validates the session cookie and injects user_id, tenant_id,
// and session_id into the gin.Context. Requests without a valid session receive
// a 401 response.
func AuthMiddleware(sessionMgr *session.Manager, namespace string) gin.HandlerFunc {
	cookieName := cookieForNamespace(namespace)

	return func(c *gin.Context) {
		if cookieName == "" {
			response.Unauthorized(c, 40101, "unsupported namespace")
			c.Abort()
			return
		}

		sessionID, err := c.Cookie(cookieName)
		if err != nil || sessionID == "" {
			response.Unauthorized(c, 40101, "authentication required")
			c.Abort()
			return
		}

		sess, err := sessionMgr.Get(c.Request.Context(), namespace, sessionID)
		if err != nil || sess == nil {
			response.Unauthorized(c, 40101, "invalid or expired session")
			c.Abort()
			return
		}

		// Real user request — extend idle window. Touch must live ONLY here,
		// not inside Get(), otherwise listing endpoints would keep idle
		// sessions alive forever (see pkg/session/manager.go).
		_ = sessionMgr.Touch(c.Request.Context(), namespace, sessionID)

		// Keep the shared SSO (proto) session warm while the user is active in
		// any first-party SPA. Otherwise it idle-expires on its own (nothing
		// else touches it), and third-party OIDC SSO would demand a fresh login
		// under an otherwise-active session. Best-effort: a missing/expired
		// proto cookie is a no-op. The SPA session was just validated above, so
		// an inactive user 401s here before reaching this revival.
		if pid, err := c.Cookie(CookieProto); err == nil && pid != "" {
			_ = sessionMgr.Touch(c.Request.Context(), session.NamespaceProtocol, pid)
		}

		// Inject into context
		c.Set(CtxUserID, sess.UserID)
		c.Set(CtxTenantID, sess.TenantID)
		c.Set(CtxSessionID, sess.ID)
		c.Set(CtxNamespace, namespace)
		c.Set(CtxMFAEnrollPending, sess.MFAEnrollPending)

		// Stamp the actor onto the *request* context so domain services that
		// publish audit events (via c.Request.Context()) attribute them to this
		// caller automatically — who, IP, session — without each publisher
		// reassembling the fields. IP / UA are the live request values.
		ctx := auditctx.With(c.Request.Context(), auditctx.Actor{
			ActorID:   sess.UserID,
			ActorType: actorTypeForNamespace(namespace),
			TenantID:  sess.TenantID,
			SessionID: sess.ID,
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		// Stamp the session tenant onto the std context so the gorm
		// tenant-isolation plugin pins every tenant-scoped query to this
		// tenant by default. A super_admin X-Tenant-ID switch (console only)
		// overrides this downstream in middleware.TenantContext.
		ctx = tenantscope.WithTenant(ctx, sess.TenantID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
