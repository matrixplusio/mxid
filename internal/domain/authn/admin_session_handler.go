package authn

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
)

// AdminSessionHandler exposes per-user session listing and force-revoke for
// admin operators. Mounted under /users/:id/sessions in the console API so
// the user detail page can pull and revoke active sessions in one place.
//
// All three namespaces (console / portal / protocol) are aggregated — the
// admin's intent is "log this user out everywhere", not "clean a specific
// SPA cookie". The returned items carry their namespace so the UI can show
// where each session lives.
type AdminSessionHandler struct {
	sessionMgr *session.Manager
}

// NewAdminSessionHandler wires a new handler.
func NewAdminSessionHandler(sm *session.Manager) *AdminSessionHandler {
	return &AdminSessionHandler{sessionMgr: sm}
}

// AdminSessionResponse is the per-session payload returned to the console.
// Mirrors session.Session minus secrets — currently there are no secrets,
// but keeping the response struct lets us evolve the API independently.
type AdminSessionResponse struct {
	ID           string `json:"id"`
	Namespace    string `json:"namespace"`
	UserID       int64  `json:"user_id,string"`
	IP           string `json:"ip"`
	UserAgent    string `json:"user_agent"`
	AuthType     string `json:"auth_type"`
	MFAVerified  bool   `json:"mfa_verified"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	LastActiveAt string `json:"last_active_at"`
}

// RegisterRoutes mounts the admin session endpoints on the console API.
//
// SECURITY: this MUST be mounted on a group that already carries the console
// AuthMiddleware + authz + TenantContext chain (i.e. after they are `.Use`d).
// It was historically mounted from inside authn.Register, which runs BEFORE
// those middlewares were added to the group, leaving these routes fully
// unauthenticated (gin group middleware only applies to routes registered
// after `.Use`). Each route now also carries an explicit authz.Require so it
// fails closed regardless of the audit-only gateway.
func (h *AdminSessionHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/users/:id/sessions", authz.Require("user.read", nil), h.list)
	rg.DELETE("/users/:id/sessions", authz.Require("user.update", nil), h.revokeAll)
	rg.DELETE("/users/:id/sessions/:sid", authz.Require("user.update", nil), h.revokeOne)
}

func (h *AdminSessionHandler) list(c *gin.Context) {
	uid, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}

	namespaces := []string{session.NamespaceConsole, session.NamespacePortal, session.NamespaceProtocol}
	out := make([]*AdminSessionResponse, 0)
	for _, ns := range namespaces {
		items, err := h.sessionMgr.ListByUser(c.Request.Context(), ns, uid)
		if err != nil {
			// One namespace failing should not poison the whole listing.
			continue
		}
		for _, s := range items {
			out = append(out, &AdminSessionResponse{
				ID:           s.ID,
				Namespace:    s.Namespace,
				UserID:       s.UserID,
				IP:           s.IP,
				UserAgent:    s.UserAgent,
				AuthType:     s.AuthType,
				MFAVerified:  s.MFAVerified,
				CreatedAt:    s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				ExpiresAt:    s.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
				LastActiveAt: s.LastActiveAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		}
	}
	response.OK(c, out)
}

// revokeAll force-logs-out the user from every namespace. Useful after a
// password reset or suspected compromise.
func (h *AdminSessionHandler) revokeAll(c *gin.Context) {
	uid, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	for _, ns := range []string{session.NamespaceConsole, session.NamespacePortal, session.NamespaceProtocol} {
		// Best-effort across namespaces; one failure should not abort.
		_ = h.sessionMgr.DeleteAllByUser(c.Request.Context(), ns, uid)
	}
	c.JSON(http.StatusNoContent, nil)
}

// revokeOne deletes a single session. The namespace must be supplied as a
// query param because the session ID alone is opaque — we don't trial-delete
// against three namespaces to avoid masking errors.
func (h *AdminSessionHandler) revokeOne(c *gin.Context) {
	uid, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	sid := c.Param("sid")
	if sid == "" {
		response.BadRequest(c, 40002, "missing session id")
		return
	}
	ns := c.Query("namespace")
	if ns == "" {
		// 40004 (not 40003): 40003 is the frontend's global totpCodeReused
		// localization; keep this admin-session error off that number.
		response.BadRequest(c, 40004, "missing namespace query")
		return
	}
	switch ns {
	case session.NamespaceConsole, session.NamespacePortal, session.NamespaceProtocol:
		// valid
	default:
		response.BadRequest(c, 40004, "invalid namespace")
		return
	}
	// Ownership guard: the opaque session id must actually belong to :id,
	// otherwise an operator authorized to manage user A could delete an
	// arbitrary session (incl. another user's / a super_admin's) by id.
	sess, err := h.sessionMgr.Get(c.Request.Context(), ns, sid)
	if err != nil || sess == nil || sess.UserID != uid {
		response.NotFound(c, 40401, "session not found")
		return
	}
	if err := h.sessionMgr.Delete(c.Request.Context(), ns, sid); err != nil {
		response.InternalError(c, "delete session failed", err)
		return
	}
	c.JSON(http.StatusNoContent, nil)
}
