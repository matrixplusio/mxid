package portal

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/urlswap"
)

// appsHandler serves portal app-related endpoints.
//
// Layout: a single AppQuerier interface aggregates app catalogue + favorites
// + recently-launched lookups. Keeping the routes / interface boundaries thin
// here puts persistence concerns in cmd/server/adapters_portal.go where the
// actual gorm models live.
type appsHandler struct {
	appQuerier AppQuerier
	bus        *event.Bus
}

// registerAppsRoutes wires the portal /apps namespace plus /app-groups,
// /favorites, /recent so the frontend has a single contract for "what
// should I render on the dashboard".
func registerAppsRoutes(rg *gin.RouterGroup, h *appsHandler) {
	apps := rg.Group("/apps")
	{
		apps.GET("", h.listApps)
		apps.GET("/favorites", h.listFavorites)
		apps.PATCH("/favorites/order", h.reorderFavorites)
		apps.GET("/recent", h.listRecent)
		apps.GET("/:id/launch", h.launchApp)
		apps.POST("/:id/favorite", h.addFavorite)
		apps.DELETE("/:id/favorite", h.removeFavorite)
	}
	rg.GET("/app-groups", h.listAppGroups)
}

// listApps returns the authenticated user's authorized applications.
// Each AppInfo carries its group memberships so the frontend can render
// sections without a second request.
func (h *appsHandler) listApps(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	tenantID, _ := authn.GetTenantID(c)

	apps, err := h.appQuerier.ListAuthorizedApps(c.Request.Context(), userID, tenantID, c.Query("q"))
	if err != nil {
		response.InternalError(c, "failed to list apps")
		return
	}

	response.OK(c, apps)
}

// listAppGroups returns visible app groups + per-group access-aware counts.
func (h *appsHandler) listAppGroups(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	tenantID, _ := authn.GetTenantID(c)

	groups, err := h.appQuerier.ListAuthorizedAppGroups(c.Request.Context(), userID, tenantID)
	if err != nil {
		response.InternalError(c, "failed to list app groups")
		return
	}
	response.OK(c, groups)
}

// listFavorites returns the user's favorited app IDs (ordered by sort_order).
// The frontend already has the full AppInfo set from /apps, so we return
// IDs only — cheaper and avoids data duplication.
func (h *appsHandler) listFavorites(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	ids, err := h.appQuerier.ListFavoriteAppIDs(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to list favorites")
		return
	}
	response.OK(c, gin.H{"app_ids": idsToStrings(ids)})
}

// listRecent returns the N most-recently launched app IDs for the user.
// `limit` defaults to 4 (sized for one horizontal ribbon row).
func (h *appsHandler) listRecent(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	tenantID, _ := authn.GetTenantID(c)
	limit := 4
	if v := c.Query("limit"); v != "" {
		if n, err := parseLimit(v); err == nil {
			limit = n
		}
	}
	ids, err := h.appQuerier.ListRecentAppIDs(c.Request.Context(), userID, tenantID, limit)
	if err != nil {
		response.InternalError(c, "failed to list recent")
		return
	}
	response.OK(c, gin.H{"app_ids": idsToStrings(ids)})
}

// addFavorite pins an app to the user's favorites. Idempotent — adding the
// same app twice is a 200 (kept simple so the SPA can fire-and-forget).
func (h *appsHandler) addFavorite(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	tenantID, _ := authn.GetTenantID(c)
	appID, err := parseID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, 40001, "invalid app id")
		return
	}
	if err := h.appQuerier.AddFavorite(c.Request.Context(), userID, tenantID, appID); err != nil {
		response.InternalError(c, "failed to add favorite")
		return
	}
	response.OK(c, gin.H{"ok": true})
}

// reorderFavorites accepts {"app_ids": [...]} and persists the new sort_order.
// Frontend sends the COMPLETE list each time — keeps the API stateless and
// makes drag-drop merge conflicts trivial (last writer wins). app_ids that
// aren't currently favorited are ignored server-side; not an error so the
// SPA can fire-and-forget without re-fetching first.
func (h *appsHandler) reorderFavorites(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	var req struct {
		AppIDs []string `json:"app_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	parsedIDs := make([]int64, 0, len(req.AppIDs))
	for _, s := range req.AppIDs {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			response.BadRequest(c, 40001, "invalid app id in app_ids")
			return
		}
		parsedIDs = append(parsedIDs, id)
	}
	if err := h.appQuerier.ReorderFavorites(c.Request.Context(), userID, parsedIDs); err != nil {
		response.InternalError(c, "failed to reorder favorites")
		return
	}
	response.OK(c, gin.H{"ok": true})
}

// removeFavorite unpins an app. Idempotent.
func (h *appsHandler) removeFavorite(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	appID, err := parseID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, 40001, "invalid app id")
		return
	}
	if err := h.appQuerier.RemoveFavorite(c.Request.Context(), userID, appID); err != nil {
		response.InternalError(c, "failed to remove favorite")
		return
	}
	response.OK(c, gin.H{"ok": true})
}

// launchApp returns the launch URL and publishes app.launched so the audit
// log captures it. /apps/recent reads from the audit log — the audit row
// IS the recently-used signal; no separate launch table.
func (h *appsHandler) launchApp(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	tenantID, _ := authn.GetTenantID(c)
	sessionID, _ := authn.GetSessionID(c)

	appID, err := parseID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, 40001, "invalid app id")
		return
	}

	url, err := h.appQuerier.GetAppLaunchURL(c.Request.Context(), appID, userID)
	if err != nil {
		response.InternalError(c, "failed to get launch url")
		return
	}
	// Adapter builds launch_url against the cached issuer config (usually
	// localhost in dev). Swap to the inbound request host so a portal user
	// accessing via LAN IP / canonical domain stays on the same host all
	// the way through the protocol bounce — otherwise the browser ends up
	// on `localhost:3500/...` and gets a connection refused.
	url = urlswap.SwapLocalhostHost(url, c.Request.Host)

	if h.bus != nil {
		// Best-effort name lookup so the audit row reads "launched <name>".
		// A lookup failure must not block the launch — fall back to id-only.
		appName, _ := h.appQuerier.AppName(c.Request.Context(), appID)
		h.bus.Publish(c.Request.Context(), event.Event{
			Type: event.AppLaunched,
			Payload: map[string]any{
				"user_id":    userID,
				"tenant_id":  tenantID,
				"app_id":     appID,
				"name":       appName,
				"session_id": sessionID,
				"ip":         c.ClientIP(),
				"user_agent": c.Request.UserAgent(),
			},
		})
	}

	response.OK(c, gin.H{"launch_url": url})
}

func parseLimit(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 1 {
		n = 1
	}
	if n > 20 {
		n = 20
	}
	return n, nil
}

// idsToStrings converts []int64 → []string for JSON output. Always returns
// a non-nil slice so the frontend can rely on `app_ids: string[]` and skip
// null guards.
func idsToStrings(ids []int64) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.FormatInt(id, 10)
	}
	return out
}
