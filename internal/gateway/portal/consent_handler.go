package portal

import (
	"context"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/consent"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/response"
)

// ConsentApp carries the public-facing details a portal consent UI needs to
// render the prompt. Backend resolves this from app.Module so the handler
// stays decoupled from the app domain.
type ConsentApp struct {
	ID          int64  `json:"id,string"`
	Name        string `json:"name"`
	Description string `json:"description"`
	LogoURL     string `json:"logo_url"`
	HomeURL     string `json:"home_url"`
}

// ConsentQuerier abstracts the app + scope info lookup the portal consent
// page needs. Implemented by the cmd/server adapter against app.Module.
type ConsentQuerier interface {
	GetApp(ctx context.Context, appID int64) (*ConsentApp, error)
}

type consentHandler struct {
	consentSvc *consent.Service
	queryier   ConsentQuerier
	tenantID   int64
	bus        *event.Bus
}

// scopeDescriptions provides a Chinese-language label per OIDC scope. Tracked
// per scope identifier so the consent UI can render human-friendly prompts
// without leaking scope strings to end users.
//
// Unknown scopes fall through to the raw identifier — that surfaces in QA so
// a follow-up adds a localized label rather than silently hiding scopes.
var scopeDescriptions = map[string]string{
	"openid":         "知晓你的身份编号",
	"profile":        "读取你的姓名、头像、用户名等基本资料",
	"email":          "读取你的邮箱地址",
	"phone":          "读取你的手机号",
	"groups":         "读取你所属的用户组",
	"offline_access": "在你离线时继续访问 (颁发 refresh_token)",
	"address":        "读取你的地址信息",
}

func registerConsentRoutes(rg *gin.RouterGroup, h *consentHandler) {
	c := rg.Group("/consent")
	{
		c.GET("/preview", h.preview)   // app + scope info for the consent prompt
		c.POST("", h.grant)            // user clicks 同意
		c.GET("/granted", h.list)      // 我的授权列表
		c.DELETE("/:app_id", h.revoke) // 撤销授权
	}
}

// preview returns the app + scope info needed to render /consent.
func (h *consentHandler) preview(c *gin.Context) {
	appID, err := parseID(c.Query("app_id"))
	if err != nil {
		response.BadRequest(c, 40001, "invalid app_id")
		return
	}
	scopesQ := c.QueryArray("scope")
	if len(scopesQ) == 0 {
		scopesQ = splitSpaceSep(c.Query("scopes"))
	}

	app, err := h.queryier.GetApp(c.Request.Context(), appID)
	if err != nil || app == nil {
		response.NotFound(c, 40401, "app not found")
		return
	}

	items := make([]gin.H, 0, len(scopesQ))
	for _, s := range scopesQ {
		label := scopeDescriptions[s]
		if label == "" {
			label = s
		}
		items = append(items, gin.H{"scope": s, "label": label})
	}

	response.OK(c, gin.H{
		"app":    app,
		"scopes": items,
	})
}

// grant records the user's affirmative consent and returns 200 so the SPA
// can redirect back to /protocol/oidc/authorize?... to resume the flow.
//
// Path: POST /api/v1/portal/consent { app_id, scopes[] }
func (h *consentHandler) grant(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	var req struct {
		AppID  int64    `json:"app_id,string" binding:"required"`
		Scopes []string `json:"scopes" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	if _, err := h.consentSvc.Grant(c.Request.Context(), h.tenantID, userID, req.AppID, req.Scopes); err != nil {
		response.InternalError(c, "failed to record consent", err)
		return
	}
	if h.bus != nil {
		h.bus.Publish(c.Request.Context(), event.Event{
			Type: event.OIDCConsentGranted,
			Payload: map[string]any{
				"user_id": userID, "tenant_id": h.tenantID,
				"app_id": req.AppID, "scope": req.Scopes,
			},
		})
	}
	response.OK(c, nil)
}

// list returns the user's active consents for "my authorizations" page.
func (h *consentHandler) list(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	rows, err := h.consentSvc.ListByUser(c.Request.Context(), h.tenantID, userID)
	if err != nil {
		response.InternalError(c, "failed to list consents", err)
		return
	}
	out := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		app, _ := h.queryier.GetApp(c.Request.Context(), r.AppID)
		out = append(out, gin.H{
			"app_id":     strconv.FormatInt(r.AppID, 10),
			"app":        app,
			"scopes":     []string(r.Scopes),
			"granted_at": r.GrantedAt,
		})
	}
	response.OK(c, out)
}

// revoke drops the consent for a specific app so the next /authorize will
// re-prompt. Idempotent.
func (h *consentHandler) revoke(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	appID, err := parseID(c.Param("app_id"))
	if err != nil {
		response.BadRequest(c, 40001, "invalid app_id")
		return
	}
	if err := h.consentSvc.Revoke(c.Request.Context(), h.tenantID, userID, appID); err != nil {
		response.InternalError(c, "failed to revoke consent", err)
		return
	}
	if h.bus != nil {
		h.bus.Publish(c.Request.Context(), event.Event{
			Type: event.OIDCConsentRevoked,
			Payload: map[string]any{
				"user_id": userID, "tenant_id": h.tenantID, "app_id": appID,
			},
		})
	}
	response.OK(c, nil)
}

func splitSpaceSep(s string) []string {
	out := []string{}
	cur := []byte{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == ' ' || ch == '+' {
			flush()
			continue
		}
		cur = append(cur, ch)
	}
	flush()
	return out
}
