// Package settings provides console admin endpoints for the runtime
// settings store (mxid_setting). Each category has a typed GET/PUT pair;
// the underlying setting.Service handles AES encryption + caching.
//
// Tenant scoping: super_admin can pass `?global=true` to read/write the
// tenant_id=0 row (system-wide defaults). Otherwise reads/writes go
// against the caller's session tenant.
package settings

import (
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/platformconfig"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/middleware"
	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/mailer"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
)

type Handler struct {
	service    *setting.Service
	platform   *platformconfig.Service
	mailer     *mailer.Mailer
	defaultTID int64
}

func NewHandler(svc *setting.Service, platform *platformconfig.Service, mailer *mailer.Mailer, defaultTID int64) *Handler {
	return &Handler{service: svc, platform: platform, mailer: mailer, defaultTID: defaultTID}
}

func (h *Handler) Register(rg *gin.RouterGroup) {
	g := rg.Group("/settings")
	{
		// One endpoint per setting category. Plain category name in the URL
		// instead of generic /settings?key=... because each category has a
		// different shape — typed body validation only works if the path
		// dispatches to the right handler.
		g.GET("/mail/smtp", h.getMailSMTP)
		g.PUT("/mail/smtp", h.putMailSMTP)
		g.POST("/mail/smtp/test", h.testMailSMTP)

		g.GET("/mail/templates", h.getMailTemplates)
		g.PUT("/mail/templates", h.putMailTemplates)

		g.GET("/security", h.getSecurity)
		g.PUT("/security", h.putSecurity)

		g.GET("/branding", h.getBranding)
		// Branding write is an EE feature; CE reads defaults but can't change them.
		g.PUT("/branding", middleware.RequireFeature(license.FeatureBranding), h.putBranding)

		g.GET("/login-methods", h.getLoginMethods)
		g.PUT("/login-methods", h.putLoginMethods)

		g.GET("/protocol-defaults", h.getProtocolDefaults)
		g.PUT("/protocol-defaults", h.putProtocolDefaults)

		g.GET("/sms", h.getSMS)
		g.PUT("/sms", h.putSMS)

		g.GET("/audit-policy", h.getAuditPolicy)
		g.PUT("/audit-policy", h.putAuditPolicy)

		g.GET("/offboarding-webhook", h.getOffboardingWebhook)
		g.PUT("/offboarding-webhook", h.putOffboardingWebhook)

		g.GET("/mfa", h.getMFA)
		g.PUT("/mfa", h.putMFA)

		g.GET("/conditional-access", h.getConditionalAccess)
		// Conditional access is an EE feature; CE reads defaults but can't change them.
		g.PUT("/conditional-access", middleware.RequireFeature(license.FeatureConditionalAccess), h.putConditionalAccess)

		g.GET("/localization", h.getLocalization)
		g.PUT("/localization", h.putLocalization)

		g.GET("/license", h.getLicense)
		g.PUT("/license", h.putLicense)

		g.GET("/external-urls", h.getExternalURLs)
		g.PUT("/external-urls", h.putExternalURLs)
	}
}

// tenantID resolves the effective tenant for the setting:
//   - `?global=true` query param  → 0 (system default), super_admin only
//   - otherwise                   → session tenant
//
// Settings are mostly global today; per-tenant overrides are a future
// feature, but the schema already supports them.
func (h *Handler) tenantID(c *gin.Context) int64 {
	if c.Query("global") == "true" {
		return 0
	}
	return tenantctx.FromContext(c, h.defaultTID)
}

func (h *Handler) userID(c *gin.Context) *int64 {
	if v, ok := c.Get("user_id"); ok {
		if id, ok := v.(int64); ok {
			return &id
		}
	}
	return nil
}

/* ──────────────── Mail SMTP ──────────────── */

func (h *Handler) getMailSMTP(c *gin.Context) {
	cfg, err := h.service.MailSMTP(c.Request.Context(), h.tenantID(c))
	if err != nil {
		response.InternalError(c, "")
		return
	}
	// Don't leak password to UI; surface a sentinel so admin can tell
	// whether one is set.
	hadPwd := cfg.Password != ""
	cfg.Password = ""
	response.OK(c, gin.H{"config": cfg, "password_set": hadPwd})
}

func (h *Handler) putMailSMTP(c *gin.Context) {
	var body setting.MailSMTP
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	// Empty password in PUT → preserve the existing one (admin didn't
	// change it). Otherwise replace.
	if body.Password == "" {
		existing, _ := h.service.MailSMTP(c.Request.Context(), h.tenantID(c))
		body.Password = existing.Password
	}
	if err := h.service.Set(c.Request.Context(), setting.KeyMailSMTP, h.tenantID(c), body, h.userID(c)); err != nil {
		response.InternalError(c, "")
		return
	}
	response.OK(c, gin.H{"saved": true})
}

func (h *Handler) testMailSMTP(c *gin.Context) {
	var body struct {
		To string `json:"to" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	err := h.mailer.Send(c.Request.Context(), h.tenantID(c), []string{body.To},
		"[MXID] SMTP 测试邮件",
		`<p>这是一封测试邮件 — 如果您收到，说明 MXID SMTP 配置成功。</p>`)
	if err != nil {
		response.BadRequest(c, 40002, err.Error())
		return
	}
	response.OK(c, gin.H{"sent": true})
}

/* ──────────────── Generic get/put helper ──────────────── */

func (h *Handler) genericGet(c *gin.Context, key string, defaultVal any) {
	if err := h.service.Get(c.Request.Context(), key, h.tenantID(c), defaultVal); err != nil && err != setting.ErrNotFound {
		response.InternalError(c, "")
		return
	}
	response.OK(c, defaultVal)
}

func (h *Handler) genericPut(c *gin.Context, key string, body any) {
	if err := c.ShouldBindJSON(body); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	if err := h.service.Set(c.Request.Context(), key, h.tenantID(c), body, h.userID(c)); err != nil {
		response.InternalError(c, "")
		return
	}
	response.OK(c, gin.H{"saved": true})
}

/* ──────────────── Per-category thin wrappers ──────────────── */

func (h *Handler) getMailTemplates(c *gin.Context) {
	v := setting.DefaultMailTemplates()
	h.genericGet(c, setting.KeyMailTemplates, &v)
}
func (h *Handler) putMailTemplates(c *gin.Context) {
	var v setting.MailTemplates
	h.genericPut(c, setting.KeyMailTemplates, &v)
}

func (h *Handler) getSecurity(c *gin.Context) {
	v := setting.DefaultSecurityPolicy()
	h.genericGet(c, setting.KeySecurityPolicy, &v)
}
func (h *Handler) putSecurity(c *gin.Context) {
	var v setting.SecurityPolicy
	h.genericPut(c, setting.KeySecurityPolicy, &v)
}

func (h *Handler) getBranding(c *gin.Context) {
	v := setting.DefaultBranding()
	h.genericGet(c, setting.KeyBranding, &v)
}
func (h *Handler) putBranding(c *gin.Context) {
	var v setting.Branding
	h.genericPut(c, setting.KeyBranding, &v)
}

func (h *Handler) getLoginMethods(c *gin.Context) {
	v := setting.DefaultLoginMethods()
	h.genericGet(c, setting.KeyLoginMethods, &v)
}
func (h *Handler) putLoginMethods(c *gin.Context) {
	var v setting.LoginMethods
	h.genericPut(c, setting.KeyLoginMethods, &v)
}

func (h *Handler) getProtocolDefaults(c *gin.Context) {
	v := setting.DefaultProtocolDefaults()
	h.genericGet(c, setting.KeyProtocolDefault, &v)
}
func (h *Handler) putProtocolDefaults(c *gin.Context) {
	var v setting.ProtocolDefaults
	h.genericPut(c, setting.KeyProtocolDefault, &v)
}

func (h *Handler) getSMS(c *gin.Context) {
	v := setting.DefaultSMS()
	if err := h.service.Get(c.Request.Context(), setting.KeySMS, h.tenantID(c), &v); err != nil && err != setting.ErrNotFound {
		response.InternalError(c, "")
		return
	}
	hadSecret := v.Secret != ""
	v.Secret = ""
	response.OK(c, gin.H{"config": v, "secret_set": hadSecret})
}
func (h *Handler) putSMS(c *gin.Context) {
	var v setting.SMS
	if err := c.ShouldBindJSON(&v); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	if v.Secret == "" {
		existing := setting.DefaultSMS()
		_ = h.service.Get(c.Request.Context(), setting.KeySMS, h.tenantID(c), &existing)
		v.Secret = existing.Secret
	}
	if err := h.service.Set(c.Request.Context(), setting.KeySMS, h.tenantID(c), v, h.userID(c)); err != nil {
		response.InternalError(c, "")
		return
	}
	response.OK(c, gin.H{"saved": true})
}

func (h *Handler) getAuditPolicy(c *gin.Context) {
	v := setting.DefaultAuditPolicy()
	h.genericGet(c, setting.KeyAuditPolicy, &v)
}
func (h *Handler) putAuditPolicy(c *gin.Context) {
	var v setting.AuditPolicy
	h.genericPut(c, setting.KeyAuditPolicy, &v)
}

func (h *Handler) getOffboardingWebhook(c *gin.Context) {
	v := setting.DefaultOffboardingWebhook()
	if err := h.service.Get(c.Request.Context(), setting.KeyOffboardingWebhook, h.tenantID(c), &v); err != nil && err != setting.ErrNotFound {
		response.InternalError(c, "")
		return
	}
	hadSecret := v.Secret != ""
	v.Secret = "" // never echo the signing secret back
	response.OK(c, gin.H{"config": v, "secret_set": hadSecret})
}

func (h *Handler) putOffboardingWebhook(c *gin.Context) {
	var v setting.OffboardingWebhook
	if err := c.ShouldBindJSON(&v); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	if v.Enabled {
		if u, err := url.Parse(v.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			response.BadRequest(c, 40001, "invalid webhook url")
			return
		}
	}
	// Blank secret on save = keep the existing one (the UI never echoes it back).
	if v.Secret == "" {
		existing := setting.DefaultOffboardingWebhook()
		_ = h.service.Get(c.Request.Context(), setting.KeyOffboardingWebhook, h.tenantID(c), &existing)
		v.Secret = existing.Secret
	}
	if err := h.service.Set(c.Request.Context(), setting.KeyOffboardingWebhook, h.tenantID(c), v, h.userID(c)); err != nil {
		response.InternalError(c, "")
		return
	}
	response.OK(c, gin.H{"saved": true})
}

func (h *Handler) getMFA(c *gin.Context) {
	v := setting.DefaultMFAPolicy()
	h.genericGet(c, setting.KeyMFAPolicy, &v)
}
func (h *Handler) putMFA(c *gin.Context) {
	var v setting.MFAPolicy
	if err := c.ShouldBindJSON(&v); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	switch v.Mode {
	case setting.MFAModeOff, setting.MFAModeAdminOnly, setting.MFAModeAll:
	default:
		response.BadRequest(c, 40001, "invalid mfa mode")
		return
	}
	if v.StepUpWindowSeconds < 0 {
		v.StepUpWindowSeconds = 0
	}
	if err := h.service.Set(c.Request.Context(), setting.KeyMFAPolicy, h.tenantID(c), &v, h.userID(c)); err != nil {
		response.InternalError(c, "")
		return
	}
	response.OK(c, gin.H{"saved": true})
}

func (h *Handler) getConditionalAccess(c *gin.Context) {
	v := setting.DefaultConditionalAccess()
	h.genericGet(c, setting.KeyConditionalAccess, &v)
}
func (h *Handler) putConditionalAccess(c *gin.Context) {
	var v setting.ConditionalAccess
	if err := c.ShouldBindJSON(&v); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	if v.ImpossibleTravelWindowMinutes < 0 {
		v.ImpossibleTravelWindowMinutes = 0
	}
	if err := h.service.Set(c.Request.Context(), setting.KeyConditionalAccess, h.tenantID(c), &v, h.userID(c)); err != nil {
		response.InternalError(c, "")
		return
	}
	response.OK(c, gin.H{"saved": true})
}

func (h *Handler) getLocalization(c *gin.Context) {
	v := setting.DefaultLocalization()
	h.genericGet(c, setting.KeyLocalization, &v)
}
func (h *Handler) putLocalization(c *gin.Context) {
	var v setting.Localization
	h.genericPut(c, setting.KeyLocalization, &v)
}

func (h *Handler) getLicense(c *gin.Context) {
	v := setting.DefaultLicense()
	if err := h.platform.Get(c.Request.Context(), platformconfig.KeyLicense, &v); err != nil && err != platformconfig.ErrNotFound {
		response.InternalError(c, "")
		return
	}
	// Never leak the signed token back to the UI — it's a secret (anyone who
	// copies it can activate elsewhere). Surface only whether one is set; the
	// edition/customer/expiry are non-secret derived fields.
	v.KeySet = v.Key != ""
	v.Key = ""
	v.InstallID = license.InstallFingerprint()
	response.OK(c, v)
}

// putLicense accepts ONLY the signed token (key). Edition / customer / expiry /
// limits are DERIVED from the verified token — never trusted from the client —
// and the active license is hot-reloaded so gates flip without a restart. The
// old admin-editable enable_enterprise / max_* inputs are gone: an operator can
// no longer self-grant EE by editing fields.
func (h *Handler) putLicense(c *gin.Context) {
	var body struct {
		Key string `json:"key"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, 40001, err.Error())
		return
	}
	key := strings.TrimSpace(body.Key)
	if key == "" {
		// Empty submit = keep the existing license (the UI never echoes the
		// token back, so a blank field means "unchanged", not "deactivate").
		existing := setting.DefaultLicense()
		_ = h.platform.Get(c.Request.Context(), platformconfig.KeyLicense, &existing)
		key = existing.Key
	}
	mgr := license.Load(key, time.Now())

	derived := setting.License{
		Key:          key,
		RegisteredTo: mgr.Customer(),
		MaxUsers:     mgr.MaxUsers(),
		MaxTenants:   mgr.MaxTenants(),
	}
	if exp := mgr.ExpiresAt(); !exp.IsZero() {
		derived.ExpiresAt = exp.Format("2006-01-02")
	}
	if err := h.platform.Set(c.Request.Context(), platformconfig.KeyLicense, derived); err != nil {
		response.InternalError(c, "")
		return
	}
	license.SetCurrent(mgr)

	errStr := ""
	if e := mgr.LoadErr(); e != nil {
		errStr = e.Error()
	}
	response.OK(c, gin.H{
		"edition":  string(mgr.Edition()),
		"valid":    mgr.IsEE(),
		"customer": mgr.Customer(),
		"features": mgr.EnabledFeatures(),
		"error":    errStr,
	})
}

func (h *Handler) getExternalURLs(c *gin.Context) {
	v := setting.DefaultExternalURLs()
	h.genericGet(c, setting.KeyExternalURLs, &v)
}
func (h *Handler) putExternalURLs(c *gin.Context) {
	var v setting.ExternalURLs
	h.genericPut(c, setting.KeyExternalURLs, &v)
}
