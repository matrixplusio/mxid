// Magic-link login: passwordless sign-in via a one-shot URL emailed to
// the user. Two endpoints, both public (pre-auth):
//
//   POST /api/v1/portal-public/auth/magic-link/send  {email, tenant?}
//        → if the email maps to a real user AND magic-link is enabled in
//          settings, issue a one-shot token (5 min) in Redis and email
//          the callback URL. Response shape is identical regardless of
//          whether the email exists (no enumeration).
//
//   GET  /api/v1/portal-public/auth/magic-link/callback?token=...&tenant=...
//        → consume the token, create a portal session, set the session
//          cookie, redirect to the portal home.
//
// Gated by LoginMethods.EmailMagicLink: when admin disables magic-link
// the /send endpoint returns 403; /callback still works for tokens issued
// before the toggle flipped (they expire in 5 min anyway).
package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/mailer"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	magicLinkTTL       = 300 // seconds — 5 min
	magicLinkKeyPrefix = "magic_link:"
)

// MagicLinkEnabledChecker returns true when admin has enabled the
// EmailMagicLink login method for the default tenant. Used by the send
// endpoint to short-circuit before issuing tokens.
type MagicLinkEnabledChecker func(ctx context.Context) bool

// MagicLinkHandler manages the send/callback flow.
type MagicLinkHandler struct {
	rdb        *redis.Client
	users      UserQuerier
	logger     *zap.Logger
	publicURL  string
	mailer     *mailer.Mailer
	sessionMgr *session.Manager
	enabled    MagicLinkEnabledChecker
	defaultTID int64
	tenantByCd TenantResolver
	cookieDom  string
	cookieSec  bool
	// devFallback gates the dev_link response field + link Info log on
	// non-release mode. In release the magic link is never returned or logged.
	devFallback bool
	// limiter throttles /auth/magic-link/send per email so an attacker can't
	// email-bomb a victim (the send side previously had no throttle at all,
	// unlike sms-otp's 60s cooldown). nil = no throttle.
	limiter *ratelimit.Limiter
}

// MagicLinkHandlerOpts captures the dependency soup so call sites can pass
// a single literal instead of a 10-arg constructor.
type MagicLinkHandlerOpts struct {
	Redis        *redis.Client
	Users        UserQuerier
	Logger       *zap.Logger
	PortalURL    string
	Mailer       *mailer.Mailer
	SessionMgr   *session.Manager
	Enabled      MagicLinkEnabledChecker
	DefaultTID   int64
	TenantByCode TenantResolver
	CookieDomain string
	CookieSecure bool
	// DevFallback enables the non-release dev_link exposure. Set from
	// cfg.Server.IsRelease() inverted at the call site.
	DevFallback bool
	// Limiter throttles send per email. nil disables throttling.
	Limiter *ratelimit.Limiter
}

func NewMagicLinkHandler(o MagicLinkHandlerOpts) *MagicLinkHandler {
	return &MagicLinkHandler{
		rdb:        o.Redis,
		users:      o.Users,
		logger:     o.Logger,
		publicURL:  o.PortalURL,
		mailer:     o.Mailer,
		sessionMgr: o.SessionMgr,
		enabled:    o.Enabled,
		defaultTID: o.DefaultTID,
		tenantByCd: o.TenantByCode,
		cookieDom:   o.CookieDomain,
		cookieSec:   o.CookieSecure,
		devFallback: o.DevFallback,
		limiter:     o.Limiter,
	}
}

// RegisterMagicLinkRoutes mounts /auth/magic-link/send + callback on rg.
func RegisterMagicLinkRoutes(rg *gin.RouterGroup, h *MagicLinkHandler) {
	rg.POST("/auth/magic-link/send", h.send)
	rg.GET("/auth/magic-link/callback", h.callback)
}

type magicSendRequest struct {
	Email  string `json:"email" binding:"required,email"`
	Tenant string `json:"tenant"`
}

type magicSendResponse struct {
	Sent       bool   `json:"sent"`
	TTLSeconds int    `json:"ttl_seconds"`
	DevLink    string `json:"dev_link,omitempty"`
}

func (h *MagicLinkHandler) send(c *gin.Context) {
	if h.enabled != nil && !h.enabled(c.Request.Context()) {
		response.Error(c, http.StatusForbidden, 40301, "magic link login disabled", "")
		return
	}

	var req magicSendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	resp := magicSendResponse{Sent: true, TTLSeconds: magicLinkTTL}

	// Per-email send throttle to stop email-bombing. Checked BEFORE the user
	// lookup so existent and non-existent emails are throttled identically
	// (no enumeration via differential throttling). Every send counts toward
	// the budget; the limiter trips after MaxAttempts within Window.
	if rle := rateLimited(c.Request.Context(), h.limiter, "mlink:"+email); rle != nil {
		respondRateLimited(c, rle)
		return
	}
	if rle := h.limiter.RecordFailure(c.Request.Context(), "mlink:"+email); rle != nil {
		var rlErr *ratelimit.RateLimitError
		if errors.As(rle, &rlErr) {
			respondRateLimited(c, rlErr)
			return
		}
	}

	tenantID := h.resolveTenant(c.Request.Context(), req.Tenant)
	// Pin the resolved tenant so the user lookup / read run tenant-scoped
	// (public route, no AuthMiddleware to set the scope).
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), tenantID))
	userID, err := h.users.LookupByEmail(c.Request.Context(), tenantID, email)
	if err != nil {
		h.logger.Warn("magic link send: lookup failed", zap.String("email", email), zap.Error(err))
		response.OK(c, resp)
		return
	}
	if userID == 0 {
		// Unknown email — same shape, no token.
		response.OK(c, resp)
		return
	}

	token, err := generateToken()
	if err != nil {
		response.InternalError(c, "failed to generate token", err)
		return
	}
	// Encode (user_id|tenant_id) so the callback doesn't need a second lookup.
	val := fmt.Sprintf("%d:%d", userID, tenantID)
	if err := h.rdb.Set(c.Request.Context(), magicLinkKeyPrefix+token, val, magicLinkTTL*1e9).Err(); err != nil {
		response.InternalError(c, "failed to persist token", err)
		return
	}

	link := fmt.Sprintf("%s/api/v1/portal-public/auth/magic-link/callback?token=%s", strings.TrimRight(h.publicURL, "/"), token)
	if req.Tenant != "" {
		link += "&tenant=" + req.Tenant
	}

	smtpOK := false
	if h.mailer != nil {
		var displayName, username string
		if u, err := h.users.GetByID(c.Request.Context(), userID); err == nil {
			displayName = u.DisplayName
			username = u.Username
			if displayName == "" {
				displayName = username
			}
		}
		if err := h.mailer.SendMagicLinkEmail(c.Request.Context(), tenantID, email, displayName, username, link); err == nil {
			smtpOK = true
		} else {
			h.logger.Warn("magic link mail send failed, falling back to dev_link",
				zap.String("email", email), zap.Error(err))
		}
	}
	if !smtpOK {
		if h.devFallback {
			resp.DevLink = link
			h.logger.Info("magic link (no SMTP / fallback)",
				zap.Int64("user_id", userID),
				zap.String("email", email),
				zap.String("link", link))
		} else {
			h.logger.Warn("magic link mail send failed (no dev fallback in release)",
				zap.Int64("user_id", userID))
		}
	}
	response.OK(c, resp)
}

func (h *MagicLinkHandler) callback(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		response.BadRequest(c, 40001, "token required")
		return
	}
	userID, tenantID, err := h.consumeToken(c.Request.Context(), token)
	if err != nil {
		// Redirect back to login with an error so the user sees a UI hint
		// instead of a bare JSON 400.
		c.Redirect(http.StatusFound, h.publicURL+"/login?err=magic_expired")
		return
	}

	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	sess, err := h.sessionMgr.Create(c.Request.Context(), session.NamespacePortal, userID, tenantID, ip, ua, "magic_link")
	if err != nil {
		response.InternalError(c, "failed to create session", err)
		return
	}
	// Stamp last-login (see sms_otp.go): magic-link callbacks bypass the
	// password engine, so the stamp must happen here. Best-effort.
	if err := h.users.UpdateLastLogin(c.Request.Context(), userID, ip); err != nil {
		h.logger.Warn("magic link login: update last login failed",
			zap.Int64("user_id", userID), zap.Error(err))
	}
	// 24h cookie — magic-link callers don't get remember-me; they re-auth
	// via another magic link or password next time.
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authn.CookiePortal, sess.ID, 86400, "/", h.cookieDom, h.cookieSec, true)
	c.Redirect(http.StatusFound, h.publicURL+"/apps")
}

func (h *MagicLinkHandler) consumeToken(ctx context.Context, token string) (int64, int64, error) {
	key := magicLinkKeyPrefix + token
	val, err := h.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, 0, errors.New("token invalid or expired")
		}
		return 0, 0, fmt.Errorf("read token: %w", err)
	}
	_ = h.rdb.Del(ctx, key).Err()

	var userID, tenantID int64
	if _, err := fmt.Sscanf(val, "%d:%d", &userID, &tenantID); err != nil {
		return 0, 0, fmt.Errorf("parse token payload: %w", err)
	}
	return userID, tenantID, nil
}

func (h *MagicLinkHandler) resolveTenant(ctx context.Context, code string) int64 {
	if code == "" || h.tenantByCd == nil {
		return h.defaultTID
	}
	if tid := h.tenantByCd(ctx, code); tid > 0 {
		return tid
	}
	return h.defaultTID
}
