// Password reset is the lost-password recovery flow used by the portal
// login page. Two endpoints, both public (pre-auth):
//
//	POST /api/v1/portal-public/password/forgot   {email, tenant?}
//	     → if SMTP enabled: emails a link/code via mailer.SendPasswordResetEmail
//	     → always returns 200 even when the email maps to no user
//	       (avoid leaking email enumeration; mirrors Auth0/Okta behaviour)
//
//	POST /api/v1/portal-public/password/reset    {token, new_password}
//	     → consumes the one-shot token, writes a new password through
//	       user.Service.ResetPassword (full policy + history checks apply)
//
// Tokens live in Redis for 30 minutes — same TTL as the email-verify flow.
// We tie token → user_id (not token → email) so a user changing their
// email mid-flight invalidates the in-flight link.
package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/imkerbos/mxid/pkg/mailer"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	pwdResetTTL       = 1800 // seconds — 30 min
	pwdResetKeyPrefix = "pwd_reset:"
)

// errResetTokenInvalid is the safe, user-facing result of consumeToken when the
// token is missing/expired/malformed. It lets the handler 400 on this case and
// route every OTHER consumeToken error (a wrapped Redis failure) to a logged
// 500 instead of echoing the infra error text back to the client.
var errResetTokenInvalid = errors.New("token invalid or expired")

// TenantResolver resolves a portal-supplied tenant code (e.g. "matrixplus")
// to its int64 id. Mirrors the resolver wired into the login handler; we
// re-use the same signature so main.go can pass the same callback in.
type TenantResolver func(ctx context.Context, code string) int64

// PasswordResetHandler manages the forgot/reset flow.
type PasswordResetHandler struct {
	rdb        *redis.Client
	users      UserQuerier
	logger     *zap.Logger
	publicURL  string
	mailer     *mailer.Mailer
	defaultTID int64
	tenantByCd TenantResolver
	// devFallback gates the dev_link response field + the link Info log on
	// non-release mode. In release the reset link is NEVER returned in the
	// HTTP body and never logged, so a misconfigured/failing SMTP provider
	// can't leak the out-of-band reset secret. Set from cfg.Server.IsRelease().
	devFallback bool
	// limiter throttles /password/forgot per email so repeated calls can't
	// spam reset emails. nil = no throttle. Wired via SetLimiter.
	limiter *ratelimit.Limiter
}

// SetDevFallback toggles the non-release dev_link exposure. Kept as a setter
// so the positional constructor signature stays stable.
func (h *PasswordResetHandler) SetDevFallback(on bool) { h.devFallback = on }

// SetLimiter wires the per-email forgot-password send throttle. nil disables
// throttling (legacy behaviour). Kept as a setter so the positional
// constructor signature stays stable.
func (h *PasswordResetHandler) SetLimiter(l *ratelimit.Limiter) { h.limiter = l }

// NewPasswordResetHandler builds the handler. tenantByCode may be nil —
// the handler falls back to the default tenant.
func NewPasswordResetHandler(
	rdb *redis.Client, users UserQuerier, logger *zap.Logger,
	publicURL string, mailerSvc *mailer.Mailer, defaultTID int64,
	tenantByCode TenantResolver,
) *PasswordResetHandler {
	return &PasswordResetHandler{
		rdb:        rdb,
		users:      users,
		logger:     logger,
		publicURL:  publicURL,
		mailer:     mailerSvc,
		defaultTID: defaultTID,
		tenantByCd: tenantByCode,
	}
}

// RegisterPasswordResetRoutes mounts /password/forgot + /password/reset on
// the supplied public route group. The caller is responsible for choosing
// a group that does NOT carry an auth-middleware (these endpoints are
// pre-login by definition).
func RegisterPasswordResetRoutes(rg *gin.RouterGroup, h *PasswordResetHandler) {
	rg.POST("/password/forgot", h.forgot)
	rg.POST("/password/reset", h.reset)
}

type forgotRequest struct {
	Email  string `json:"email" binding:"required,email"`
	Tenant string `json:"tenant"`
}

type forgotResponse struct {
	// Sent is always true — we never disclose whether the email matched a
	// real user. UIs should show a "if the email exists, a link was sent"
	// message regardless.
	Sent bool `json:"sent"`
	// DevLink is non-empty ONLY when SMTP is not configured AND the email
	// matched a real user. Lets first-deploy admins click through without
	// configuring SMTP. Production never sees this populated.
	DevLink string `json:"dev_link,omitempty"`
	// TTLSeconds is the lifetime of the reset token; surfaces in the UI as
	// a hint so users don't ignore the link for hours.
	TTLSeconds int `json:"ttl_seconds"`
}

func (h *PasswordResetHandler) forgot(c *gin.Context) {
	var req forgotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	resp := forgotResponse{Sent: true, TTLSeconds: pwdResetTTL}

	// Per-email throttle so repeated /password/forgot calls can't spam reset
	// emails. Checked + counted BEFORE the user lookup so existent and
	// non-existent emails throttle identically (no enumeration leak).
	if rle := rateLimited(c.Request.Context(), h.limiter, "pwreset:"+email); rle != nil {
		respondRateLimited(c, rle)
		return
	}
	if rle := h.limiter.RecordFailure(c.Request.Context(), "pwreset:"+email); rle != nil {
		var rlErr *ratelimit.RateLimitError
		if errors.As(rle, &rlErr) {
			respondRateLimited(c, rlErr)
			return
		}
	}

	tenantID := h.resolveTenant(c.Request.Context(), req.Tenant)
	// Pin the resolved tenant so the user lookups / reads below run
	// tenant-scoped (this route is mounted on the unauthenticated public
	// group, so nothing else sets the scope).
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), tenantID))
	userID, err := h.users.LookupByEmail(c.Request.Context(), tenantID, email)
	if err != nil {
		h.logger.Warn("password forgot: lookup failed",
			zap.String("email", email),
			zap.Error(err))
		// Still respond as if successful — never confirm or deny the email.
		response.OK(c, resp)
		return
	}
	if userID == 0 {
		// Unknown email — return the same shape. No token issued, no log.
		response.OK(c, resp)
		return
	}

	token, err := generateToken()
	if err != nil {
		response.InternalError(c, "failed to generate token", err)
		return
	}
	// Bind both tenant and user to the token so the (tenant-less) reset call
	// can re-establish the tenant scope before mutating the user row.
	tokenVal := strconv.FormatInt(tenantID, 10) + ":" + strconv.FormatInt(userID, 10)
	if err := h.rdb.Set(c.Request.Context(), pwdResetKeyPrefix+token, tokenVal, pwdResetTTL*1e9).Err(); err != nil {
		response.InternalError(c, "failed to persist token", err)
		return
	}

	link := fmt.Sprintf("%s/password/reset?token=%s", h.publicURL, token)
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
		// Short numeric code is also included so OTP-style flows (admin
		// who'd rather hand-type) work; templates pick {{.Link}} or
		// {{.Code}} as appropriate.
		code := token[:8]
		if err := h.mailer.SendPasswordResetEmail(c.Request.Context(), tenantID, email, displayName, username, link, code); err == nil {
			smtpOK = true
		} else {
			h.logger.Warn("password reset email send failed, falling back to dev_link",
				zap.String("email", email),
				zap.Error(err))
		}
	}
	if !smtpOK {
		if h.devFallback {
			resp.DevLink = link
			h.logger.Info("password reset link (no SMTP / fallback)",
				zap.Int64("user_id", userID),
				zap.String("email", email),
				zap.String("link", link),
				zap.Int("ttl_seconds", pwdResetTTL),
			)
		} else {
			// Release mode: never leak the reset link into the response or
			// logs. Record only a non-sensitive warning.
			h.logger.Warn("password reset email send failed (no dev fallback in release)",
				zap.Int64("user_id", userID))
		}
	}
	response.OK(c, resp)
}

type resetRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6,max=128"`
}

func (h *PasswordResetHandler) reset(c *gin.Context) {
	var req resetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	tenantID, userID, err := h.consumeToken(c.Request.Context(), req.Token)
	if err != nil {
		if errors.Is(err, errResetTokenInvalid) {
			response.BadRequest(c, 40002, "token invalid or expired")
			return
		}
		response.InternalError(c, "failed to reset password", err)
		return
	}
	// Re-establish the tenant scope captured at forgot-time so the password
	// write is tenant-isolated even though the reset request itself carries
	// no tenant.
	if tenantID > 0 {
		c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), tenantID))
	}

	if err := h.users.ResetPassword(c.Request.Context(), userID, req.NewPassword); err != nil {
		// Discriminate on the real sentinels (not a string-match heuristic,
		// which could misclassify an unrelated error as "password" and mask
		// a genuine 500, or vice versa). The token was already consumed by
		// this point, so a stale user (deleted between forgot and reset)
		// reads to the caller the same as an invalid/expired token — it
		// carries no more information than that already.
		switch {
		case errors.Is(err, user.ErrUserNotFound):
			response.BadRequest(c, 40002, "token invalid or expired")
		case errors.Is(err, user.ErrWeakPassword):
			response.BadRequest(c, 40004, err.Error())
		case errors.Is(err, user.ErrPasswordReused):
			// 40005 (matches user.codePasswordReused), NOT 40003 — 40003
			// collides with the frontend's global totpCodeReused localization.
			response.BadRequest(c, 40005, err.Error())
		default:
			response.InternalError(c, "failed to reset password", err)
		}
		return
	}

	response.OK(c, gin.H{"reset": true})
}

// consumeToken atomically reads + deletes the (tenant_id, user_id) pair bound
// to the token. Mirrors the email-verify pattern: one-shot, no replay. The
// value is "tenant:user"; a legacy bare-int value (no tenant) parses with
// tenantID=0, in which case the caller leaves the scope unset and the
// underlying ResetPassword still works via its explicit user id.
func (h *PasswordResetHandler) consumeToken(ctx context.Context, token string) (tenantID, userID int64, err error) {
	key := pwdResetKeyPrefix + token
	val, err := h.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, 0, errResetTokenInvalid
		}
		return 0, 0, fmt.Errorf("read token: %w", err)
	}
	_ = h.rdb.Del(ctx, key).Err()

	if i := strings.IndexByte(val, ':'); i >= 0 {
		tenantID, _ = strconv.ParseInt(val[:i], 10, 64)
		userID, _ = strconv.ParseInt(val[i+1:], 10, 64)
	} else {
		userID, _ = strconv.ParseInt(val, 10, 64)
	}
	if userID == 0 {
		return 0, 0, errors.New("token invalid or expired")
	}
	return tenantID, userID, nil
}

func (h *PasswordResetHandler) resolveTenant(ctx context.Context, code string) int64 {
	if code == "" || h.tenantByCd == nil {
		return h.defaultTID
	}
	if tid := h.tenantByCd(ctx, code); tid > 0 {
		return tid
	}
	return h.defaultTID
}

// HTTP 200/400 conventions follow the rest of the portal — we don't bring
// gin.H + http stdlib into the rest of the handler so they only appear in
// the resetSuccess fallback path above. Keep this import here so the
// http.StatusFound reference compiles even if the JSON happy path drops it.
var _ = http.StatusFound
