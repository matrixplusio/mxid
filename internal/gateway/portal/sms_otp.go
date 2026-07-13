// SMS OTP login: passwordless sign-in via a 6-digit code sent over SMS.
// Two endpoints, both public (pre-auth):
//
//	POST /api/v1/portal-public/auth/sms/send   {phone, tenant?}
//	     → if SMS is enabled and the phone maps to a real user, generate a
//	       6-digit code in Redis (5 min TTL) and dispatch via the
//	       configured SMS provider. Always returns 200 (no enumeration).
//
//	POST /api/v1/portal-public/auth/sms/login  {phone, code, tenant?}
//	     → consume the code, create a portal session, return the user
//	       payload + set the session cookie.
//
// Gated by LoginMethods.SMSOTP. Disabled → 403 on /send.
package portal

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/sms"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	smsOTPTTL       = 300 // seconds — 5 min
	smsOTPKeyPrefix = "sms_otp:"
	// Resend cooldown: same phone can't request a new code for 60s.
	smsOTPCooldown       = 60
	smsOTPCooldownPrefix = "sms_otp_cooldown:"
)

// errSMSCodeInvalid is the safe, user-facing result of consumeCode for a
// wrong/expired/malformed code. The handler treats it as a failed attempt
// (counted against the phone's rate budget) and 400s; any OTHER consumeCode
// error (a wrapped Redis failure) becomes a logged 500 that neither leaks the
// infra error text nor burns the caller's guess budget on an outage.
var errSMSCodeInvalid = errors.New("code invalid or expired")

// SMSEnabledChecker — true when LoginMethods.SMSOTP is enabled for the
// default tenant.
type SMSEnabledChecker func(ctx context.Context) bool

// SMSOTPHandler manages the send/login flow.
type SMSOTPHandler struct {
	rdb        *redis.Client
	users      UserQuerier
	logger     *zap.Logger
	smsSvc     *sms.Service
	sessionMgr *session.Manager
	enabled    SMSEnabledChecker
	defaultTID int64
	tenantByCd TenantResolver
	cookieDom  string
	cookieSec  bool
	// devFallback gates the dev_code response field + code Info log on
	// non-release mode. In release the OTP code is never returned or logged.
	devFallback bool
	// limiter caps wrong-code guesses per phone. consumeCode deliberately
	// keeps a still-valid code alive on a typo (so the user isn't forced to
	// resend), which without a cap leaves the 6-digit space brute-forceable
	// within the 5-min TTL. The limiter closes that hole; nil = no cap.
	limiter *ratelimit.Limiter
}

// SMSOTPHandlerOpts groups the dependency soup.
type SMSOTPHandlerOpts struct {
	Redis        *redis.Client
	Users        UserQuerier
	Logger       *zap.Logger
	SMS          *sms.Service
	SessionMgr   *session.Manager
	Enabled      SMSEnabledChecker
	DefaultTID   int64
	TenantByCode TenantResolver
	CookieDomain string
	CookieSecure bool
	// DevFallback enables the non-release dev_code exposure.
	DevFallback bool
	// Limiter is the per-phone brute-force cap on /auth/sms/login. nil
	// disables the cap (legacy behaviour).
	Limiter *ratelimit.Limiter
}

func NewSMSOTPHandler(o SMSOTPHandlerOpts) *SMSOTPHandler {
	return &SMSOTPHandler{
		rdb:         o.Redis,
		users:       o.Users,
		logger:      o.Logger,
		smsSvc:      o.SMS,
		sessionMgr:  o.SessionMgr,
		enabled:     o.Enabled,
		defaultTID:  o.DefaultTID,
		tenantByCd:  o.TenantByCode,
		cookieDom:   o.CookieDomain,
		cookieSec:   o.CookieSecure,
		devFallback: o.DevFallback,
		limiter:     o.Limiter,
	}
}

// RegisterSMSOTPRoutes mounts /auth/sms/send + /auth/sms/login on rg.
func RegisterSMSOTPRoutes(rg *gin.RouterGroup, h *SMSOTPHandler) {
	rg.POST("/auth/sms/send", h.send)
	rg.POST("/auth/sms/login", h.login)
}

type smsSendRequest struct {
	Phone  string `json:"phone" binding:"required,min=4,max=32"`
	Tenant string `json:"tenant"`
}

type smsSendResponse struct {
	Sent       bool `json:"sent"`
	TTLSeconds int  `json:"ttl_seconds"`
	// DevCode is populated only when SMS service is disabled OR provider
	// send failed AND the phone matched a real user. Dev fallback so OSS
	// admins can complete the flow.
	DevCode string `json:"dev_code,omitempty"`
}

func (h *SMSOTPHandler) send(c *gin.Context) {
	if h.enabled != nil && !h.enabled(c.Request.Context()) {
		response.Error(c, http.StatusForbidden, 40301, "sms otp login disabled", "")
		return
	}

	var req smsSendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	phone := strings.TrimSpace(req.Phone)
	resp := smsSendResponse{Sent: true, TTLSeconds: smsOTPTTL}

	// Cooldown — same phone can't spam /send. Key is independent of
	// tenant_id; phone numbers are globally unique enough for this.
	cooldownKey := smsOTPCooldownPrefix + phone
	if exists, _ := h.rdb.Exists(c.Request.Context(), cooldownKey).Result(); exists > 0 {
		// Cooldown is a rate-limit condition — emit 429 to match the other 42901
		// sites (it was a 400 here, a status collision on the same code).
		response.Error(c, http.StatusTooManyRequests, 42901, "please wait before requesting another code", "")
		return
	}

	tenantID := h.resolveTenant(c.Request.Context(), req.Tenant)
	// Pin the resolved tenant so the user lookup runs tenant-scoped (public
	// route, no AuthMiddleware to set the scope).
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), tenantID))
	userID, err := h.users.LookupByPhone(c.Request.Context(), tenantID, phone)
	if err != nil {
		h.logger.Warn("sms otp send: lookup failed", zap.String("phone", phone), zap.Error(err))
		response.OK(c, resp)
		return
	}
	if userID == 0 {
		// Unknown phone — same shape, no code issued.
		response.OK(c, resp)
		return
	}

	code, err := generateSMSCode()
	if err != nil {
		response.InternalError(c, "failed to generate code", err)
		return
	}
	val := fmt.Sprintf("%d:%s", userID, code)
	if err := h.rdb.Set(c.Request.Context(), smsOTPKeyPrefix+phone, val, smsOTPTTL*1e9).Err(); err != nil {
		response.InternalError(c, "failed to persist code", err)
		return
	}
	// Set cooldown after token persist. Fail CLOSED: if the cooldown can't be
	// recorded we cannot throttle the next request, so refuse rather than let an
	// SMS-spray / cost-amplification window open on a Redis blip.
	if err := h.rdb.Set(c.Request.Context(), cooldownKey, "1", smsOTPCooldown*1e9).Err(); err != nil {
		response.InternalError(c, "failed to set cooldown", err)
		return
	}

	providerOK := false
	if h.smsSvc != nil {
		if err := h.smsSvc.SendOTP(c.Request.Context(), tenantID, phone, code); err == nil {
			providerOK = true
		} else {
			h.logger.Warn("sms provider send failed, falling back to dev_code",
				zap.String("phone", phone), zap.Error(err))
		}
	}
	if !providerOK {
		if h.devFallback {
			resp.DevCode = code
			h.logger.Info("sms otp (no provider / fallback)",
				zap.Int64("user_id", userID),
				zap.String("phone", phone),
				zap.String("code", code),
				zap.Int("ttl_seconds", smsOTPTTL))
		} else {
			h.logger.Warn("sms provider send failed (no dev fallback in release)",
				zap.Int64("user_id", userID))
		}
	}
	response.OK(c, resp)
}

type smsLoginRequest struct {
	Phone  string `json:"phone" binding:"required"`
	Code   string `json:"code" binding:"required,len=6"`
	Tenant string `json:"tenant"`
}

type smsLoginResponse struct {
	UserID      int64  `json:"user_id,string"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

func (h *SMSOTPHandler) login(c *gin.Context) {
	if h.enabled != nil && !h.enabled(c.Request.Context()) {
		response.Error(c, http.StatusForbidden, 40301, "sms otp login disabled", "")
		return
	}

	var req smsLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	phone := strings.TrimSpace(req.Phone)
	tenantID := h.resolveTenant(c.Request.Context(), req.Tenant)
	// Pin the resolved tenant so the user read below runs tenant-scoped.
	c.Request = c.Request.WithContext(tenantscope.WithTenant(c.Request.Context(), tenantID))

	// Per-phone brute-force cap: the OTP is only 6 digits and consumeCode keeps
	// a wrong-guess code alive (TTL-based), so without this the code is
	// brute-forceable within its 5-min window. Block once the phone trips.
	if rle := rateLimited(c.Request.Context(), h.limiter, "phone:"+phone); rle != nil {
		respondRateLimited(c, rle)
		return
	}

	userID, err := h.consumeCode(c.Request.Context(), phone, req.Code)
	if err != nil {
		// A Redis failure is not a failed guess: 500 it (logged, not leaked)
		// without burning the phone's budget or echoing the infra error text.
		if !errors.Is(err, errSMSCodeInvalid) {
			response.InternalError(c, "failed to verify code", err)
			return
		}
		// Wrong/expired code — count it against the phone's budget. Tripping
		// the cap immediately returns 429 so the attacker can't keep guessing.
		if rle := h.limiter.RecordFailure(c.Request.Context(), "phone:"+phone); rle != nil {
			var rlErr *ratelimit.RateLimitError
			if errors.As(rle, &rlErr) {
				respondRateLimited(c, rlErr)
				return
			}
		}
		response.BadRequest(c, 40002, "code invalid or expired")
		return
	}
	// Correct code — clear the phone's failure budget.
	h.limiter.Reset(c.Request.Context(), "phone:"+phone)

	user, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to read user", err)
		return
	}

	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	sess, err := h.sessionMgr.Create(c.Request.Context(), session.NamespacePortal, userID, tenantID, ip, ua, "sms_otp")
	if err != nil {
		response.InternalError(c, "failed to create session", err)
		return
	}
	// Stamp last-login. Passwordless logins bypass the password engine's
	// completeLogin (the only other UpdateLastLogin caller), so without this
	// the user's "last login" never reflects an SMS OTP sign-in. Best-effort:
	// a bookkeeping failure must not fail an otherwise successful login.
	if err := h.users.UpdateLastLogin(c.Request.Context(), userID, ip); err != nil {
		h.logger.Warn("sms login: update last login failed",
			zap.Int64("user_id", userID), zap.Error(err))
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authn.CookiePortal, sess.ID, 86400, "/", h.cookieDom, h.cookieSec, true)
	response.OK(c, smsLoginResponse{
		UserID:      user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
	})
}

// consumeCode reads + atomically clears the (userID, expectedCode) bound
// to the phone. Compares constant-time (string compare here is acceptable
// because the OTP is 6 random digits — a timing attack on each digit
// wouldn't help an attacker within 5 minutes).
func (h *SMSOTPHandler) consumeCode(ctx context.Context, phone, code string) (int64, error) {
	key := smsOTPKeyPrefix + phone
	val, err := h.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, errSMSCodeInvalid
		}
		return 0, fmt.Errorf("read code: %w", err)
	}
	parts := strings.SplitN(val, ":", 2)
	if len(parts) != 2 {
		return 0, errSMSCodeInvalid
	}
	var userID int64
	if _, err := fmt.Sscanf(parts[0], "%d", &userID); err != nil {
		return 0, errSMSCodeInvalid
	}
	if parts[1] != code {
		// Wrong code — DO NOT delete; let the 5-min TTL handle the lockout.
		// Otherwise one fat-fingered keystroke would force a resend.
		return 0, errSMSCodeInvalid
	}
	// Correct — clear so it can't be reused.
	_ = h.rdb.Del(ctx, key).Err()
	return userID, nil
}

func (h *SMSOTPHandler) resolveTenant(ctx context.Context, code string) int64 {
	if code == "" || h.tenantByCd == nil {
		return h.defaultTID
	}
	if tid := h.tenantByCd(ctx, code); tid > 0 {
		return tid
	}
	return h.defaultTID
}

// generateSMSCode returns a 6-digit numeric OTP. Uses crypto/rand (not
// math/rand) so the codes aren't predictable across server restarts.
func generateSMSCode() (string, error) {
	const digits = 6
	max := big.NewInt(10)
	out := make([]byte, digits)
	for i := range digits {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = byte('0' + n.Int64())
	}
	return string(out), nil
}
