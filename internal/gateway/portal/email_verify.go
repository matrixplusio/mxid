package portal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/mailer"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/tenantctx"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// TTL for verification tokens. 30 min is the common industry default —
// long enough that the user can switch apps + open their inbox, short
// enough that leaked tokens expire before they're useful.
const emailVerifyTTL = 1800 // seconds

const verifyKeyPrefix = "email_verify:"

// EmailVerifyHandler manages the email verification flow.
//
// Flow:
//   1. POST /profile/email/send-verification  → generates token, stores in
//      redis ({prefix}{token} → userID), and returns the verification URL.
//      In production this URL would be sent via SMTP; in dev it's also
//      logged so the developer can click it.
//   2. GET  /profile/email/verify?token=...    → consumes the token (one-shot),
//      flips email_verified=true.
//
// We tie token → userID rather than token → email so a user changing their
// email after requesting verification automatically invalidates the in-flight
// link (the new email won't match what the token "intends").
type EmailVerifyHandler struct {
	rdb        *redis.Client
	users      UserQuerier
	logger     *zap.Logger
	publicURL  string // PortalURL — used to build the click-back link.
	mailer     *mailer.Mailer
	defaultTID int64
	// devFallback gates the dev_link response field + link Info log on
	// non-release mode. In release the verification link is never returned
	// in the HTTP body and never logged.
	devFallback bool
}

// SetDevFallback toggles the non-release dev_link exposure. Kept as a setter
// so the positional constructor signature stays stable.
func (h *EmailVerifyHandler) SetDevFallback(on bool) { h.devFallback = on }

// NewEmailVerifyHandler builds the email-verification handler. Exported
// so main.go can mount it on the console route group too.
func NewEmailVerifyHandler(
	rdb *redis.Client, users UserQuerier, logger *zap.Logger,
	publicURL string, mailerSvc *mailer.Mailer, defaultTID int64,
) *EmailVerifyHandler {
	return &EmailVerifyHandler{
		rdb:        rdb,
		users:      users,
		logger:     logger,
		publicURL:  publicURL,
		mailer:     mailerSvc,
		defaultTID: defaultTID,
	}
}

// RegisterEmailVerifyRoutes mounts the send + click-back routes on rg.
func RegisterEmailVerifyRoutes(rg *gin.RouterGroup, h *EmailVerifyHandler) {
	rg.POST("/profile/email/send-verification", h.sendVerification)
	rg.GET("/profile/email/verify", h.verify)
}

func registerEmailVerifyRoutes(rg *gin.RouterGroup, h *EmailVerifyHandler) {
	RegisterEmailVerifyRoutes(rg, h)
}

func (h *EmailVerifyHandler) sendVerification(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	email, err := h.users.GetEmail(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to read user", err)
		return
	}
	if email == "" {
		response.BadRequest(c, 40001, "email not set — set an email before requesting verification")
		return
	}

	token, err := generateToken()
	if err != nil {
		response.InternalError(c, "failed to generate token", err)
		return
	}
	// Bind the token to (userID, email) — NOT userID alone. On verify we require
	// the user's CURRENT email to still equal this one, so changing the email
	// after requesting verification invalidates the in-flight link (otherwise the
	// click would flip email_verified on the NEW, unverified address).
	if err := h.rdb.Set(c.Request.Context(), verifyKeyPrefix+token, fmt.Sprintf("%d:%s", userID, email), emailVerifyTTL*1e9).Err(); err != nil {
		response.InternalError(c, "failed to persist token", err)
		return
	}

	link := fmt.Sprintf("%s/profile/email/verify?token=%s", h.publicURL, token)
	tenantID := tenantctx.FromContext(c, h.defaultTID)

	// Try real SMTP first. If it errors (or SMTP not enabled), fall back
	// to logging + returning `dev_link` so dev / first-deploy admins can
	// still click through. Distinguishes the two cases in the response.
	devLink := ""
	smtpOK := false
	if h.mailer != nil {
		// Fetch display name for template variables.
		var displayName, username string
		if u, err := h.users.GetByID(c.Request.Context(), userID); err == nil {
			displayName = u.DisplayName
			username = u.Username
		}
		if err := h.mailer.SendVerifyEmail(c.Request.Context(), tenantID, email, displayName, username, link); err == nil {
			smtpOK = true
		} else {
			h.logger.Warn("smtp send failed, falling back to dev_link",
				zap.Error(err), zap.String("email", email))
			if h.devFallback {
				devLink = link
			}
		}
	} else if h.devFallback {
		devLink = link
	}

	if !smtpOK {
		if h.devFallback {
			h.logger.Info("email verification link (no SMTP / fallback)",
				zap.Int64("user_id", userID),
				zap.String("email", email),
				zap.String("link", link),
				zap.Int("ttl_seconds", emailVerifyTTL),
			)
		} else {
			// Release mode: never leak the verification link into the
			// response body or logs.
			h.logger.Warn("email verification send failed (no dev fallback in release)",
				zap.Int64("user_id", userID))
		}
	}

	response.OK(c, gin.H{
		"sent":        true,
		"smtp":        smtpOK,
		"email":       email,
		"ttl_seconds": emailVerifyTTL,
		// dev_link populated only when SMTP unavailable — UI hides it when
		// SMTP send succeeded so users don't see the raw token URL.
		"dev_link": devLink,
	})
}

func (h *EmailVerifyHandler) verify(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		response.BadRequest(c, 40001, "token required")
		return
	}

	userID, tokenEmail, err := h.consumeToken(c.Request.Context(), token)
	if err != nil {
		response.BadRequest(c, 40002, err.Error())
		return
	}

	// The link is only valid for the email it was issued for. If the user
	// changed their email in the meantime, the current address is different +
	// unverified — refuse rather than mark the new address verified.
	curEmail, err := h.users.GetEmail(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to read user", err)
		return
	}
	if curEmail == "" || !strings.EqualFold(curEmail, tokenEmail) {
		response.BadRequest(c, 40002, "verification link no longer matches your email")
		return
	}

	if err := h.users.MarkEmailVerified(c.Request.Context(), userID); err != nil {
		response.InternalError(c, "failed to mark verified", err)
		return
	}

	// Redirect to portal profile so user sees the success state instead of
	// a bare JSON response. Falls back to a JSON 200 if the portal URL is
	// missing (shouldn't happen in practice).
	if h.publicURL != "" {
		c.Redirect(http.StatusFound, h.publicURL+"/profile?email_verified=1")
		return
	}
	response.OK(c, gin.H{"verified": true})
}

func (h *EmailVerifyHandler) consumeToken(ctx context.Context, token string) (int64, string, error) {
	key := verifyKeyPrefix + token
	val, err := h.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, "", errors.New("token invalid or expired")
		}
		return 0, "", fmt.Errorf("read token: %w", err)
	}
	// Delete immediately — one-shot. Even if MarkEmailVerified errors below,
	// the user can request a new link; better than leaving a reusable token.
	_ = h.rdb.Del(ctx, key).Err()
	// Value is "<userID>:<email>"; split on the first colon (emails have no ':').
	uidStr, email, ok := strings.Cut(val, ":")
	if !ok {
		return 0, "", errors.New("token invalid or expired")
	}
	uid, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil {
		return 0, "", errors.New("token invalid or expired")
	}
	return uid, email, nil
}

// generateToken returns a 32-byte hex random string (64 chars). Long
// enough to resist brute-force given the 30-min TTL + Redis-only storage.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
