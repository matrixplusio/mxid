package portal

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/ginutil"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
)

// ChangePasswordRequest is the request body for password change.
// TOTPCode is required when the user has TOTP enrolled (step-up auth) —
// a stolen session cookie alone cannot rotate the password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
	TOTPCode    string `json:"totp_code"`
}

// VerifyTOTPRequest is the request body for TOTP verification.
type VerifyTOTPRequest struct {
	Code string `json:"code" binding:"required"`
}

// SecurityHandler serves /security endpoints. Reused by both portal and
// console route groups — namespace is what decides which session set the
// /sessions list/delete operates on, while change-password kills sessions
// in BOTH namespaces (OWASP recommendation: invalidate the user globally
// when their credential rotates).
type SecurityHandler struct {
	namespace       string
	userQuerier     UserQuerier
	sessionQuerier  SessionQuerier
	mfaQuerier      MFAQuerier
	identityQuerier IdentityQuerier
	historyQuerier  LoginHistoryQuerier
	apiTokenQuerier APITokenQuerier
	tenantID        int64
	mfaRateLimiter  *authn.MFARateLimiter
	bus             *event.Bus
}

// NewSecurityHandler is exported so cmd/server can build a second copy
// for the console route group without copying the per-endpoint code.
func NewSecurityHandler(
	namespace string,
	user UserQuerier, sess SessionQuerier, mfa MFAQuerier, id IdentityQuerier,
	history LoginHistoryQuerier, apiTokens APITokenQuerier, tenantID int64,
	mfaRateLimiter *authn.MFARateLimiter, bus *event.Bus,
) *SecurityHandler {
	return &SecurityHandler{
		namespace:       namespace,
		userQuerier:     user,
		sessionQuerier:  sess,
		mfaQuerier:      mfa,
		identityQuerier: id,
		historyQuerier:  history,
		apiTokenQuerier: apiTokens,
		tenantID:        tenantID,
		mfaRateLimiter:  mfaRateLimiter,
		bus:             bus,
	}
}

// publish emits a domain event for the audit trail. Best-effort: a nil bus
// (tests) is a no-op. Actor / IP are denormalized downstream from the
// request-scoped auditctx, so the payload only carries event-specific fields.
func (h *SecurityHandler) publish(c *gin.Context, eventType string, payload map[string]any) {
	if h.bus == nil {
		return
	}
	h.bus.Publish(c.Request.Context(), event.Event{Type: eventType, Payload: payload})
}

// RegisterSecurityRoutes mounts the /security sub-tree onto `rg` — caller
// supplies the route group (portal OR console) and the handler whose
// namespace matches.
func RegisterSecurityRoutes(rg *gin.RouterGroup, h *SecurityHandler) {
	sec := rg.Group("/security")
	{
		sec.PUT("/password", h.changePassword)

		sec.GET("/mfa", h.listMFA)
		sec.POST("/mfa/totp/setup", h.setupTOTP)
		sec.POST("/mfa/totp/verify", h.verifyTOTP)
		sec.DELETE("/mfa/totp", h.deleteTOTP)

		sec.GET("/identities", h.listIdentities)

		sec.GET("/sessions", h.listSessions)
		sec.DELETE("/sessions/:sid", h.deleteSession)

		sec.GET("/login-history", h.listLoginHistory)

		// Backup codes — GET returns just the remaining count, POST
		// generates a fresh set and returns plaintext (one-shot display).
		sec.GET("/mfa/backup-codes", h.countBackupCodes)
		sec.POST("/mfa/backup-codes", h.regenerateBackupCodes)

		// Personal Access Tokens.
		sec.GET("/api-tokens", h.listAPITokens)
		sec.POST("/api-tokens", h.createAPIToken)
		sec.DELETE("/api-tokens/:id", h.revokeAPIToken)
	}
}

// CreateAPITokenRequest is the create payload. Scopes are advisory unless
// the bearer middleware enforces them on a route.
type CreateAPITokenRequest struct {
	Name          string   `json:"name" binding:"required,max=128"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expires_in_days" binding:"omitempty,min=0,max=730"`
}

func (h *SecurityHandler) listAPITokens(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	if h.apiTokenQuerier == nil {
		response.OK(c, []any{})
		return
	}
	items, err := h.apiTokenQuerier.List(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to list tokens", err)
		return
	}
	response.OK(c, items)
}

func (h *SecurityHandler) createAPIToken(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	if h.apiTokenQuerier == nil {
		response.InternalError(c, "api tokens not configured")
		return
	}
	var req CreateAPITokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}
	tid, _ := authn.GetTenantID(c)
	if tid == 0 {
		tid = h.tenantID
	}
	info, err := h.apiTokenQuerier.Create(c.Request.Context(), userID, tid, req.Name, req.Scopes, req.ExpiresInDays)
	if err != nil {
		response.InternalError(c, "failed to create token", err)
		return
	}
	h.publish(c, event.APITokenCreated, map[string]any{
		"user_id": userID, "tenant_id": tid, "name": req.Name, "scopes": req.Scopes,
	})
	response.OK(c, info)
}

func (h *SecurityHandler) revokeAPIToken(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	if h.apiTokenQuerier == nil {
		response.InternalError(c, "api tokens not configured")
		return
	}
	tokenID, ok := ginutil.ParseInt64Param(c, "id")
	if !ok {
		return
	}
	if err := h.apiTokenQuerier.Revoke(c.Request.Context(), userID, tokenID); err != nil {
		response.MapError(c, err)
		return
	}
	h.publish(c, event.APITokenRevoked, map[string]any{
		"id": tokenID, "user_id": userID, "tenant_id": h.tenantID, "token_id": tokenID,
	})
	response.OK(c, gin.H{"revoked": true})
}

// countBackupCodes returns the user's remaining active code count + a hint
// that they should regenerate when low. UI uses this to show the warning
// "only N codes left".
func (h *SecurityHandler) countBackupCodes(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	n, err := h.mfaQuerier.CountBackupCodes(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to count backup codes", err)
		return
	}
	response.OK(c, gin.H{"remaining": n})
}

// hasVerifiedTOTP checks the MFA list for an active TOTP factor.
func hasVerifiedTOTP(items []*MFAInfo) bool {
	for _, m := range items {
		if m.Type == "totp" && m.Verified {
			return true
		}
	}
	return false
}

// regenerateBackupCodes wipes any existing codes and mints 10 fresh ones.
// The plaintext is returned ONCE — callers must surface them immediately
// to the user; server-side only bcrypt hashes persist.
//
// Step-up not enforced here in this PR: the user already passed both the
// password challenge (got the session) and TOTP (verified=true is the
// gate for backup-codes mattering). Adding a fresh TOTP re-prompt is a
// reasonable hardening for a follow-up PR.
// RegenerateBackupCodesRequest carries the step-up TOTP code. Regenerate
// is high-impact (invalidates all old codes) so we require a fresh proof
// of possession even though the caller already has a valid session.
type RegenerateBackupCodesRequest struct {
	TOTPCode string `json:"totp_code"`
}

func (h *SecurityHandler) regenerateBackupCodes(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	// Read step-up code; binding optional so unenrolled paths still 200
	// (no TOTP yet → no challenge needed; the verify check below short-
	// circuits in that case).
	var req RegenerateBackupCodesRequest
	_ = c.ShouldBindJSON(&req)

	mfas, err := h.mfaQuerier.ListMFA(c.Request.Context(), userID)
	if err == nil && hasVerifiedTOTP(mfas) {
		ip := c.ClientIP()
		if err := h.mfaRateLimiter.Check(c.Request.Context(), userID, ip); err != nil {
			var rle *authn.MFARateLimitError
			if errors.As(err, &rle) {
				c.Header("Retry-After", strconv.Itoa(int(rle.RetryAfter.Seconds())))
			}
			response.Error(c, 429, 42901, "mfa rate limited", err.Error())
			return
		}
		if req.TOTPCode == "" {
			response.BadRequest(c, 40005, "totp code required")
			return
		}
		if err := h.mfaQuerier.VerifyTOTP(c.Request.Context(), userID, req.TOTPCode); err != nil {
			h.mfaRateLimiter.RecordFailure(c.Request.Context(), userID, ip)
			response.BadRequest(c, 40006, "invalid totp code")
			return
		}
		h.mfaRateLimiter.Reset(c.Request.Context(), userID, ip)
	}

	codes, err := h.mfaQuerier.GenerateBackupCodes(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to generate backup codes", err)
		return
	}
	response.OK(c, gin.H{"codes": codes})
}

// listLoginHistory returns the recent login/logout/MFA-fail events for
// the requesting user. Default limit 50, max 200 (protect audit_log).
func (h *SecurityHandler) listLoginHistory(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}
	if h.historyQuerier == nil {
		response.OK(c, []any{})
		return
	}
	limit := 50
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 200 {
		limit = 200
	}
	tid, _ := authn.GetTenantID(c)
	if tid == 0 {
		tid = h.tenantID
	}
	items, err := h.historyQuerier.ListLoginHistory(c.Request.Context(), tid, userID, limit)
	if err != nil {
		response.InternalError(c, "failed to load login history", err)
		return
	}
	response.OK(c, items)
}

// changePassword handles password change.
func (h *SecurityHandler) changePassword(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	// Step-up: if TOTP is enrolled, require a fresh code. Old-password
	// alone is not enough because session-hijack attackers may already
	// have it (keylogger). TOTP code shares the rate limiter to prevent
	// brute force.
	if h.mfaQuerier != nil {
		mfas, err := h.mfaQuerier.ListMFA(c.Request.Context(), userID)
		if err == nil && hasVerifiedTOTP(mfas) {
			ip := c.ClientIP()
			if err := h.mfaRateLimiter.Check(c.Request.Context(), userID, ip); err != nil {
				var rle *authn.MFARateLimitError
				if errors.As(err, &rle) {
					c.Header("Retry-After", strconv.Itoa(int(rle.RetryAfter.Seconds())))
				}
				response.Error(c, 429, 42901, "mfa rate limited", err.Error())
				return
			}
			if req.TOTPCode == "" {
				response.BadRequest(c, 40005, "totp code required")
				return
			}
			if err := h.mfaQuerier.VerifyTOTP(c.Request.Context(), userID, req.TOTPCode); err != nil {
				h.mfaRateLimiter.RecordFailure(c.Request.Context(), userID, ip)
				response.BadRequest(c, 40006, "invalid totp code")
				return
			}
			h.mfaRateLimiter.Reset(c.Request.Context(), userID, ip)
		}
	}

	if err := h.userQuerier.ChangePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		// Route through the user domain's bound sentinels (wrong old password,
		// weak/reused new password, etc.) instead of blindly echoing err.Error()
		// — a wrapped DB failure otherwise leaks its text under a bogus 400.
		response.MapError(c, err)
		return
	}

	// Credential rotated — invalidate every active session belonging to
	// this user in BOTH portal and console namespaces. The CURRENT session
	// is the one exception (otherwise the success response races a 401 from
	// the same request's middleware on a re-fetch). Caller's SPA still
	// needs to re-login on its next page transition because the session
	// cookie is one-shot in the surviving namespace and absent in the other.
	currentSID, _ := authn.GetSessionID(c)
	for _, ns := range []string{session.NamespacePortal, session.NamespaceConsole} {
		_ = h.sessionQuerier.DeleteAllByUserExcept(c.Request.Context(), ns, userID, currentSID)
	}

	response.OK(c, nil)
}

// listMFA returns the user's enrolled MFA methods.
func (h *SecurityHandler) listMFA(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	items, err := h.mfaQuerier.ListMFA(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to list mfa", err)
		return
	}

	response.OK(c, items)
}

// setupTOTP initiates TOTP enrollment.
func (h *SecurityHandler) setupTOTP(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	secret, qrURL, err := h.mfaQuerier.SetupTOTP(c.Request.Context(), userID)
	if err != nil {
		response.MapError(c, err)
		return
	}

	response.OK(c, gin.H{
		"secret": secret,
		"qr_url": qrURL,
	})
}

// verifyTOTP verifies a TOTP code to complete enrollment. Shares the
// brute-force counter with the login-flow MFA challenge so an attacker
// who already has a session can't grind codes here either.
func (h *SecurityHandler) verifyTOTP(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	var req VerifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, 40001, "invalid request body")
		return
	}

	ip := c.ClientIP()
	if err := h.mfaRateLimiter.Check(c.Request.Context(), userID, ip); err != nil {
		var rle *authn.MFARateLimitError
		if errors.As(err, &rle) {
			c.Header("Retry-After", strconv.Itoa(int(rle.RetryAfter.Seconds())))
		}
		response.Error(c, 429, 42901, "mfa rate limited", err.Error())
		return
	}

	if err := h.mfaQuerier.VerifyTOTP(c.Request.Context(), userID, req.Code); err != nil {
		h.mfaRateLimiter.RecordFailure(c.Request.Context(), userID, ip)
		if errors.Is(err, user.ErrMFACodeReused) {
			// Common right after scanning: the same code was just used to finish a
			// previous step. Tell the user to wait for the next one instead of the
			// misleading "invalid code".
			response.BadRequest(c, 40003, "totp code already used, wait for the next one")
			return
		}
		response.BadRequest(c, 40002, "invalid totp code")
		return
	}
	h.mfaRateLimiter.Reset(c.Request.Context(), userID, ip)

	// This verify already proved TOTP possession — treat it as a fresh step-up so
	// a high-risk op right after enrolling doesn't demand another code (which
	// would reuse this same TOTP window and get rejected as a replay). Best-effort.
	if sid, ok := authn.GetSessionID(c); ok {
		_ = h.sessionQuerier.MarkStepUpFresh(c.Request.Context(), h.namespace, sid)
	}

	h.publish(c, event.MFAEnabled, map[string]any{
		"user_id": userID, "tenant_id": h.tenantID, "type": "totp",
	})

	response.OK(c, nil)
}

// deleteTOTP removes TOTP enrollment.
func (h *SecurityHandler) deleteTOTP(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	if err := h.mfaQuerier.DeleteTOTP(c.Request.Context(), userID); err != nil {
		response.InternalError(c, "failed to delete totp", err)
		return
	}

	h.publish(c, event.MFADisabled, map[string]any{
		"user_id": userID, "tenant_id": h.tenantID, "type": "totp",
	})

	response.OK(c, nil)
}

// listIdentities returns the user's linked identity providers.
func (h *SecurityHandler) listIdentities(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	items, err := h.identityQuerier.ListIdentities(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "failed to list identities", err)
		return
	}

	response.OK(c, items)
}

// listSessions returns the user's active sessions.
func (h *SecurityHandler) listSessions(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	items, err := h.sessionQuerier.ListSessions(c.Request.Context(), h.namespace, userID)
	if err != nil {
		response.InternalError(c, "failed to list sessions", err)
		return
	}

	response.OK(c, items)
}

// deleteSession revokes a specific session.
func (h *SecurityHandler) deleteSession(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	sid := c.Param("sid")
	if sid == "" {
		response.BadRequest(c, 40001, "missing session id")
		return
	}

	if err := h.sessionQuerier.DeleteSession(c.Request.Context(), h.namespace, sid, userID); err != nil {
		response.InternalError(c, "failed to delete session", err)
		return
	}

	h.publish(c, event.SessionKicked, map[string]any{
		"user_id": userID, "session_id": sid, "tenant_id": h.tenantID,
	})

	response.OK(c, nil)
}
