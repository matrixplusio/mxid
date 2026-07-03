package authn

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/session"
)

// Step-up response codes. The console SPA keys off these to drive the MFA
// modal (step_up_required) or the enrollment redirect (mfa_enroll_required).
const (
	CodeStepUpRequired    = 40330 // high-risk op needs a fresh MFA; show the modal
	CodeMFAEnrollRequired = 40331 // policy requires MFA but user has none enrolled
)

const consolePathPrefix = "/api/v1/console/"

// highRiskWriteSuffixes are the non-DELETE console routes that mutate
// security-critical state and therefore require step-up. Matched against the
// gin route template (c.FullPath()) by suffix so they survive prefix changes.
var highRiskWriteSuffixes = []string{
	"/super-admin",                 // grant/revoke super admin
	"/password",                    // admin set another user's password (account takeover)
	"/rotate-signing-key",          // invalidate an app's SSO signing material
	"/regenerate-secret",           // reset an app's client secret
	"/mfa/lockout/clear",           // clear an MFA brute-force lockout
	"/access-requests/:id/approve", // JIT: approve a temporary privilege elevation
	"/access-requests/:id/revoke",  // JIT: revoke an active temporary grant
}

// IsHighRiskConsole reports whether a console request should be gated by
// step-up MFA. Rule: every console DELETE is high-risk (it destroys an asset —
// app, user, org, group, role binding, session, cert, membership), plus a
// curated set of security-critical writes. Non-console routes are never gated.
func IsHighRiskConsole(method, fullPath string) bool {
	if !strings.HasPrefix(fullPath, consolePathPrefix) {
		return false
	}
	if method == http.MethodDelete {
		return true
	}
	for _, suf := range highRiskWriteSuffixes {
		if strings.HasSuffix(fullPath, suf) {
			return true
		}
	}
	return false
}

// StepUpDeps are the runtime collaborators the step-up middleware needs. All
// are wired in main.go so the middleware stays decoupled from concrete
// settings / authz / MFA implementations.
type StepUpDeps struct {
	SessionMgr *session.Manager
	// Policy returns the MFA enforcement mode and the step-up grace window for
	// the tenant.
	Policy func(ctx context.Context, tenantID int64) (mode string, window time.Duration)
	// IsAdmin reports whether the user is a console-eligible admin (drives
	// admin_only mode).
	IsAdmin func(ctx context.Context, tenantID, userID int64) bool
	// HasMFA reports whether the user has an MFA factor enrolled.
	HasMFA func(ctx context.Context, userID int64) (bool, error)
	// Audit records the decision (optional). allowed=false means a challenge
	// or enrollment was demanded; reason is a short machine tag.
	Audit func(c *gin.Context, userID, tenantID int64, allowed bool, reason string)
}

// modeApplies reports whether the MFA mode requires THIS user to hold MFA.
func modeApplies(ctx context.Context, d StepUpDeps, mode string, tenantID, userID int64) bool {
	switch mode {
	case "all":
		return true
	case "admin_only":
		return d.IsAdmin != nil && d.IsAdmin(ctx, tenantID, userID)
	default: // off / unknown
		return false
	}
}

// StepUpMiddleware enforces step-up MFA on high-risk console operations.
//
// Decision table (only reached for high-risk routes):
//   - MFA mode off / not applicable to this user → allow (audit fallback).
//   - applicable but user has no MFA enrolled     → 403 mfa_enroll_required.
//   - applicable, MFA fresh within window         → allow.
//   - applicable, MFA stale/never                 → 403 step_up_required.
func StepUpMiddleware(d StepUpDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !IsHighRiskConsole(c.Request.Method, c.FullPath()) {
			c.Next()
			return
		}

		ctx := c.Request.Context()
		userID := c.GetInt64(CtxUserID)
		tenantID := c.GetInt64(CtxTenantID)
		sessionID := c.GetString(CtxSessionID)

		mode, window := d.Policy(ctx, tenantID)

		if !modeApplies(ctx, d, mode, tenantID, userID) {
			// MFA not enforced for this actor — audit covers the high-risk op.
			audit(d, c, userID, tenantID, true, "mfa_not_enforced")
			c.Next()
			return
		}

		enrolled, err := d.HasMFA(ctx, userID)
		if err != nil {
			response.InternalError(c, "mfa status check failed")
			c.Abort()
			return
		}
		if !enrolled {
			audit(d, c, userID, tenantID, false, "enroll_required")
			response.Forbidden(c, CodeMFAEnrollRequired, "mfa enrollment required for this operation")
			c.Abort()
			return
		}

		sess, _ := d.SessionMgr.Get(ctx, session.NamespaceConsole, sessionID)
		if sess != nil && sess.StepUpFresh(time.Now(), window) {
			audit(d, c, userID, tenantID, true, "step_up_fresh")
			c.Next()
			return
		}

		audit(d, c, userID, tenantID, false, "step_up_required")
		response.Forbidden(c, CodeStepUpRequired, "step-up mfa required for this operation")
		c.Abort()
	}
}

func audit(d StepUpDeps, c *gin.Context, userID, tenantID int64, allowed bool, reason string) {
	if d.Audit != nil {
		d.Audit(c, userID, tenantID, allowed, reason)
	}
}

// StepUpChecker exposes the same freshness/enrollment primitives
// StepUpMiddleware uses, for callers that must force a step-up challenge
// unconditionally (i.e. regardless of whether the tenant's ambient MFA
// policy mode would otherwise apply to this actor). The JIT access-approval
// flow is the motivating case: an eligibility marked require_stepup=true must
// demand a fresh MFA even when the global policy mode is "off".
//
// StepUpChecker has no dependency on any specific consumer package — Go's
// structural typing lets it satisfy a narrower interface declared elsewhere
// (e.g. access.StepUpEnforcer) without either package importing the other.
type StepUpChecker struct {
	deps StepUpDeps
}

// NewStepUpChecker builds a StepUpChecker from the same StepUpDeps used to
// construct StepUpMiddleware, so both mechanisms agree on session lookup,
// the step-up window, and MFA enrollment status.
func NewStepUpChecker(d StepUpDeps) *StepUpChecker {
	return &StepUpChecker{deps: d}
}

// Fresh reports whether the current console session (resolved from c exactly
// like StepUpMiddleware does — via CtxSessionID) passed MFA within the
// tenant's configured step-up window. The MFA policy *mode* is irrelevant
// here on purpose: only the window matters, because the caller is enforcing
// step-up unconditionally.
func (s *StepUpChecker) Fresh(c *gin.Context, tenantID int64) bool {
	ctx := c.Request.Context()
	sessionID := c.GetString(CtxSessionID)
	_, window := s.deps.Policy(ctx, tenantID)
	sess, _ := s.deps.SessionMgr.Get(ctx, session.NamespaceConsole, sessionID)
	return sess != nil && sess.StepUpFresh(time.Now(), window)
}

// HasMFA reports whether userID has any MFA factor enrolled.
func (s *StepUpChecker) HasMFA(ctx context.Context, userID int64) (bool, error) {
	return s.deps.HasMFA(ctx, userID)
}
