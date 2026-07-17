package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSRFConfig configures the CSRF protection middleware.
//
// Strategy: Origin/Referer header validation against an allow-list of trusted
// front-end origins. Combined with SameSite=Lax cookies (set by the auth
// handler) this blocks the classic CSRF attack pattern where a malicious page
// posts a form to MXID using the victim's session cookie.
//
// We do NOT issue synchronizer tokens — Origin/SameSite cover the OWASP
// recommended baseline (https://owasp.org/www-community/attacks/csrf) and
// avoid a stateful token store. High-risk admin operations should layer
// re-auth on top, not extra tokens.
//
// Endpoints that legitimately receive cross-origin POSTs (SSO protocol
// callbacks under /protocol/*, bearer-auth API token endpoints under
// /openapi/*) MUST be mounted on route groups WITHOUT this middleware.
type CSRFConfig struct {
	// TrustedOrigins is the scheme://host[:port] list permitted to issue
	// state-changing requests. Wildcards are NOT allowed.
	TrustedOrigins []string
	// SkipPaths lists exact request paths to bypass the check (e.g. health
	// probes). Path prefix match.
	SkipPaths []string
	// AllowBearerAuth lets requests with an Authorization: Bearer header
	// pass the check unconditionally. Used for API-token requests that
	// share a router but do not rely on cookies.
	AllowBearerAuth bool
	// SkipWithHeader names a custom request header whose mere presence bypasses
	// the Origin check. A custom header cannot be set on a cross-site request
	// without a CORS preflight the server controls (the classic "custom request
	// header" CSRF defense, OWASP-recommended). The browser extension carries the
	// form-fill binding token in such a header; its host_permissions let it reach
	// the API without a trusted SPA Origin, so the header — not Origin — is what
	// proves the request came from a cooperating client. Empty = disabled.
	SkipWithHeader string
}

// CSRF returns a middleware enforcing Origin / Referer matching for unsafe
// methods. Safe methods (GET, HEAD, OPTIONS) are passed through.
//
// Failure modes:
//   - missing Origin AND Referer  → 403 (cannot prove same-site intent)
//   - Origin/Referer not in allow → 403
//
// Same-origin requests issued by SPAs always carry Origin (per Fetch spec
// §3.2.7) so this middleware does not break ordinary calls. cURL / Postman
// users hitting cookie-auth endpoints must explicitly set -H "Origin: ...".
func CSRF(cfg CSRFConfig) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(cfg.TrustedOrigins))
	for _, o := range cfg.TrustedOrigins {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o != "" {
			allowed[o] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		for _, p := range cfg.SkipPaths {
			if strings.HasPrefix(c.Request.URL.Path, p) {
				c.Next()
				return
			}
		}

		if cfg.SkipWithHeader != "" && c.GetHeader(cfg.SkipWithHeader) != "" {
			c.Next()
			return
		}

		if cfg.AllowBearerAuth {
			if strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
				c.Next()
				return
			}
		}

		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = refererOrigin(c.GetHeader("Referer"))
		}
		if origin == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    40310,
				"message": "csrf: missing Origin or Referer",
			})
			return
		}

		if _, ok := allowed[strings.TrimRight(origin, "/")]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    40311,
				"message": "csrf: origin not allowed",
			})
			return
		}

		c.Next()
	}
}

// refererOrigin extracts the scheme://host[:port] prefix from a Referer
// header value. Returns empty string when the value is missing or malformed.
func refererOrigin(referer string) string {
	if referer == "" {
		return ""
	}
	idx := strings.Index(referer, "://")
	if idx < 0 {
		return ""
	}
	rest := referer[idx+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		return referer
	}
	return referer[:idx+3+end]
}
