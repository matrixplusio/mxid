package oidcop

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// ConsentChecker reports whether a user has already granted a client all the
// requested scopes. Implemented by the consent domain service.
type ConsentChecker interface {
	HasAll(ctx context.Context, tenantID, userID, appID int64, scopes []string) (bool, error)
}

// LoginBridge connects op's AuthRequest lifecycle to MXID's BFF portal login +
// consent. op redirects an unauthenticated user to loginURL(authRequestID),
// which points at Handle below; once the user has a session (and consent),
// Handle marks the request done and bounces to op's callback to issue the code.
//
// Reuses the portal SPA's existing `return_to` convention for both login and
// consent, so NO portal frontend change is required.
type LoginBridge struct {
	storage     *Storage
	apps        resolver.AppResolver
	sessions    resolver.SessionResolver
	consent     ConsentChecker
	callbackURL func(context.Context, string) string
	loginURL    func(authRequestID string) string
	portalURL   string
}

// NewLoginBridge wires a LoginBridge. loginURL must build the external URL of
// Handle for a given authRequestID (same builder op uses as the client LoginURL),
// since it doubles as the post-login/consent return_to target.
func NewLoginBridge(
	storage *Storage,
	apps resolver.AppResolver,
	sessions resolver.SessionResolver,
	consent ConsentChecker,
	callbackURL func(context.Context, string) string,
	loginURL func(string) string,
	portalURL string,
) *LoginBridge {
	return &LoginBridge{
		storage:     storage,
		apps:        apps,
		sessions:    sessions,
		consent:     consent,
		callbackURL: callbackURL,
		loginURL:    loginURL,
		portalURL:   portalURL,
	}
}

// Handle is the GET endpoint op redirects to: /protocol/oidc/login?authRequestID=…
func (b *LoginBridge) Handle(c *gin.Context) {
	authReqID := c.Query("authRequestID")
	if authReqID == "" {
		authReqID = c.Query("id")
	}
	if authReqID == "" {
		c.String(http.StatusBadRequest, "missing authRequestID")
		return
	}

	ctx := c.Request.Context()
	ar, err := b.storage.AuthRequestByID(ctx, authReqID)
	if err != nil {
		c.String(http.StatusBadRequest, "unknown or expired auth request")
		return
	}

	// Resolve the SSO session from the protocol cookie, falling back to the
	// portal cookie (IdP-initiated / already-logged-in portal users).
	sess := b.resolveSession(ctx, c)
	if sess == nil {
		// Not logged in → portal login, returning here afterwards.
		b.redirect(c, b.portalURL+"/login?return_to="+url.QueryEscape(b.loginURL(authReqID)))
		return
	}

	app, err := b.apps.GetAppByClientID(ctx, ar.GetClientID())
	if err != nil || app == nil {
		c.String(http.StatusBadRequest, "unknown client")
		return
	}

	// Consent (OIDC Core §3.1.2.4): required when the app demands it or is a
	// third-party client. First-party apps with require_consent=false skip it.
	if b.consent != nil && (app.RequireConsent || !app.IsFirstParty()) {
		ok, err := b.consent.HasAll(ctx, sess.TenantID, sess.UserID, app.ID, ar.GetScopes())
		if err != nil {
			c.String(http.StatusInternalServerError, "consent check failed")
			return
		}
		if !ok {
			scope := joinScopes(ar.GetScopes())
			b.redirect(c, b.portalURL+"/consent?app_id="+itoa(app.ID)+
				"&scope="+url.QueryEscape(scope)+
				"&return_to="+url.QueryEscape(b.loginURL(authReqID)))
			return
		}
	}

	// Authenticated + consented → mark done and hand back to op for the code.
	amr := []string{"pwd"}
	if sess.AuthType == "mfa" {
		amr = append(amr, "mfa")
	}
	if err := b.storage.AuthRequestDone(ctx, authReqID, itoa(sess.UserID), time.Now(), amr); err != nil {
		c.String(http.StatusBadRequest, "unknown or expired auth request")
		return
	}
	b.redirect(c, b.callbackURL(ctx, authReqID))
}

func (b *LoginBridge) resolveSession(ctx context.Context, c *gin.Context) *resolver.SSOSession {
	for _, name := range []string{"mxid_proto_sid", "mxid_portal_sid"} {
		if sid, err := c.Cookie(name); err == nil && sid != "" {
			if sess, err := b.sessions.GetSSOSession(ctx, sid); err == nil && sess != nil {
				return sess
			}
		}
	}
	return nil
}

func (b *LoginBridge) redirect(c *gin.Context, to string) {
	c.Redirect(http.StatusFound, to)
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }
func itoa(i int64) string               { return strconv.FormatInt(i, 10) }
