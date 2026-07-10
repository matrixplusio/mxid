// Package oidclogout implements engine-independent OIDC back-channel logout
// fan-out (https://openid.net/specs/openid-connect-backchannel-1_0.html).
// It is consumed by both the zitadel engine (internal/protocol/oidcop) and,
// eventually, replaces the equivalent hand-rolled logic in
// internal/protocol/oidc so offboarding and JIT downstream teardown work
// under either engine.
package oidclogout

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/session"
)

// fanOutTimeout bounds the detached background fan-out so a slow/unreachable
// RP never leaks a goroutine indefinitely. Mirrors the retiring hand-rolled
// engine's 30s budget (internal/protocol/oidc/handler.go).
const fanOutTimeout = 30 * time.Second

// Doer is the minimal HTTP interface the Service needs to POST a
// logout_token. Production wiring passes a *pkg/safehttp.Client (SSRF
// guarded); tests inject a plain *http.Client so loopback httptest servers
// are reachable (the safehttp guard intentionally blocks internal addresses).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// oidcProtocolConfig is the subset of the app's protocol_config JSONB this
// package reads. Deliberately NOT internal/protocol/oidc.OIDCConfig — that
// package is engine-specific and slated for deletion (WS9); the JSON field
// names are the stable, shared DB contract between engines.
type oidcProtocolConfig struct {
	BackchannelLogoutURI             string `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required"`
}

// Service fans out signed logout_tokens to every OIDC RP participating in a
// user's protocol SSO session(s). Engine independent: it depends only on
// session.Manager, the participation Index, resolver.AppResolver, and a
// Signer — none of which are tied to a specific OIDC provider implementation.
type Service struct {
	sessions *session.Manager
	index    *Index
	apps     resolver.AppResolver
	signer   Signer
	issuer   string // full issuer incl. /protocol/oidc, used as logout_token `iss`
	http     Doer
	// identity + tenants resolve the logout_token `sub` through the app's
	// subject_strategy, so it matches the `sub` the RP received in the id_token.
	// Both optional (nil-safe): a nil identity resolver falls back to the raw
	// user id, preserving the previous behaviour for callers that don't wire them.
	identity resolver.IdentityResolver
	tenants  resolver.TenantResolver
	// resolveIssuer maps a ctx to the runtime OIDC issuer override, or "" to use
	// the static issuer. Wired from the SAME source as the op provider's dynamic
	// issuer so the logout_token `iss` can never disagree with the id_token `iss`
	// under an admin external-URL override. Optional (nil → always static).
	resolveIssuer func(context.Context) string
}

// NewService wires a Service. issuer must be the same value emitted as the
// id_token `iss` (i.e. the zitadel engine's opIssuer, host + /protocol/oidc)
// so RPs validating the logout_token see a consistent issuer. identity +
// tenants are used to resolve `sub` via the app's subject_strategy; pass nil to
// fall back to the raw user id.
func NewService(sessions *session.Manager, index *Index, apps resolver.AppResolver, signer Signer, issuer string, httpClient Doer, identity resolver.IdentityResolver, tenants resolver.TenantResolver, resolveIssuer func(context.Context) string) *Service {
	return &Service{
		sessions:      sessions,
		index:         index,
		apps:          apps,
		signer:        signer,
		issuer:        issuer,
		http:          httpClient,
		identity:      identity,
		tenants:       tenants,
		resolveIssuer: resolveIssuer,
	}
}

// issuerFor returns the logout_token `iss`: the runtime override when set, else
// the static boot issuer. Kept identical to the op provider's issuer resolution
// so an RP validating the logout_token sees the same `iss` it saw in the
// id_token.
func (s *Service) issuerFor(ctx context.Context) string {
	if s.resolveIssuer != nil {
		if iss := s.resolveIssuer(ctx); iss != "" {
			return iss
		}
	}
	return s.issuer
}

// LogoutUser fans out a back-channel logout to every RP the user has an
// active protocol SSO session with — used by offboarding to proactively drop
// the departing user's session inside each participating app.
//
// Must be called BEFORE the user's protocol sessions are killed: the per-RP
// app sets are keyed by SSO session id, which is derived from the user's live
// protocol sessions. The collection (session + participation reads) runs
// synchronously so it sees the data before the kill; the actual logout_token
// POSTs are dispatched on a detached goroutine so a slow RP never blocks the
// caller. Best-effort — apps that don't implement back-channel logout, or
// that can't be reached, fall through to failing closed on their next token
// validation.
//
// DESTRUCTIVE read of the participation index (Index.List): safe here because
// the session itself is being torn down, so the tracking set does not need to
// survive.
func (s *Service) LogoutUser(ctx context.Context, userID int64) {
	protoSessions, err := s.sessions.ListByUser(ctx, session.NamespaceProtocol, userID)
	if err != nil || len(protoSessions) == 0 {
		return
	}

	type target struct {
		sid    string
		appIDs []int64
	}
	var targets []target
	for _, sess := range protoSessions {
		appIDs, _ := s.index.List(ctx, sess.ID)
		if len(appIDs) > 0 {
			targets = append(targets, target{sid: sess.ID, appIDs: appIDs})
		}
	}
	if len(targets) == 0 {
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), fanOutTimeout)
		defer cancel()
		for _, t := range targets {
			for _, appID := range t.appIDs {
				s.sendLogout(bgCtx, appID, userID, t.sid)
			}
		}
	}()
}

// LogoutUserApp sends a back-channel logout_token only to the RP identified
// by appID, for every protocol SSO session of the user where that app
// participated. Used by JIT elevation expiry/revoke to drop an elevated role
// from one downstream app without logging the user out of their other apps.
//
// NON-DESTRUCTIVE read of the participation index (Index.Peek): the session's
// tracking set must remain intact so a subsequent full logout (LogoutUser)
// can still fan out to all other participating RPs. This is the invariant the
// JIT peek-not-destroy regression test guards.
//
// Best-effort + async, same 30s-budget detached goroutine as LogoutUser. Must
// be called BEFORE the user's protocol sessions are killed (same constraint
// as LogoutUser) so the participation index is still present.
func (s *Service) LogoutUserApp(ctx context.Context, userID, appID int64) {
	protoSessions, err := s.sessions.ListByUser(ctx, session.NamespaceProtocol, userID)
	if err != nil || len(protoSessions) == 0 {
		return
	}

	var sids []string
	for _, sess := range protoSessions {
		appIDs, _ := s.index.Peek(ctx, sess.ID)
		if slices.Contains(appIDs, appID) {
			sids = append(sids, sess.ID)
		}
	}
	if len(sids) == 0 {
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), fanOutTimeout)
		defer cancel()
		for _, sid := range sids {
			s.sendLogout(bgCtx, appID, userID, sid)
		}
	}()
}

// resolveSubject computes the logout_token `sub` for this app + user via the
// app's subject_strategy, so it equals the `sub` the RP received in the
// id_token (oidcop/claims.go resolveSubject). Falls back to the raw snowflake
// id when the resolvers are unwired or the lookup fails — back-channel logout
// is best-effort and must never be dropped purely on a subject-strategy miss.
func (s *Service) resolveSubject(ctx context.Context, app *resolver.AppConfig, userID int64) string {
	fallback := strconv.FormatInt(userID, 10)
	if s.identity == nil {
		return fallback
	}
	idn, err := s.identity.ResolveUser(ctx, userID)
	if err != nil || idn == nil {
		return fallback
	}
	tenantCode := ""
	if s.tenants != nil && idn.TenantID > 0 {
		tenantCode, _ = s.tenants.GetTenantCode(ctx, idn.TenantID)
	}
	out, err := resolver.ResolveSubject(ctx, app.SubjectStrategy, resolver.SubjectInput{
		UserID:     idn.ID,
		Username:   idn.Username,
		Email:      idn.Email,
		TenantID:   idn.TenantID,
		TenantCode: tenantCode,
		ClientID:   app.ClientID,
	})
	if err != nil || out == nil || out.Subject == "" {
		return fallback
	}
	return out.Subject
}

// sendLogout signs and POSTs a logout_token to a single RP. Silent no-op on
// any resolution/signing/delivery failure — this is a best-effort
// notification; the RP falls back to failing closed on its next token
// validation with MXID.
func (s *Service) sendLogout(ctx context.Context, appID, userID int64, sid string) {
	app, err := s.apps.GetAppByID(ctx, appID)
	if err != nil || app == nil || app.ClientID == "" {
		return
	}

	var cfg oidcProtocolConfig
	if len(app.ProtocolConfig) > 0 {
		_ = json.Unmarshal(app.ProtocolConfig, &cfg)
	}
	if cfg.BackchannelLogoutURI == "" {
		return
	}

	claims := LogoutTokenClaims{
		Issuer:   s.issuerFor(ctx),
		Audience: app.ClientID,
		Subject:  s.resolveSubject(ctx, app, userID),
	}
	if cfg.BackchannelLogoutSessionRequired && sid != "" {
		claims.SID = sid
	}

	signed, err := s.signer.SignLogoutToken(ctx, claims)
	if err != nil {
		return
	}

	form := url.Values{}
	form.Set("logout_token", signed)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BackchannelLogoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.http.Do(req)
	if err != nil {
		// Includes the SSRF-guard block case (backchannel_logout_uri resolving
		// to an internal/disallowed address, or a non-https scheme). Best-effort
		// notification; the caller ignores the error, but blocking here
		// prevents the signed logout_token from being POSTed to an internal
		// address.
		return
	}
	_ = resp.Body.Close()
}
