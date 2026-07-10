package oidcop

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// DynamicIssuer resolves the OIDC issuer for a request at runtime, e.g. from an
// admin-configured external-URL override (settings). It returns "" to fall back
// to the static boot issuer. Mirrors the per-request URL swap SAML/CAS already
// do via SetURLProvider, so id_token `iss` and discovery honour a runtime URL
// change without a restart. MUST be nil-safe on a nil request (op may probe it).
type DynamicIssuer func(r *http.Request) string

// NewProvider builds the zitadel OpenID Provider. issuer is the full external
// base (e.g. https://host/protocol/oidc); cryptoKey (32 bytes) encrypts op's
// internal state/cookies. The provider IS an http.Handler serving authorize/
// token/userinfo/keys/discovery/end_session.
//
// dynamicIssuer is optional: when non-nil, the issuer emitted for a request is
// dynamicIssuer(r) if it returns non-empty, else the static issuer. When nil,
// the issuer is always the static one (previous behaviour). The static issuer
// is still validated at construction either way, so a broken boot issuer fails
// loud at startup.
func NewProvider(issuer string, storage op.Storage, cryptoKey [32]byte, allowInsecure bool, dynamicIssuer DynamicIssuer) (op.OpenIDProvider, error) {
	config := &op.Config{
		CryptoKey:                cryptoKey,
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true, // PKCE S256
		AuthMethodPost:           true, // client_secret_post
		AuthMethodPrivateKeyJWT:  true, // private_key_jwt client auth
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedScopes: []string{
			"openid", "profile", "email", "phone", "address", "groups", "offline_access",
		},
		SupportedUILocales: []language.Tag{language.English, language.SimplifiedChinese},
		// WS2: back-channel logout (internal/protocol/oidclogout) is wired
		// for offboarding + JIT downstream teardown, so advertise it in
		// discovery per spec.
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
	}
	// Mirror the hand-rolled engine's endpoint paths so existing clients
	// (Grafana et al.) need no reconfiguration when switching engines — only
	// the issuer/iss value changes. op's own defaults differ (/oauth/token,
	// /keys, /end_session, /oauth/introspect).
	opts := []op.Option{
		op.WithCustomTokenEndpoint(op.NewEndpoint("token")),
		op.WithCustomKeysEndpoint(op.NewEndpoint("jwks")),
		op.WithCustomEndSessionEndpoint(op.NewEndpoint("end-session")),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint("introspect")),
	}
	if allowInsecure {
		// We terminate TLS at nginx; the internal issuer is http. Allow it.
		opts = append(opts, op.WithAllowInsecure())
	}
	return op.NewProvider(config, storage, issuerOption(issuer, dynamicIssuer), opts...)
}

// issuerOption returns op's static issuer provider when dynamicIssuer is nil,
// otherwise a provider that validates the static base at construction (so a
// broken boot issuer still fails loud) and, per request, prefers a non-empty
// dynamicIssuer(r) over the static value. Falls back to static on a nil request
// or an empty override — the issuer is NEVER empty.
func issuerOption(issuer string, dynamicIssuer DynamicIssuer) func(bool) (op.IssuerFromRequest, error) {
	if dynamicIssuer == nil {
		return op.StaticIssuer(issuer)
	}
	return func(allowInsecure bool) (op.IssuerFromRequest, error) {
		if err := op.ValidateIssuer(issuer, allowInsecure); err != nil {
			return nil, err
		}
		return func(r *http.Request) string {
			if r != nil {
				if iss := dynamicIssuer(r); iss != "" {
					return iss
				}
			}
			return issuer
		}, nil
	}
}

// CallbackURL returns the builder for the authorize-callback URL op resumes at
// once the login bridge marks an auth request done (issuer/authorize/callback?id=).
func CallbackURL(provider op.OpenIDProvider) func(context.Context, string) string {
	return op.AuthCallbackURL(provider)
}

// Mount attaches the provider's handlers under group at the "/oidc/*" subtree.
// stripPrefix is the issuer path (e.g. /protocol/oidc) that must be stripped so
// op's root-relative routes (/authorize, /.well-known/...) match.
//
// filterDiscoveryResponse (WS6-B) is applied here, over the whole provider,
// so the implicit-flow values zitadel/oidc's discovery handler hardcodes
// (see discovery.go) never reach a client — without touching op's own
// routing or the hand-rolled engine's separate /protocol/oidc surface.
func Mount(group *gin.RouterGroup, stripPrefix string, provider http.Handler) {
	// withIdpInitiated runs OUTSIDE op so it can read the raw idp_initiated
	// query param before op's schema decoder discards it (IgnoreUnknownKeys) —
	// see withIdpInitiated. It stashes the flag on the request context, which
	// op propagates into Storage.CreateAuthRequest (pkg/op's Authorize derives
	// its ctx from r.Context()), where it is persisted onto the auth request.
	wrapped := gin.WrapH(http.StripPrefix(stripPrefix, withIdpInitiated(filterDiscoveryResponse(provider))))
	group.Any("/oidc/*any", wrapped)
}

// idpInitiatedCtxKey keys the idp_initiated flag on the request context.
type idpInitiatedCtxKey struct{}

// contextWithIdpInitiated returns ctx carrying the idp_initiated flag.
func contextWithIdpInitiated(ctx context.Context, v bool) context.Context {
	return context.WithValue(ctx, idpInitiatedCtxKey{}, v)
}

// idpInitiatedFromContext reports whether the request context was tagged as an
// IdP-initiated (portal app-list launch) authorize request.
func idpInitiatedFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(idpInitiatedCtxKey{}).(bool)
	return v
}

// withIdpInitiated reads the raw idp_initiated=1 query param off the incoming
// request (before op's schema decoder drops it as an unknown key) and stashes
// it on the request context so Storage.CreateAuthRequest can persist it onto
// the auth request. This is the only surviving path for the flag: op's
// oidc.AuthRequest has no field for it, and CreateAuthRequest gets no raw
// *http.Request. Query-string only — matches the hand-rolled engine, which
// reads c.Query("idp_initiated") (internal/protocol/oidc/handler.go:397).
func withIdpInitiated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("idp_initiated") == "1" {
			r = r.WithContext(contextWithIdpInitiated(r.Context(), true))
		}
		next.ServeHTTP(w, r)
	})
}
