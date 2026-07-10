package app

// Wiring for the zitadel/oidc-based OIDC provider (engine=zitadel), the
// replacement for the hand-rolled internal/protocol/oidc. Kept out of main.go
// so the god-file wiring stays a single gated call.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/oidckey"
	"github.com/imkerbos/mxid/internal/protocol/oidclogout"
	"github.com/imkerbos/mxid/internal/protocol/oidcop"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/dlock"
	"github.com/imkerbos/mxid/pkg/safehttp"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/ssoflow"
)

// wireOIDCOP builds and mounts the zitadel OpenID Provider plus the BFF login
// bridge, and starts provider-keyset rotation. issuer is the full external base
// (e.g. https://host/protocol/oidc). Returns the WS2 back-channel logout fan-out
// service so run.go can wire it into offboarding + JIT downstream teardown.
func wireOIDCOP(
	workerCtx context.Context,
	a *bootstrap.App,
	issuer string,
	appResolver resolver.AppResolver,
	idResolver resolver.IdentityResolver,
	sessResolver resolver.SessionResolver,
	sessionMgr *session.Manager,
	access oidcop.AccessChecker,
	tenantResolver resolver.TenantResolver,
	appRoles oidcop.AppRoleResolver,
	issuerResolver func(context.Context) string,
) (*oidclogout.Service, error) {
	// Provider keyset + auto-rotation (90d default). EnsureActive mints the
	// first signing key on startup. Rotation runs under the leader lock so
	// only one replica drives it — without this, N pods could concurrently
	// rotate and disagree on which key is active (see migration 000053's
	// partial unique index, the last-resort DB guard against that).
	keySvc := oidckey.NewService(a.DB, a.IDGen, a.MasterKey)
	go dlock.RunAsLeader(workerCtx, a.DB, dlock.KeyOIDCRotation, a.Logger, func(ctx context.Context) {
		keySvc.RunRotation(ctx, oidckey.DefaultRotationEvery, func(err error) {
			a.Logger.Error("oidc keyset rotation", zap.Error(err))
		})
	})

	// The OIDC issuer is the discovery base, which per spec equals the path the
	// endpoints live under. The hand-rolled engine advertised issuer=host-root
	// (non-standard, issuer != endpoint base); op requires them aligned, so the
	// op issuer is host + /protocol/oidc. id_token `iss` becomes this value.
	opIssuer := strings.TrimSuffix(issuer, "/") + "/protocol/oidc"
	issURL, err := url.Parse(opIssuer)
	if err != nil {
		return nil, err
	}
	issuerPath := issURL.Path // /protocol/oidc

	// loginURL is the login-bridge path for an authRequestID. op redirects
	// unauthenticated users here, and it doubles as the post-login/post-consent
	// return_to target. RELATIVE on purpose: the browser resolves it against
	// whatever host it accessed (nginx :3500, be it localhost or a LAN IP), so
	// the flow never hard-codes a host/port. Sibling path to the op "/oidc/*"
	// subtree to avoid the wildcard.
	loginURL := func(id string) string {
		return issuerPath + "-login?authRequestID=" + url.QueryEscape(id)
	}

	clients := oidcop.NewClientStore(appResolver, loginURL)
	claims := oidcop.NewClaimsStore(idResolver, appResolver, tenantResolver, appRoles)
	// claims doubles as the UserStatusResolver (WS3-A disabled-account
	// guard) — it already wraps idResolver, the same source the hand-rolled
	// engine reads user.Status from. a.EventBus carries the WS3-B
	// reuse-detection audit signal (event.OIDCTokenReuse); nil-safe if ever
	// unwired.
	storage := oidcop.NewStorage(a.Redis, keySvc, clients, claims, claims, a.EventBus, oidcop.DefaultConfig())

	cryptoKey := a.MasterKey.Derive("oidc-op-crypto-v1")
	// Dynamic issuer: honour a runtime external-URL override (settings) the same
	// way SAML/CAS do, falling back to the static boot issuer. nil-safe on a nil
	// request (op may probe the issuer func at construction). Nil issuerResolver
	// → static-only, the pre-override behaviour.
	var dynamicIssuer oidcop.DynamicIssuer
	if issuerResolver != nil {
		dynamicIssuer = func(r *http.Request) string {
			if r == nil {
				return ""
			}
			return issuerResolver(r.Context())
		}
	}
	provider, err := oidcop.NewProvider(opIssuer, storage, cryptoKey, true, dynamicIssuer)
	if err != nil {
		return nil, err
	}

	// WS8: per-client_id token-endpoint rate limit, ported from the
	// hand-rolled engine's checkRateLimit (internal/protocol/oidc/handler.go:558)
	// so /protocol/oidc/token throttles abusive clients identically under
	// either engine. Wrapped around provider here (rather than threading
	// a.Redis/appResolver into Mount) so Mount keeps composing only
	// self-contained request/response wrappers.
	rateLimited := oidcop.WithTokenRateLimit(a.Redis, appResolver)(provider)

	// op endpoints under the issuer path; login bridge at the sibling path.
	oidcop.Mount(a.ProtocolGroup, issuerPath, rateLimited)

	// op.AuthCallbackURL returns an op-root-relative path (/authorize/callback?id=…)
	// because op is mounted under a stripped prefix. Prepend only the issuer PATH
	// (not the host) so it stays relative — same host-agnostic reasoning as
	// loginURL above.
	opCallback := oidcop.CallbackURL(provider)
	callbackURL := func(ctx context.Context, id string) string {
		return issuerPath + opCallback(ctx, id)
	}

	// WS2: back-channel logout fan-out for offboarding + JIT downstream
	// teardown. The signer uses the SAME provider keyset (keySvc) that signs
	// id_tokens above — NOT a per-app cert — so RPs validate the logout_token
	// against the JWKS they already trust for id_token verification. Outbound
	// POSTs go through the SSRF-guarded safehttp client; production
	// backchannel_logout_uri values are admin-configured, arbitrary hosts.
	participationIndex := oidclogout.NewIndex(a.Redis)
	logoutSvc := oidclogout.NewService(
		sessionMgr,
		participationIndex,
		appResolver,
		oidclogout.NewProviderKeysetSigner(keySvc),
		opIssuer,
		safehttp.New(safehttp.WithTimeout(5*time.Second)),
		idResolver,
		tenantResolver,
		issuerResolver,
	)

	// SSO login-confirmation store (Google-style, product requirement). SAME
	// Redis-backed keyspace (ssoconfirm:) the portal confirm page mints into
	// (internal/gateway/portal/consent_handler.go) and the hand-rolled engine
	// consumes from — ssoflow.ConfirmStore is a stateless wrapper over the
	// shared client, so this is one logical store, NOT a second one. The bridge
	// consumes a valid one-time token to satisfy the SP-initiated confirm gate.
	confirm := ssoflow.NewConfirmStore(a.Redis)

	// portalURL "" → the bridge redirects to relative /login, /consent, and
	// /no-access, which the browser resolves against the nginx host it is
	// already on.
	bridge := oidcop.NewLoginBridge(
		storage, appResolver, sessResolver, confirm, access, participationIndex,
		callbackURL, loginURL, "",
	)
	a.ProtocolGroup.GET("/oidc-login", bridge.Handle)

	a.Logger.Info("OIDC engine: zitadel/oidc", zap.String("issuer", opIssuer))
	return logoutSvc, nil
}
