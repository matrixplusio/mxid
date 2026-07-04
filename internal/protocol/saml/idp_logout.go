package saml

import (
	"context"
	"net/http"
	"time"

	"github.com/imkerbos/mxid/pkg/safehttp"
	"go.uber.org/zap"
)

// samlBackchannelClient is the SSRF-safe client for sending IdP-initiated SAML
// LogoutRequests to an admin-configured SP SLO endpoint (per-app, arbitrary
// host). The IP/scheme guard re-checks every dial + redirect hop, preventing the
// signed LogoutRequest from being replayed to an internal address.
var samlBackchannelClient = safehttp.New(safehttp.WithTimeout(5 * time.Second))

// IdPInitiatedLogout terminates the user's SAML session at the SP when a JIT
// app-role grant expires or is revoked. It looks up the SessionIndex + NameID
// captured at SSO time, builds a signed <samlp:LogoutRequest> per stored ref,
// and sends it to the SP's SLOURL via the HTTP-Redirect binding through the
// SSRF-safe client.
//
// Best-effort and asynchronous: the dispatch runs in a goroutine so the caller
// (the grant sweeper / revoke path) never blocks on an unreachable SP, and any
// failure is logged rather than propagated. The session index entry is deleted
// once requests are dispatched — a failed delivery still drops the local record
// because the grant is gone regardless of whether the SP acknowledges.
func (h *Handler) IdPInitiatedLogout(ctx context.Context, userID, appID int64) {
	if h.sessionIdx == nil {
		return
	}
	refs, err := h.sessionIdx.Get(ctx, userID, appID)
	if err != nil {
		h.logger.Warn("saml jit logout: session index lookup failed",
			zap.Int64("user_id", userID), zap.Int64("app_id", appID), zap.Error(err))
		return
	}
	if len(refs) == 0 {
		return // no active SAML session to terminate
	}

	app, err := h.appRes.GetAppByID(ctx, appID)
	if err != nil || app == nil {
		h.logger.Warn("saml jit logout: resolve app failed",
			zap.Int64("app_id", appID), zap.Error(err))
		return
	}
	cfg := h.parseSAMLConfig(app.ProtocolConfig)
	if cfg.SLOURL == "" {
		// SP has no Single Logout Service configured — nothing we can do.
		// Still drop the stale index entry below.
		h.logger.Warn("saml jit logout: no SLOURL for app", zap.Int64("app_id", appID))
		_ = h.sessionIdx.Delete(ctx, userID, appID)
		return
	}

	key, _, err := h.loadKeyAndCert(ctx, appID)
	if err != nil {
		h.logger.Warn("saml jit logout: load signing key failed",
			zap.Int64("app_id", appID), zap.Error(err))
		return
	}

	issuer := h.resolveURLs(ctx, "").Issuer
	doer := h.doer()

	for _, ref := range refs {
		nameIDFormat := ref.NameIDFormat
		if nameIDFormat == "" {
			// Older ref recorded before NameIDFormat was captured per-session;
			// fall back to the app's current config default.
			nameIDFormat = cfg.NameIDFormat
		}
		target, berr := buildLogoutRequestRedirect(cfg.SLOURL, issuer, ref.NameID, nameIDFormat, ref.SessionIndex, key)
		if berr != nil {
			h.logger.Warn("saml jit logout: build LogoutRequest failed",
				zap.Int64("app_id", appID), zap.Error(berr))
			continue
		}
		go h.sendLogoutRequest(doer, target, appID)
	}

	if derr := h.sessionIdx.Delete(ctx, userID, appID); derr != nil {
		h.logger.Warn("saml jit logout: delete session index failed",
			zap.Int64("user_id", userID), zap.Int64("app_id", appID), zap.Error(derr))
	}
}

// sendLogoutRequest GETs the SP SLO redirect URL (carrying the signed
// SAMLRequest) through the SSRF-safe client. Best-effort: the response is
// discarded and any error logged.
func (h *Handler) sendLogoutRequest(doer httpDoer, target string, appID int64) {
	// Detached back-channel call (fired from a goroutine with no request ctx);
	// give it its own bounded context so the dial is cancellable and can't hang
	// past the deadline even if the SSRF client's own timeout ever changed.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		h.logger.Warn("saml jit logout: new request failed",
			zap.Int64("app_id", appID), zap.Error(err))
		return
	}
	resp, err := doer.Do(req)
	if err != nil {
		// Includes the SSRF-guard block case (SLOURL resolving to an internal
		// address or a disallowed scheme).
		h.logger.Warn("saml jit logout: send failed",
			zap.Int64("app_id", appID), zap.Error(err))
		return
	}
	_ = resp.Body.Close()
}

// doer returns the HTTP client used to deliver LogoutRequests: the injected
// test override when set, otherwise the package-level SSRF-safe client.
func (h *Handler) doer() httpDoer {
	if h.backchannelClient != nil {
		return h.backchannelClient
	}
	return samlBackchannelClient
}
