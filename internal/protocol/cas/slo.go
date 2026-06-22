package cas

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imkerbos/mxid/pkg/safehttp"
	"go.uber.org/zap"
)

// casLogoutClient is the SSRF-safe client for POSTing CAS logoutRequest XML
// to admin-configured SP SLO endpoints. The IP/scheme guard re-checks every
// dial + redirect hop, preventing the logout payload from being replayed to
// an internal address.
var casLogoutClient = safehttp.New(
	safehttp.WithTimeout(5*time.Second),
	safehttp.AllowHTTP(), // CAS SPs in dev/CI may be plain http; guard still blocks private IPs
)

// casLogoutXMLTemplate is the standard CAS Single Logout XML body as required
// by the CAS protocol spec (section 2.3.3). Jumpserver and other CAS clients
// expect the logoutRequest POST parameter to contain a <samlp:LogoutRequest>
// with the service ticket in <samlp:SessionIndex>.
const casLogoutXMLTemplate = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
	` ID="%s" Version="2.0" IssueInstant="%s">` +
	`<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">@NOT_USED@</saml:NameID>` +
	`<samlp:SessionIndex>%s</samlp:SessionIndex>` +
	`</samlp:LogoutRequest>`

// SingleLogout sends a CAS back-channel Single Logout POST to every service
// the user authenticated to under appID. For each recorded service it:
//
//  1. Builds a <samlp:LogoutRequest> carrying the original service ticket.
//  2. POSTs it as logoutRequest=<urlencoded XML> to the service's SLO URL
//     (cfg.LogoutURL if configured, otherwise the recorded ServiceURL).
//  3. Clears the registry entry for the (userID, appID) pair.
//
// Each POST runs in its own goroutine (best-effort, async). Errors are logged
// with WARN severity; they do not block the caller or prevent registry cleanup.
func (h *Handler) SingleLogout(ctx context.Context, userID, appID int64) {
	if h.serviceRegistry == nil {
		return
	}

	services, err := h.serviceRegistry.ListServices(ctx, userID, appID)
	if err != nil {
		h.logger.Warn("cas slo: list services failed",
			zap.Int64("user_id", userID), zap.Int64("app_id", appID), zap.Error(err))
		return
	}
	if len(services) == 0 {
		return
	}

	// Resolve the app config to check whether a dedicated LogoutURL is set.
	// Best-effort: a missing app or config parse error simply leaves target as
	// the recorded ServiceURL (which is the correct CAS SLO fallback).
	var logoutURLOverride string
	if h.appRes != nil {
		if app, aerr := h.appRes.GetAppByID(ctx, appID); aerr == nil && app != nil {
			cfg := h.parseCASConfig(app.ProtocolConfig)
			logoutURLOverride = cfg.LogoutURL
		}
	}

	doer := h.sloDoer()

	now := time.Now().UTC()
	for _, svc := range services {
		target := svc.ServiceURL
		if logoutURLOverride != "" {
			target = logoutURLOverride
		}

		id := fmt.Sprintf("LR-%d-%d-%d", userID, appID, now.UnixNano())
		body := fmt.Sprintf(casLogoutXMLTemplate, id, now.Format(time.RFC3339), svc.Ticket)

		go h.sendCASLogout(doer, target, body, appID)
	}

	// Clear the registry after dispatching goroutines. A failure here is
	// logged but does not affect whether the SLO POSTs were sent.
	if cerr := h.serviceRegistry.Clear(ctx, userID, appID); cerr != nil {
		h.logger.Warn("cas slo: registry clear failed",
			zap.Int64("user_id", userID), zap.Int64("app_id", appID), zap.Error(cerr))
	}
}

// sendCASLogout POSTs the CAS logoutRequest form body to target via the
// provided doer. Errors (including SSRF-guard blocks) are logged at WARN;
// the response body is discarded.
func (h *Handler) sendCASLogout(doer httpDoer, target, xmlBody string, appID int64) {
	form := url.Values{"logoutRequest": {xmlBody}}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		h.logger.Warn("cas slo: build request failed",
			zap.Int64("app_id", appID), zap.String("target", target), zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := doer.Do(req)
	if err != nil {
		// Includes the SSRF-guard block case (target resolving to an internal
		// address or disallowed scheme). Best-effort: log and move on.
		h.logger.Warn("cas slo: POST failed",
			zap.Int64("app_id", appID), zap.String("target", target), zap.Error(err))
		return
	}
	_ = resp.Body.Close()
}

// sloDoer returns the HTTP doer for SingleLogout: the injected test override
// when non-nil, otherwise the package-level SSRF-safe casLogoutClient.
func (h *Handler) sloDoer() httpDoer {
	if h.backchannelClient != nil {
		return h.backchannelClient
	}
	return casLogoutClient
}
