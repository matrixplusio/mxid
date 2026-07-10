package cas

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/safehttp"
	"go.uber.org/zap"
)

// casProxyCallbackClient is the SSRF-safe client for the pgtUrl callback. The
// CAS spec requires the pgtUrl to be reachable over TLS; the guard re-checks the
// resolved IP on every dial + redirect so the callback can't be pointed at an
// internal address. AllowHTTP mirrors the SLO client for dev/CI SPs on plain
// http — the private-IP guard still applies.
var casProxyCallbackClient = safehttp.New(
	safehttp.WithTimeout(5*time.Second),
	safehttp.AllowHTTP(),
)

// proxyCallbackDoer returns the injected test override when set, else the
// package-level SSRF-safe client.
func (h *Handler) proxyCallbackDoer() httpDoer {
	if h.backchannelClient != nil {
		return h.backchannelClient
	}
	return casProxyCallbackClient
}

// maybeIssuePGT handles a pgtUrl on a validate response. It fails CLOSED and
// best-effort: it returns the PGTIOU (to embed in the XML) only when the app has
// proxy enabled, the pgtUrl is an allow-listed service URL, and the callback
// delivering the real PGT succeeds. Any failure returns "" and the PGT is
// omitted from the response — the ticket validation itself is unaffected.
func (h *Handler) maybeIssuePGT(c *gin.Context, cfg *CASConfig, app *resolver.AppConfig, st *ServiceTicket, pgtURL string) string {
	if !cfg.ProxyEnabled {
		return ""
	}
	// The pgtUrl must belong to a registered service URL — a PGT is a long-lived
	// credential, so we never deliver one to an arbitrary host.
	if !h.isValidService(cfg, pgtURL) {
		h.logger.Warn("cas proxy: pgtUrl not in allow-list", zap.String("pgt_url", pgtURL), zap.Int64("app_id", app.ID))
		return ""
	}

	pgtIOU, err := crypto.GenerateRandomString(32)
	if err != nil {
		return ""
	}
	pgtIOU = "PGTIOU-" + pgtIOU

	// Mint the PGT first (we need its id for the callback). Inherit the proxy
	// chain from a proxy ticket; a service ticket starts a fresh chain.
	pgt, err := h.store.CreatePGT(c.Request.Context(), st.UserID, st.TenantID, app.ID, st.Username, pgtURL, st.Proxies, cfg.PGTicketTTL)
	if err != nil {
		h.logger.Warn("cas proxy: mint pgt failed", zap.Error(err), zap.Int64("app_id", app.ID))
		return ""
	}

	// Callback: GET pgtUrl?pgtId=<PGT>&pgtIou=<PGTIOU>. On non-2xx / SSRF block,
	// drop the PGT so it can't be used and omit it from the response.
	if !h.pgtCallback(c.Request.Context(), pgtURL, pgt.PGT, pgtIOU, app.ID) {
		_ = h.store.DeletePGT(c.Request.Context(), pgt.PGT)
		return ""
	}
	return pgtIOU
}

// pgtCallback performs the pgtUrl GET carrying pgtId + pgtIou. Returns true only
// on a 2xx response.
func (h *Handler) pgtCallback(ctx context.Context, pgtURL, pgtID, pgtIOU string, appID int64) bool {
	u, err := url.Parse(pgtURL)
	if err != nil {
		return false
	}
	q := u.Query()
	q.Set("pgtId", pgtID)
	q.Set("pgtIou", pgtIOU)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	resp, err := h.proxyCallbackDoer().Do(req)
	if err != nil {
		h.logger.Warn("cas proxy: pgtUrl callback failed",
			zap.String("pgt_url", pgtURL), zap.Int64("app_id", appID), zap.Error(err))
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// proxy handles CAS /proxy — mints a single-use proxy ticket (PT-) for
// targetService from a valid PGT.
func (h *Handler) proxy(c *gin.Context) {
	pgtID := c.Query("pgt")
	targetService := c.Query("targetService")
	if pgtID == "" || targetService == "" {
		h.proxyFailure(c, "INVALID_REQUEST", "missing pgt or targetService parameter")
		return
	}

	appCode := c.Param("app_code")
	app, err := h.appRes.GetApp(c.Request.Context(), appCode)
	if err != nil || app == nil {
		h.proxyFailure(c, "INVALID_REQUEST", "application not found")
		return
	}
	if app.Status != 1 {
		h.proxyFailure(c, "INVALID_REQUEST", "application is disabled")
		return
	}
	cfg := h.parseCASConfig(app.ProtocolConfig)
	if !cfg.ProxyEnabled {
		h.proxyFailure(c, "UNAUTHORIZED_SERVICE", "proxy authentication is not enabled for this service")
		return
	}
	// targetService must be an allow-listed URL for this app (fail-closed).
	if !h.isValidService(cfg, targetService) {
		h.proxyFailure(c, "UNAUTHORIZED_SERVICE", "targetService is not a registered service URL")
		return
	}

	pgt, err := h.store.GetPGT(c.Request.Context(), pgtID)
	if err != nil {
		h.proxyFailure(c, "BAD_PGT", "proxy-granting ticket not recognized or expired")
		return
	}
	// The PGT is bound to the app that minted it — a PGT from another CAS app
	// cannot mint tickets here.
	if pgt.AppID != app.ID {
		h.proxyFailure(c, "BAD_PGT", "proxy-granting ticket does not belong to this service")
		return
	}

	pt, err := h.store.CreateProxyTicket(c.Request.Context(), pgt, targetService)
	if err != nil {
		h.proxyFailure(c, "INTERNAL_ERROR", "failed to create proxy ticket")
		return
	}

	resp := &ProxyResponse{
		Xmlns:   "http://www.yale.edu/tp/cas",
		Success: &ProxySuccess{ProxyTicket: pt.Ticket},
	}
	xmlBytes, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		h.proxyFailure(c, "INTERNAL_ERROR", "failed to generate response")
		return
	}
	c.Data(http.StatusOK, "application/xml; charset=utf-8", append([]byte(xml.Header), xmlBytes...))
}

// proxyFailure writes a <cas:proxyFailure> envelope.
func (h *Handler) proxyFailure(c *gin.Context, code, message string) {
	resp := &ProxyResponse{
		Xmlns:   "http://www.yale.edu/tp/cas",
		Failure: &ProxyFailure{Code: code, Message: message},
	}
	xmlBytes, _ := xml.MarshalIndent(resp, "", "  ")
	c.Data(http.StatusOK, "application/xml; charset=utf-8", append([]byte(xml.Header), xmlBytes...))
}
