package bootstrap

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/response"
)

// SystemInfo is the payload of GET /api/v1/system/info — public metadata the
// frontends need before authentication (and that admins copy-paste from the
// in-console docs page).
//
// All URLs are absolute and externally reachable; frontends MUST use them
// verbatim instead of guessing from window.location.origin (which breaks
// under reverse proxies, custom paths, or single-domain deploys where the
// console lives at /admin).
type SystemInfo struct {
	// IssuerURL is the root for protocol endpoints. OIDC discovery doc lives
	// at {IssuerURL}/protocol/oidc/{app}/.well-known/openid-configuration.
	IssuerURL string `json:"issuer_url"`
	// PortalURL is where end users land for login / consent.
	PortalURL string `json:"portal_url"`
	// ConsoleURL is where admins manage the IDP. May equal PortalURL when
	// the operator runs a single-domain deploy.
	ConsoleURL string `json:"console_url"`
	// Version is the MXID build tag. Empty during dev.
	Version string `json:"version,omitempty"`
	// Edition is "ce" or "ee" — drives which features the frontend exposes.
	Edition string `json:"edition"`
	// LicenseState is "ce" | "ee" | "expired" | "invalid" — lets the console
	// distinguish a lapsed/bad license (show a renew banner) from plain CE.
	LicenseState string `json:"license_state"`
	// Features lists the unlocked EE feature keys (empty in CE). The console
	// gates EE-only UI on these.
	Features []string `json:"features"`
}

// RegisterSystemInfo wires GET /api/v1/system/info on the root engine.
// Intentionally NOT under /api/v1/console or /api/v1/portal because the
// portal SPA login page needs it before any session exists.
//
// registeredCodeSep is the set of code-separated feature keys actually built
// into this binary (registry.RegisteredFeatures()). It's passed in rather than
// read here because bootstrap must not import pkg/ee/registry (registry already
// imports bootstrap — that would cycle). Empty in CE.
func RegisterSystemInfo(r *gin.Engine, cfg *ServerConfig, version string, registeredCodeSep []string) {
	registered := make(map[string]bool, len(registeredCodeSep))
	for _, k := range registeredCodeSep {
		registered[k] = true
	}
	base := SystemInfo{
		IssuerURL:  firstNonEmpty(cfg.IssuerURL, cfg.PortalURL),
		PortalURL:  cfg.PortalURL,
		ConsoleURL: firstNonEmpty(cfg.ConsoleURL, cfg.PortalURL),
		// Public endpoint: expose only the major version, not the full
		// git-describe tag (e.g. v0.0.2-15-g69e2fd9) — the exact build/commit is
		// an information-disclosure vector for an anonymous caller. The precise
		// version stays available post-auth via the console version endpoint.
		Version: majorVersion(version),
	}
	r.GET("/api/v1/system/info", func(c *gin.Context) {
		// Edition read live so a runtime license swap reflects without restart.
		info := base
		lic := license.Current()
		info.Edition = string(lic.Edition())
		info.LicenseState = lic.State()
		info.Features = featureStrings(lic.EnabledFeatures(), registered)
		response.OK(c, info)
	})
}

// majorVersion strips the git-describe suffix from a build tag so the public
// system-info endpoint leaks only "v0.0.2", not "v0.0.2-15-g69e2fd9". Anything
// before the first "-" is the released semver; the rest is build metadata.
func majorVersion(v string) string {
	if i := strings.IndexByte(v, '-'); i > 0 {
		return v[:i]
	}
	return v
}

func featureStrings(fs []license.Feature, registeredCodeSep map[string]bool) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		// Don't advertise reserved-but-unbuilt features (e.g. webauthn)
		// even if a license unlocks them — public metadata must reflect what's
		// actually usable, not the catalog.
		if !license.IsImplemented(f) {
			continue
		}
		// Code-separated features (external_idp/...) ship only in the EE binary.
		// A CE image with an EE license unlocks them in the catalog but 404s them
		// at runtime — advertise one only when its EE package registered into this
		// binary. Runtime-gated features (branding/multi_tenant/...) live in CE and
		// are always present once unlocked.
		if license.IsCodeSeparated(f) && !registeredCodeSep[string(f)] {
			continue
		}
		out = append(out, string(f))
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
