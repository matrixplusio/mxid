package license

import "slices"

// Feature is an EE-gated capability key. CE (no/invalid license) has NONE of
// these; an EE license unlocks the subset listed in its signed payload.
//
// Core IAM (password/TOTP/sessions, OIDC/SAML/CAS, users/orgs/groups, basic
// RBAC, SMTP, basic audit, the single default tenant) is NOT gated — it never
// goes through Has(), it's always available.
type Feature string

const (
	// FeatureMultiTenant — create/run more than the single default tenant.
	FeatureMultiTenant Feature = "multi_tenant"
	// FeatureExternalIDP — log in via external identity providers (social /
	// enterprise SSO upstreams).
	FeatureExternalIDP Feature = "external_idp"
	// FeatureBranding — white-label: logo, colors, product name, login page.
	FeatureBranding Feature = "branding"
	// FeatureConditionalAccess — risk-based / adaptive access policies.
	FeatureConditionalAccess Feature = "conditional_access"
	// FeatureWebAuthn — WebAuthn / passkeys / hardware security keys.
	FeatureWebAuthn Feature = "webauthn"
	// FeatureSCIM — SCIM 2.0 user/group provisioning.
	FeatureSCIM Feature = "scim"
	// FeatureAdvancedStepUp — advanced step-up / sudo policies.
	FeatureAdvancedStepUp Feature = "advanced_stepup"
	// FeatureSMS — SMS-based login / OTP.
	FeatureSMS Feature = "sms"
	// FeatureFormFill — form-fill / SWA credential vault: store a user's
	// downstream username+password and auto-submit the target site's login form
	// via the browser extension. Credential-custodian feature; code lives only in
	// mxid-ee. See docs/FORM-FILL-SSO-DESIGN.md.
	FeatureFormFill Feature = "form_fill"
)

// AllFeatures is the full catalog — reserved keys used to validate feature
// strings in a license payload (and forward-compat). NOT every key here has
// shipping code yet; see ImplementedFeatures.
var AllFeatures = []Feature{
	FeatureMultiTenant,
	FeatureExternalIDP,
	FeatureBranding,
	FeatureConditionalAccess,
	FeatureWebAuthn,
	FeatureSCIM,
	FeatureAdvancedStepUp,
	FeatureSMS,
	FeatureFormFill,
}

// ImplementedFeatures lists the EE features that actually have shipping code in
// this product today. The remaining AllFeatures entries are reserved catalog
// keys (defined for the signing tool + forward-compat) but NOT yet built — so
// public system metadata must not advertise them as available. Move a key here
// the moment its feature ships.
var ImplementedFeatures = []Feature{
	FeatureMultiTenant,      // runtime-gated, CE schema
	FeatureBranding,         // runtime-gated, CE schema
	FeatureConditionalAccess, // runtime-gated, CE schema
	FeatureExternalIDP,      // code-separated, mxid-ee
	FeatureSCIM,             // code-separated, mxid-ee (L2 offboarding deprovision)
}

// IsImplemented reports whether f has shipping code (vs a reserved catalog key
// not yet built). Used to keep /system/info from advertising unbuilt features.
func IsImplemented(f Feature) bool {
	return slices.Contains(ImplementedFeatures, f)
}

// CodeSeparatedFeatures ship ONLY in the EE binary: their packages live in
// github.com/imkerbos/mxid-ee and self-register through pkg/ee/registry. The CE
// binary contains none of this code, so even a license that unlocks one yields
// 404 — it must be advertised only when its EE package actually registered in
// THIS binary. The other ImplementedFeatures are runtime-gated (code lives in
// CE, the license just opens the gate) and are always present once unlocked.
var CodeSeparatedFeatures = []Feature{
	FeatureExternalIDP,
	FeatureWebAuthn,
	FeatureSCIM,
	FeatureSMS,
	FeatureAdvancedStepUp,
	FeatureFormFill,
}

// IsCodeSeparated reports whether f's code ships only in the EE binary (vs
// runtime-gated CE code). Such a feature is usable only when its EE package
// registered itself at startup — see registry.RegisteredFeatures.
func IsCodeSeparated(f Feature) bool {
	return slices.Contains(CodeSeparatedFeatures, f)
}
