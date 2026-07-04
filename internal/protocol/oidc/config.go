package oidc

// OIDCConfig holds OIDC-specific settings from app.protocol_config JSONB.
type OIDCConfig struct {
	GrantTypes            []string `json:"grant_types"`              // authorization_code, refresh_token, client_credentials
	ResponseTypes         []string `json:"response_types"`           // code, token, id_token
	Scopes                []string `json:"scopes"`                   // openid, profile, email, phone, groups
	PKCERequired          bool     `json:"pkce_required"`            // enforce PKCE
	IDTokenSigningAlg     string   `json:"id_token_signing_alg"`     // RS256
	AccessTokenTTL        int      `json:"access_token_ttl"`         // seconds, default 900 (15m)
	IDTokenTTL            int      `json:"id_token_ttl"`             // seconds, default mirrors access token
	RefreshTokenTTL       int      `json:"refresh_token_ttl"`        // seconds, default 604800 (7d)
	AuthCodeTTL           int      `json:"auth_code_ttl"`            // seconds, default 300 (5m)
	RequireConsent        bool     `json:"require_consent"`          // show consent screen
	SubjectType           string   `json:"subject_type"`             // public or pairwise
	TokenEndpointAuthMode string   `json:"token_endpoint_auth_mode"` // client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt, none

	// JWT-bearer client authentication (RFC 7523). Only consulted when the
	// app's token_endpoint_auth_mode is private_key_jwt.
	//
	// JWKS is an inline JWK Set; JWKSURI is fetched on demand and cached.
	// Exactly one should be set per app — they're mutually exclusive per spec.
	JWKS    string `json:"jwks"`
	JWKSURI string `json:"jwks_uri"`

	// Back-channel logout. When set, end_session_endpoint POSTs a signed
	// logout_token to this URL whenever the user terminates their SSO session.
	BackchannelLogoutURI             string `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required"`

	// RateLimitPerMin caps token-endpoint requests for this client per
	// rolling 60-second window. 0 falls back to the IdP-wide default.
	RateLimitPerMin int `json:"rate_limit_per_min"`

	// Per-app claim mappers — the commercial IdP equivalent of Keycloak's
	// "Mappers" or Auth0's "Rules / Actions". After base scope-driven claims
	// are assembled, every mapper whose Scope matches is resolved against
	// the IdentityInfo + nested Detail map and the resulting value is
	// injected into the id_token + userinfo response under Claim.
	//
	// Empty Scope ("*") fires unconditionally.
	ClaimMappers []ClaimMapperConfig `json:"claim_mappers"`
}

// ClaimMapperConfig describes one declarative claim projection.
//
//	Claim  → name under which the value appears in id_token / userinfo
//	Source → dotted path into IdentityInfo, e.g. "user.username",
//	         "user.detail.employee_no", "user.email"
//	Scope  → OIDC scope gating; empty / "*" means always emit
type ClaimMapperConfig struct {
	Claim  string `json:"claim"`
	Source string `json:"source"`
	Scope  string `json:"scope"`
}

// Default token lifetimes (seconds), named so the numbers aren't magic ints.
const (
	defaultAccessTokenTTLSeconds  = 3600    // 1 hour
	defaultIDTokenTTLSeconds      = 3600    // 1 hour
	defaultRefreshTokenTTLSeconds = 2592000 // 30 days
	defaultAuthCodeTTLSeconds     = 600     // 10 minutes
)

// Defaults returns an OIDCConfig with sane defaults.
func Defaults() *OIDCConfig {
	return &OIDCConfig{
		GrantTypes:            []string{"authorization_code", "refresh_token"},
		ResponseTypes:         []string{"code"},
		Scopes:                []string{"openid", "profile", "email"},
		PKCERequired:          false,
		IDTokenSigningAlg:     "RS256",
		AccessTokenTTL:        defaultAccessTokenTTLSeconds,
		IDTokenTTL:            defaultIDTokenTTLSeconds,
		RefreshTokenTTL:       defaultRefreshTokenTTLSeconds,
		AuthCodeTTL:           defaultAuthCodeTTLSeconds,
		RequireConsent:        false,
		SubjectType:           "public",
		TokenEndpointAuthMode: "client_secret_post",
	}
}
