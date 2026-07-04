package oidcop

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// clientConfig is the OIDC slice of an app's protocol_config JSONB. Kept local
// to oidcop (a copy of the fields we need) so this package does not depend on
// the hand-rolled internal/protocol/oidc package that P7 retires.
type clientConfig struct {
	GrantTypes            []string      `json:"grant_types"`
	ResponseTypes         []string      `json:"response_types"`
	Scopes                []string      `json:"scopes"`
	PKCERequired          bool          `json:"pkce_required"`
	IDTokenTTL            int           `json:"id_token_ttl"`
	TokenEndpointAuthMode string        `json:"token_endpoint_auth_mode"`
	JWKS                  string        `json:"jwks"`
	JWKSURI               string        `json:"jwks_uri"`
	ClaimMappers          []claimMapper `json:"claim_mappers"`
}

// claimMapper is one declarative per-app claim projection (Keycloak "mapper" /
// Auth0 "rule" equivalent): emit Claim from the dotted identity Source, gated by
// Scope ("" or "*" = always).
type claimMapper struct {
	Claim  string `json:"claim"`
	Source string `json:"source"`
	Scope  string `json:"scope"`
}

// defaultIDTokenTTLSeconds is the fallback id_token lifetime (1 hour).
const defaultIDTokenTTLSeconds = 3600

func parseClientConfig(raw json.RawMessage) clientConfig {
	cfg := clientConfig{
		GrantTypes:            []string{"authorization_code", "refresh_token"},
		ResponseTypes:         []string{"code"},
		Scopes:                []string{"openid", "profile", "email"},
		IDTokenTTL:            defaultIDTokenTTLSeconds,
		TokenEndpointAuthMode: "client_secret_post",
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &cfg)
	}
	return cfg
}

// oidcClient adapts a resolved MXID app into op.Client.
type oidcClient struct {
	app      *resolver.AppConfig
	cfg      clientConfig
	loginURL func(authRequestID string) string
}

var _ op.Client = (*oidcClient)(nil)

func (c *oidcClient) GetID() string             { return c.app.ClientID }
func (c *oidcClient) RedirectURIs() []string    { return c.app.RedirectURIs }
func (c *oidcClient) LoginURL(id string) string { return c.loginURL(id) }
func (c *oidcClient) DevMode() bool             { return false }
func (c *oidcClient) ClockSkew() time.Duration  { return 0 }

func (c *oidcClient) PostLogoutRedirectURIs() []string {
	if c.app.LogoutURL != "" {
		return []string{c.app.LogoutURL}
	}
	return nil
}

func (c *oidcClient) ApplicationType() op.ApplicationType {
	switch c.app.ClientType {
	case "spa":
		return op.ApplicationTypeUserAgent
	case "native":
		return op.ApplicationTypeNative
	default: // web_app, m2m
		return op.ApplicationTypeWeb
	}
}

func (c *oidcClient) AuthMethod() oidc.AuthMethod {
	switch c.cfg.TokenEndpointAuthMode {
	case "client_secret_basic":
		return oidc.AuthMethodBasic
	case "none":
		return oidc.AuthMethodNone
	case "private_key_jwt":
		return oidc.AuthMethodPrivateKeyJWT
	default: // client_secret_post, client_secret_jwt (bcrypt-stored → treated as post)
		return oidc.AuthMethodPost
	}
}

func (c *oidcClient) ResponseTypes() []oidc.ResponseType {
	out := make([]oidc.ResponseType, 0, len(c.cfg.ResponseTypes))
	for _, rt := range c.cfg.ResponseTypes {
		out = append(out, oidc.ResponseType(rt))
	}
	return out
}

func (c *oidcClient) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(c.cfg.GrantTypes))
	for _, gt := range c.cfg.GrantTypes {
		out = append(out, oidc.GrantType(gt))
	}
	return out
}

// AccessTokenTypeBearer (opaque) — revocable and introspectable via our Redis
// store, the correct choice for an SSO IdP (vs self-contained JWT access tokens
// that resource servers accept without a revocation check).
func (c *oidcClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }

func (c *oidcClient) IDTokenLifetime() time.Duration {
	if c.cfg.IDTokenTTL > 0 {
		return time.Duration(c.cfg.IDTokenTTL) * time.Second
	}
	return time.Hour
}

func (c *oidcClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *oidcClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed gates which scopes a client may request. Standard OIDC scopes
// are always permitted; anything else must be in the app's configured allowlist.
func (c *oidcClient) IsScopeAllowed(scope string) bool {
	switch scope {
	case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone,
		oidc.ScopeAddress, oidc.ScopeOfflineAccess:
		return true
	}
	return slices.Contains(c.cfg.Scopes, scope)
}

// IDTokenUserinfoClaimsAssertion: false → identity claims are served from the
// userinfo endpoint, not stuffed into the id_token (the common default).
func (c *oidcClient) IDTokenUserinfoClaimsAssertion() bool { return false }

// --- ClientResolver ----------------------------------------------------------

// ClientStore resolves MXID apps as OIDC clients for the op.Storage.
type ClientStore struct {
	apps     resolver.AppResolver
	loginURL func(authRequestID string) string
}

var _ ClientResolver = (*ClientStore)(nil)

// NewClientStore wires a ClientStore. loginURL builds the BFF login redirect
// target carrying the authRequestID (the P6 bridge entrypoint).
func NewClientStore(apps resolver.AppResolver, loginURL func(authRequestID string) string) *ClientStore {
	return &ClientStore{apps: apps, loginURL: loginURL}
}

func (s *ClientStore) resolve(ctx context.Context, clientID string) (*oidcClient, error) {
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, oidc.ErrInvalidClient().WithParent(fmt.Errorf("client not found"))
	}
	if app.Protocol != "oidc" {
		return nil, oidc.ErrInvalidClient().WithParent(fmt.Errorf("app %s is not an OIDC client", clientID))
	}
	if app.Status != 1 {
		return nil, oidc.ErrInvalidClient().WithParent(fmt.Errorf("client %s is disabled", clientID))
	}
	return &oidcClient{app: app, cfg: parseClientConfig(app.ProtocolConfig), loginURL: s.loginURL}, nil
}

func (s *ClientStore) ClientByID(ctx context.Context, clientID string) (op.Client, error) {
	return s.resolve(ctx, clientID)
}

func (s *ClientStore) AuthorizeSecret(ctx context.Context, clientID, clientSecret string) error {
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if app == nil || app.ClientSecret == "" {
		return fmt.Errorf("invalid client credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(app.ClientSecret), []byte(clientSecret)); err != nil {
		return fmt.Errorf("invalid client credentials")
	}
	return nil
}

// ClientKey returns a client's registered public JWK for private_key_jwt client
// authentication, matched by key id from the app's inline JWKS.
func (s *ClientStore) ClientKey(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	app, err := s.apps.GetAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("client not found")
	}
	cfg := parseClientConfig(app.ProtocolConfig)
	if cfg.JWKS == "" {
		return nil, fmt.Errorf("client %s has no registered JWKS", clientID)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(cfg.JWKS), &set); err != nil {
		return nil, fmt.Errorf("parse client JWKS: %w", err)
	}
	for i := range set.Keys {
		if set.Keys[i].KeyID == keyID {
			return &set.Keys[i], nil
		}
	}
	// No kid match: if exactly one key, use it (clients often omit kid).
	if len(set.Keys) == 1 {
		return &set.Keys[0], nil
	}
	return nil, fmt.Errorf("no matching key for kid %q", keyID)
}
