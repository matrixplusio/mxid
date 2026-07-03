package oidcop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/imkerbos/mxid/internal/domain/oidckey"
	"github.com/imkerbos/mxid/pkg/crypto"
)

// ClientResolver resolves a client_id into an op.Client and validates client
// credentials. Implemented in client.go (P3) over MXID's app store.
type ClientResolver interface {
	ClientByID(ctx context.Context, clientID string) (op.Client, error)
	AuthorizeSecret(ctx context.Context, clientID, secret string) error
	// ClientKey returns a client's registered public JWK for private_key_jwt
	// client auth / JWT-profile grant. Returns an error when unknown.
	ClientKey(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error)
}

// ClaimsResolver fills id_token/userinfo claims from MXID identity, driven by
// scopes. Implemented in claims.go (P4).
type ClaimsResolver interface {
	SetUserinfo(ctx context.Context, info *oidc.UserInfo, userID, clientID string, scopes []string) error
	PrivateClaims(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error)
}

// Config carries token lifetimes.
type Config struct {
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	AuthRequestLifetime  time.Duration
	CodeLifetime         time.Duration
}

// DefaultConfig returns sensible OIDC token lifetimes.
func DefaultConfig() Config {
	return Config{
		AccessTokenLifetime:  10 * time.Minute,
		RefreshTokenLifetime: 30 * 24 * time.Hour,
		AuthRequestLifetime:  15 * time.Minute,
		CodeLifetime:         5 * time.Minute,
	}
}

// Storage implements op.Storage backed by Redis (auth requests, codes, tokens),
// the provider keyset (oidckey), and MXID resolvers for clients + claims.
type Storage struct {
	rdb     *redis.Client
	keys    *oidckey.Service
	clients ClientResolver
	claims  ClaimsResolver
	cfg     Config
}

// NewStorage wires a Storage.
func NewStorage(rdb *redis.Client, keys *oidckey.Service, clients ClientResolver, claims ClaimsResolver, cfg Config) *Storage {
	return &Storage{rdb: rdb, keys: keys, clients: clients, claims: claims, cfg: cfg}
}

// Compile-time assertion that we satisfy the full op.Storage contract.
var _ op.Storage = (*Storage)(nil)

// --- Redis key helpers -------------------------------------------------------

func kAuthReq(id string) string   { return "oidc:authreq:" + id }
func kCode(code string) string    { return "oidc:code:" + code }
func kToken(id string) string     { return "oidc:token:" + id }
func kRefresh(tok string) string  { return "oidc:refresh:" + tok }
func kUserTok(u, c string) string { return "oidc:utk:" + u + ":" + c }

func (s *Storage) setJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, key, b, ttl).Err()
}

func (s *Storage) getJSON(ctx context.Context, key string, v any) (bool, error) {
	b, err := s.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

// --- AuthStorage: auth requests + codes -------------------------------------

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if len(req.Prompt) == 1 && req.Prompt[0] == oidc.PromptNone {
		// No login UI can run under prompt=none → fail per spec.
		return nil, oidc.ErrLoginRequired()
	}
	id, err := crypto.GenerateBase62(24)
	if err != nil {
		return nil, err
	}
	ar := authRequestFromOIDC(req, id, userID)
	if err := s.setJSON(ctx, kAuthReq(id), ar, s.cfg.AuthRequestLifetime); err != nil {
		return nil, err
	}
	return ar, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	var ar authRequest
	ok, err := s.getJSON(ctx, kAuthReq(id), &ar)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("auth request not found")
	}
	return &ar, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	id, err := s.rdb.Get(ctx, kCode(code)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("code invalid or expired")
	}
	if err != nil {
		return nil, err
	}
	return s.AuthRequestByID(ctx, id)
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	return s.rdb.Set(ctx, kCode(code), id, s.cfg.CodeLifetime).Err()
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, kAuthReq(id)).Err()
}

// AuthRequestDone marks an auth request authenticated. Called by the login
// bridge (P6) after the user authenticates + consents through the portal.
func (s *Storage) AuthRequestDone(ctx context.Context, id, userID string, authTime time.Time, amr []string) error {
	var ar authRequest
	ok, err := s.getJSON(ctx, kAuthReq(id), &ar)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("auth request not found")
	}
	ar.UserID = userID
	ar.IsDone = true
	ar.AuthAt = authTime
	if len(amr) > 0 {
		ar.AMR = amr
	}
	return s.setJSON(ctx, kAuthReq(id), &ar, s.cfg.AuthRequestLifetime)
}

// --- AuthStorage: tokens -----------------------------------------------------

func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	clientID, _, _ := getInfoFromRequest(request)
	tok, err := s.storeAccessToken(ctx, clientID, "", request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", time.Time{}, err
	}
	return tok.ID, tok.Expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	clientID, authTime, amr := getInfoFromRequest(request)

	// Code flow: no current refresh token → mint a fresh access + refresh pair.
	if currentRefreshToken == "" {
		refreshID, err := crypto.GenerateBase62(32)
		if err != nil {
			return "", "", time.Time{}, err
		}
		access, err := s.storeAccessToken(ctx, clientID, refreshID, request.GetSubject(), request.GetAudience(), request.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		refresh, err := s.storeRefreshToken(ctx, refreshID, access, amr, authTime)
		if err != nil {
			return "", "", time.Time{}, err
		}
		return access.ID, refresh.Token, access.Expiration, nil
	}

	// Refresh flow: rotate. Mint new refresh string + access, swap atomically.
	newRefresh, err := crypto.GenerateBase62(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	access, err := s.storeAccessToken(ctx, clientID, newRefresh, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}
	if err := s.renewRefreshToken(ctx, currentRefreshToken, newRefresh, access); err != nil {
		return "", "", time.Time{}, err
	}
	return access.ID, newRefresh, access.Expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, token string) (op.RefreshTokenRequest, error) {
	var rt refreshToken
	ok, err := s.getJSON(ctx, kRefresh(token), &rt)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshTokenRequest{&rt}, nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	var rt refreshToken
	ok, err := s.getJSON(ctx, kRefresh(token), &rt)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.UserID, rt.ID, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	idx := kUserTok(userID, clientID)
	members, err := s.rdb.SMembers(ctx, idx).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	if len(members) > 0 {
		_ = s.rdb.Del(ctx, members...).Err()
	}
	return s.rdb.Del(ctx, idx).Err()
}

func (s *Storage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	// Access token (looked up by ID).
	var at accessToken
	ok, err := s.getJSON(ctx, kToken(tokenIDOrToken), &at)
	if err != nil {
		return oidc.ErrServerError().WithDescription("%s", err.Error())
	}
	if ok {
		if at.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		_ = s.rdb.Del(ctx, kToken(at.ID)).Err()
		return nil
	}
	// Refresh token (looked up by the token string).
	var rt refreshToken
	ok, err = s.getJSON(ctx, kRefresh(tokenIDOrToken), &rt)
	if err != nil {
		return oidc.ErrServerError().WithDescription("%s", err.Error())
	}
	if !ok {
		// Neither access nor refresh — already invalid; revocation is a no-op.
		return nil
	}
	if rt.ClientID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	_ = s.rdb.Del(ctx, kRefresh(rt.Token), kToken(rt.AccessTokenID)).Err()
	return nil
}

// --- AuthStorage: keys -------------------------------------------------------

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	priv, kid, alg, err := s.keys.LoadActiveSigningKey(ctx)
	if err != nil {
		return nil, err
	}
	return signingKey{id: kid, alg: joseAlg(alg), key: priv}, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	_, _, alg, err := s.keys.LoadActiveSigningKey(ctx)
	if err != nil {
		return nil, err
	}
	return []jose.SignatureAlgorithm{joseAlg(alg)}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	vks, err := s.keys.ListVerificationKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]op.Key, 0, len(vks))
	for _, vk := range vks {
		out = append(out, publicKey{id: vk.KID, alg: joseAlg(vk.Algorithm), key: vk.Public})
	}
	return out, nil
}

// --- OPStorage: clients ------------------------------------------------------

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	return s.clients.ClientByID(ctx, clientID)
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return s.clients.AuthorizeSecret(ctx, clientID, clientSecret)
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return s.clients.ClientKey(ctx, keyID, clientID)
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	// Permissive: JWT-profile (service-account) grants keep their requested
	// scopes. Tighten here if per-subject scope restriction is needed.
	return scopes, nil
}

// --- OPStorage: claims -------------------------------------------------------

// SetUserinfoFromScopes is deprecated in op; claims come from SetUserinfoFromRequest /
// GetPrivateClaimsFromScopes. Kept as a no-op per the interface contract.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	var at accessToken
	ok, err := s.getJSON(ctx, kToken(tokenID), &at)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("token is invalid or has expired")
	}
	if at.Expiration.Before(time.Now()) {
		return fmt.Errorf("token is expired")
	}
	return s.claims.SetUserinfo(ctx, userinfo, at.Subject, at.ClientID, at.Scopes)
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	var at accessToken
	ok, err := s.getJSON(ctx, kToken(tokenID), &at)
	if err != nil {
		return err
	}
	if !ok || at.Expiration.Before(time.Now()) {
		return fmt.Errorf("token is invalid or has expired")
	}
	// Token must have been issued for the introspecting client (as audience).
	if !slices.Contains(at.Audience, clientID) {
		return fmt.Errorf("token was not issued for this client")
	}
	userinfo := new(oidc.UserInfo)
	if err := s.claims.SetUserinfo(ctx, userinfo, at.Subject, at.ClientID, at.Scopes); err != nil {
		return err
	}
	introspection.SetUserInfo(userinfo)
	introspection.Scope = at.Scopes
	introspection.ClientID = at.ClientID
	introspection.TokenType = oidc.BearerToken
	introspection.Expiration = oidc.FromTime(at.Expiration)
	introspection.Audience = at.Audience
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return s.claims.PrivateClaims(ctx, userID, clientID, scopes)
}

// --- Health ------------------------------------------------------------------

func (s *Storage) Health(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

// --- token helpers -----------------------------------------------------------

func (s *Storage) storeAccessToken(ctx context.Context, clientID, refreshID, subject string, audience, scopes []string) (*accessToken, error) {
	id, err := crypto.GenerateBase62(32)
	if err != nil {
		return nil, err
	}
	at := &accessToken{
		ID:             id,
		ClientID:       clientID,
		Subject:        subject,
		RefreshTokenID: refreshID,
		Audience:       audience,
		Scopes:         scopes,
		Expiration:     time.Now().Add(s.cfg.AccessTokenLifetime),
	}
	if err := s.setJSON(ctx, kToken(id), at, s.cfg.AccessTokenLifetime); err != nil {
		return nil, err
	}
	s.indexAdd(ctx, subject, clientID, kToken(id))
	return at, nil
}

func (s *Storage) storeRefreshToken(ctx context.Context, refreshID string, access *accessToken, amr []string, authTime time.Time) (*refreshToken, error) {
	rt := &refreshToken{
		ID:            refreshID,
		Token:         refreshID,
		AuthTime:      authTime,
		AMR:           amr,
		Audience:      access.Audience,
		UserID:        access.Subject,
		ClientID:      access.ClientID,
		Scopes:        access.Scopes,
		AccessTokenID: access.ID,
		Expiration:    time.Now().Add(s.cfg.RefreshTokenLifetime),
	}
	if err := s.setJSON(ctx, kRefresh(rt.Token), rt, s.cfg.RefreshTokenLifetime); err != nil {
		return nil, err
	}
	s.indexAdd(ctx, rt.UserID, rt.ClientID, kRefresh(rt.Token))
	return rt, nil
}

// renewRefreshToken implements refresh token rotation (RFC 6819 §5.2.2.3):
// delete the presented token + its access token, then write a new record.
func (s *Storage) renewRefreshToken(ctx context.Context, currentToken, newToken string, access *accessToken) error {
	var rt refreshToken
	ok, err := s.getJSON(ctx, kRefresh(currentToken), &rt)
	if err != nil {
		return err
	}
	if !ok {
		return oidc.ErrInvalidGrant().WithDescription("invalid refresh token")
	}
	if rt.Expiration.Before(time.Now()) {
		return oidc.ErrInvalidGrant().WithDescription("expired refresh token")
	}
	_ = s.rdb.Del(ctx, kRefresh(currentToken), kToken(rt.AccessTokenID)).Err()

	rt.ID = newToken
	rt.Token = newToken
	rt.AccessTokenID = access.ID
	rt.Expiration = time.Now().Add(s.cfg.RefreshTokenLifetime)
	if err := s.setJSON(ctx, kRefresh(newToken), &rt, s.cfg.RefreshTokenLifetime); err != nil {
		return err
	}
	s.indexAdd(ctx, rt.UserID, rt.ClientID, kRefresh(newToken))
	return nil
}

// indexAdd tracks a token key under (user, client) so TerminateSession can
// revoke all of a user's tokens for a client on logout.
func (s *Storage) indexAdd(ctx context.Context, userID, clientID, tokenKey string) {
	if userID == "" || clientID == "" {
		return
	}
	idx := kUserTok(userID, clientID)
	_ = s.rdb.SAdd(ctx, idx, tokenKey).Err()
	_ = s.rdb.Expire(ctx, idx, s.cfg.RefreshTokenLifetime).Err()
}

// getInfoFromRequest extracts client_id, auth_time and amr from the various
// op.TokenRequest concrete types we hand back from the storage.
func getInfoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	switch r := req.(type) {
	case *authRequest:
		return r.ClientID, r.AuthAt, r.AMR
	case *refreshTokenRequest:
		return r.ClientID, r.AuthTime, r.AMR
	}
	return "", time.Time{}, nil
}
