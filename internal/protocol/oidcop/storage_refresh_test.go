package oidcop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &Storage{rdb: rdb, cfg: DefaultConfig()}
}

// TestRenewRefreshToken_InvalidOrExpired_IsInvalidGrant proves that a missing
// or expired refresh token on rotation surfaces as the zitadel/oidc sentinel
// oidc.ErrInvalidGrant, not a bare error. pkg/op/token.go's createTokens /
// CreateAccessToken pass storage.CreateAccessAndRefreshTokens's error straight
// through to oidc.DefaultToServerError (via RequestError) without wrapping —
// a bare error there would map to a 500 server_error instead of the correct
// 400 invalid_grant response.
func TestRenewRefreshToken_InvalidOrExpired_IsInvalidGrant(t *testing.T) {
	ctx := context.Background()

	t.Run("token not found", func(t *testing.T) {
		s := newTestStorage(t)

		err := s.renewRefreshToken(ctx, "nonexistent-token", "new-token", &accessToken{ID: "at1"})
		assertInvalidGrant(t, err)
	})

	t.Run("token expired", func(t *testing.T) {
		s := newTestStorage(t)

		rt := refreshToken{
			ID:         "old-token",
			Token:      "old-token",
			Expiration: time.Now().Add(-time.Minute), // already expired
		}
		if err := s.setJSON(ctx, kRefresh(rt.Token), &rt, time.Hour); err != nil {
			t.Fatalf("seed refresh token: %v", err)
		}

		err := s.renewRefreshToken(ctx, "old-token", "new-token", &accessToken{ID: "at1"})
		assertInvalidGrant(t, err)
	})
}

func assertInvalidGrant(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}

	var oidcErr *oidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected an *oidc.Error, got %T: %v", err, err)
	}
	if !errors.Is(oidcErr, oidc.ErrInvalidGrant()) {
		t.Fatalf("expected ErrorType=invalid_grant, got %q", oidcErr.ErrorType)
	}

	mapped := oidc.DefaultToServerError(err, err.Error())
	if mapped.ErrorType != oidc.InvalidGrant {
		t.Fatalf("DefaultToServerError mapped to %q, want %q", mapped.ErrorType, oidc.InvalidGrant)
	}
}
