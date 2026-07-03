package oidcop

import (
	"context"
	"errors"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// fakeClientAppResolver is a minimal resolver.AppResolver stub for exercising
// ClientStore.resolve's error paths (unknown / non-OIDC / disabled client).
// Only GetAppByClientID is used by ClientStore.
type fakeClientAppResolver struct {
	resolver.AppResolver
	app *resolver.AppConfig
	err error
}

func (f *fakeClientAppResolver) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	return f.app, f.err
}

// TestClientStore_ResolveErrors_AreInvalidClient proves that unknown,
// non-OIDC, and disabled clients on the refresh_token grant surface as the
// zitadel/oidc sentinel oidc.ErrInvalidClient (not a bare error), since
// pkg/op/token_refresh.go's AuthorizeRefreshClient passes GetClientByClientID's
// error straight through to oidc.DefaultToServerError without wrapping it —
// an unwrapped bare error there would map to a 500 server_error instead of
// the correct invalid_client response.
func TestClientStore_ResolveErrors_AreInvalidClient(t *testing.T) {
	cases := []struct {
		name string
		app  *resolver.AppConfig
	}{
		{
			name: "unknown client",
			app:  nil,
		},
		{
			name: "non-OIDC client",
			app:  &resolver.AppConfig{ClientID: "c1", Protocol: "saml", Status: 1},
		},
		{
			name: "disabled client",
			app:  &resolver.AppConfig{ClientID: "c1", Protocol: "oidc", Status: 0},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewClientStore(&fakeClientAppResolver{app: tc.app}, func(string) string { return "" })

			_, err := store.ClientByID(context.Background(), "c1")
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}

			var oidcErr *oidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("expected an *oidc.Error, got %T: %v", err, err)
			}
			if !errors.Is(oidcErr, oidc.ErrInvalidClient()) {
				t.Fatalf("expected ErrorType=invalid_client, got %q", oidcErr.ErrorType)
			}

			// Confirm DefaultToServerError (what the vendor lib's RequestError
			// calls before status-mapping) preserves invalid_client rather
			// than falling back to server_error.
			mapped := oidc.DefaultToServerError(err, err.Error())
			if mapped.ErrorType != oidc.InvalidClient {
				t.Fatalf("DefaultToServerError mapped to %q, want %q", mapped.ErrorType, oidc.InvalidClient)
			}
		})
	}
}
