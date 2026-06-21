package authn

import (
	"context"
	"testing"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// A disabled account must reveal its status ONLY when the correct password is
// supplied — a wrong guess stays indistinguishable from any other failure, so
// no account-state leaks to a username enumerator. This is what stops an
// offboarded user (correct password) from being told "wrong password".
func TestAuthenticate_DisabledRevealedOnlyWithCorrectPassword(t *testing.T) {
	hash, _ := crypto.HashPassword("right-pw")
	q := &enumStubQuerier{
		known: "bob",
		user:  &UserAuth{ID: 9, Username: "bob", PasswordHash: hash, Status: statusDisabled},
	}
	p := NewLocalProvider(q, 0)
	ctx := context.Background()

	// Correct password against a disabled account → AuthDisabled.
	res, err := p.Authenticate(ctx, &AuthRequest{
		TenantID:    1,
		Credentials: map[string]string{"username": "bob", "password": "right-pw"},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if res.Status != AuthDisabled {
		t.Fatalf("correct password + disabled: want AuthDisabled, got %v", res.Status)
	}

	// Wrong password against a disabled account → AuthFailed (no state leak).
	res, err = p.Authenticate(ctx, &AuthRequest{
		TenantID:    1,
		Credentials: map[string]string{"username": "bob", "password": "wrong-pw"},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if res.Status != AuthFailed {
		t.Fatalf("wrong password + disabled: want AuthFailed (no leak), got %v", res.Status)
	}
}
