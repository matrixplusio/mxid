// pkg/crypto/ed25519_test.go
package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestEd25519_SignVerifyRoundTrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv, err := Ed25519FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("anchor message")
	sig := Ed25519Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	if !Ed25519Verify(pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if Ed25519Verify(pub, []byte("tampered"), sig) {
		t.Fatal("tampered message accepted")
	}
}

func TestEd25519FromSeed_BadLen(t *testing.T) {
	if _, err := Ed25519FromSeed([]byte("short")); err == nil {
		t.Fatal("expected error for wrong seed length")
	}
}
