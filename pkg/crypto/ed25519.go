// pkg/crypto/ed25519.go
package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// Ed25519FromSeed builds a private key from a 32-byte seed.
func Ed25519FromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Ed25519Sign signs msg with priv.
func Ed25519Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Ed25519Verify reports whether sig is a valid signature of msg by pub.
func Ed25519Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}
