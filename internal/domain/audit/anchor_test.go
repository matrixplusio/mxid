// internal/domain/audit/anchor_test.go
package audit

import (
	"crypto/ed25519"
	"testing"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestSignVerifyAnchor(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	root := []byte("rootrootrootrootrootrootrootroot")
	sig := SignAnchor(priv, 7, "data", 1, 10, root)

	a := &AuditAnchor{TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 10, MerkleRoot: root, Signature: sig}
	if !VerifyAnchorSig(pub, a) {
		t.Fatal("valid anchor sig rejected")
	}
	// tamper the range -> sig invalid (message binds the range)
	a.ToSeq = 11
	if VerifyAnchorSig(pub, a) {
		t.Fatal("range tamper accepted")
	}
	a.ToSeq = 10
	a.MerkleRoot = []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	if VerifyAnchorSig(pub, a) {
		t.Fatal("root tamper accepted")
	}
}

func TestKeyIDStable(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	id1 := KeyIDForPublic(pub)
	id2 := KeyIDForPublic(pub)
	if id1 != id2 || len(id1) != 16 {
		t.Fatal("key id unstable or wrong length")
	}
}
