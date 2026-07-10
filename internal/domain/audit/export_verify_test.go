package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"go.uber.org/zap"
)

func exportFixture(t *testing.T) (*ExportBundle, ed25519.PublicKey) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	an.AnchorChain(context.Background(), 7, "data")
	pub := priv.Public().(ed25519.PublicKey)
	b, err := BuildExport(context.Background(), db, NewKeyRegistry(pub), 7, "data", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	return b, pub
}

func TestVerifyExport_CleanProvesOffline(t *testing.T) {
	b, pub := exportFixture(t)
	res, err := VerifyExport(b, NewKeyRegistry(pub))
	if err != nil || !res.OK || res.AnchoredThrough != 3 {
		t.Fatalf("clean export should prove offline: %+v err=%v", res, err)
	}
}

func TestVerifyExport_TamperedEntryFails(t *testing.T) {
	b, pub := exportFixture(t)
	b.Entries[1].EntryHash = []byte("tamperedtamperedtamperedtampered") // change a hash in the anchored range
	res, _ := VerifyExport(b, NewKeyRegistry(pub))
	if res.OK {
		t.Fatal("tampered entry accepted offline")
	}
}

func TestVerifyExport_UntrustedKeyFails(t *testing.T) {
	b, _ := exportFixture(t)
	other := make([]byte, ed25519.SeedSize)
	other[0] = 77
	wrong := ed25519.NewKeyFromSeed(other).Public().(ed25519.PublicKey)
	res, _ := VerifyExport(b, NewKeyRegistry(wrong))
	if res.OK {
		t.Fatal("export verified against an untrusted key")
	}
}

func TestVerifyExport_ZeroAnchorsRejected(t *testing.T) {
	// An export with every anchor stripped proves nothing. Before the guard the
	// verify loop was simply skipped and OK:true returned.
	b, pub := exportFixture(t)
	b.Anchors = nil
	res, err := VerifyExport(b, NewKeyRegistry(pub))
	if err != nil {
		t.Fatalf("VerifyExport error: %v", err)
	}
	if res.OK {
		t.Fatal("anchorless bundle verified (proves nothing)")
	}
	if res.Reason != "no anchors" {
		t.Fatalf("expected reason 'no anchors', got %q", res.Reason)
	}
}

func TestVerifyExport_IncompleteCoverageRejected(t *testing.T) {
	// Anchors cover [1,3] but the bundle declares ToSeq=4 with a forged, unanchored
	// entry appended. Those entries fall outside every anchor range and are never
	// Merkle-checked, so before the coverage guard the bundle verified OK.
	b, pub := exportFixture(t)
	b.ToSeq = 4
	b.Entries = append(b.Entries, ExportEntry{Seq: 4, EntryHash: []byte("forged-unanchored-entry-000004")})
	res, err := VerifyExport(b, NewKeyRegistry(pub))
	if err != nil {
		t.Fatalf("VerifyExport error: %v", err)
	}
	if res.OK {
		t.Fatal("bundle with unanchored appended entries verified")
	}
	if res.Reason != "incomplete coverage" {
		t.Fatalf("expected reason 'incomplete coverage', got %q", res.Reason)
	}
}

func TestReadExport_RoundTrip(t *testing.T) {
	b, pub := exportFixture(t)
	dir := t.TempDir()
	if err := WriteExport(dir, b); err != nil {
		t.Fatalf("WriteExport: %v", err)
	}
	readBack, err := ReadExport(dir)
	if err != nil {
		t.Fatalf("ReadExport: %v", err)
	}
	if len(readBack.Entries) != len(b.Entries) {
		t.Fatalf("entry count mismatch: got %d want %d", len(readBack.Entries), len(b.Entries))
	}
	res, err := VerifyExport(readBack, NewKeyRegistry(pub))
	if err != nil || !res.OK || res.AnchoredThrough != 3 {
		t.Fatalf("disk round-tripped export should prove offline: %+v err=%v", res, err)
	}
}

func TestVerifyExport_FabricatedBundleRejected(t *testing.T) {
	// Attacker mints their own keypair and self-signs an entirely fabricated
	// bundle: internally consistent (signature verifies, Merkle root matches),
	// but signed by a key the verifier does not trust.
	attackerSeed := make([]byte, ed25519.SeedSize)
	for i := range attackerSeed {
		attackerSeed[i] = byte(200 + i)
	}
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)
	attackerKeyID := KeyIDForPublic(attackerPub)

	entries := []ExportEntry{
		{Seq: 1, EntryHash: []byte("fabricated-hash-000000000000001")},
		{Seq: 2, EntryHash: []byte("fabricated-hash-000000000000002")},
	}
	leaves := make([][]byte, 0, len(entries))
	for _, e := range entries {
		leaves = append(leaves, e.EntryHash)
	}
	root := MerkleRoot(leaves)
	sig := SignAnchor(attackerPriv, 7, "data", 1, 2, root)

	fakeBundle := &ExportBundle{
		TenantID:   7,
		ChainClass: "data",
		FromSeq:    1,
		ToSeq:      2,
		Entries:    entries,
		Anchors: []AuditAnchor{{
			TenantID:   7,
			ChainClass: "data",
			FromSeq:    1,
			ToSeq:      2,
			MerkleRoot: root,
			Signature:  sig,
			KeyID:      attackerKeyID,
		}},
		PubKeys: map[string]string{
			attackerKeyID: base64.StdEncoding.EncodeToString(attackerPub),
		},
	}

	// The real registry only trusts the legitimate key, never the attacker's.
	legitPriv := testKey(t)
	legitPub := legitPriv.Public().(ed25519.PublicKey)
	trusted := NewKeyRegistry(legitPub)

	res, err := VerifyExport(fakeBundle, trusted)
	if err != nil {
		t.Fatalf("VerifyExport returned error: %v", err)
	}
	if res.OK {
		t.Fatal("fabricated bundle self-certified against an untrusted registry")
	}
	if res.Reason != "untrusted key" {
		t.Fatalf("expected reason 'untrusted key', got %q", res.Reason)
	}
}
