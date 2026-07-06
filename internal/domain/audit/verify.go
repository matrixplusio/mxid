package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"

	"gorm.io/gorm"
)

// VerifyResult reports the outcome of walking one chain.
type VerifyResult struct {
	OK              bool
	VerifiedThrough int64  // highest seq verified clean
	FailSeq         int64  // seq where verification failed (0 if OK)
	Reason          string // "", "hash mismatch", "seq gap", "prev_hash mismatch"
}

// VerifyChain recomputes the HMAC chain for (tenantID, chainClass) from genesis
// and reports the first inconsistency. A gap in seq means a row was deleted.
func VerifyChain(ctx context.Context, db *gorm.DB, key []byte, tenantID int64, chainClass string) (VerifyResult, error) {
	var entries []AuditEntry
	err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, chainClass).
		Order("seq asc").
		Find(&entries).Error
	if err != nil {
		return VerifyResult{}, err
	}

	prev := GenesisPrevHash
	var expectedSeq int64 = 1
	for _, e := range entries {
		if e.Seq != expectedSeq {
			return VerifyResult{OK: false, VerifiedThrough: expectedSeq - 1, FailSeq: expectedSeq, Reason: "seq gap"}, nil
		}
		if !bytes.Equal(e.PrevHash, prev) {
			return VerifyResult{OK: false, VerifiedThrough: e.Seq - 1, FailSeq: e.Seq, Reason: "prev_hash mismatch"}, nil
		}
		want := ComputeEntryHash(key, e.Seq, prev, e.Payload)
		if !bytes.Equal(want, e.EntryHash) {
			return VerifyResult{OK: false, VerifiedThrough: e.Seq - 1, FailSeq: e.Seq, Reason: "hash mismatch"}, nil
		}
		prev = e.EntryHash
		expectedSeq++
	}
	return VerifyResult{OK: true, VerifiedThrough: expectedSeq - 1}, nil
}

// AnchorVerifyResult reports the outcome of checking a chain's anchors.
type AnchorVerifyResult struct {
	OK              bool
	AnchoredThrough int64
	FailFromSeq     int64
	Reason          string // "", "root mismatch", "bad signature", "missing entries"
}

// VerifyAnchors recomputes each anchor's Merkle root from the stored entries and
// checks its Ed25519 signature. Detects tampering even by a holder of the HMAC
// chain key, provided they do not also hold the anchor private key.
func VerifyAnchors(ctx context.Context, db *gorm.DB, pub ed25519.PublicKey, tenantID int64, class string) (AnchorVerifyResult, error) {
	var anchors []AuditAnchor
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("from_seq asc").Find(&anchors).Error; err != nil {
		return AnchorVerifyResult{}, err
	}
	var through int64
	for i := range anchors {
		a := &anchors[i]
		if !VerifyAnchorSig(pub, a) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "bad signature"}, nil
		}
		var entries []AuditEntry
		if err := db.WithContext(ctx).
			Where("tenant_id = ? AND chain_class = ? AND seq >= ? AND seq <= ?", tenantID, class, a.FromSeq, a.ToSeq).
			Order("seq asc").Find(&entries).Error; err != nil {
			return AnchorVerifyResult{}, err
		}
		if int64(len(entries)) != a.ToSeq-a.FromSeq+1 {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "missing entries"}, nil
		}
		leaves := make([][]byte, len(entries))
		for j := range entries {
			leaves[j] = entries[j].EntryHash
		}
		if !bytes.Equal(MerkleRoot(leaves), a.MerkleRoot) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "root mismatch"}, nil
		}
		through = a.ToSeq
	}
	return AnchorVerifyResult{OK: true, AnchoredThrough: through}, nil
}
