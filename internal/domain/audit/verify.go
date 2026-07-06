package audit

import (
	"bytes"
	"context"

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
	Reason          string // "", "root mismatch", "bad signature", "missing entries", "anchor gap", "unknown key"
}

// VerifyAnchors recomputes each anchor's Merkle root from the stored entries and
// checks its Ed25519 signature. Detects tampering even by a holder of the HMAC
// chain key, provided they do not also hold the anchor private key.
//
// Anchors are always created as a contiguous cover of the chain starting at
// seq 1 ([1,3],[4,4],...), so this also enforces that coverage: a hole in the
// from_seq/to_seq sequence means an anchor row was deleted from
// mxid_audit_anchor. This is a cheap partial hardening, not full tamper
// detection for anchor deletion: if ALL anchors for a chain are deleted, or
// the tail of the chain is simply not yet anchored, this online check cannot
// tell the two apart — that requires diffing against the external sink
// (Phase 4 export).
func VerifyAnchors(ctx context.Context, db *gorm.DB, keys KeyRegistry, tenantID int64, class string) (AnchorVerifyResult, error) {
	var anchors []AuditAnchor
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("from_seq asc").Find(&anchors).Error; err != nil {
		return AnchorVerifyResult{}, err
	}
	var through int64
	var expectedFrom int64 = 1
	for i := range anchors {
		a := &anchors[i]
		if a.FromSeq != expectedFrom {
			return AnchorVerifyResult{OK: false, AnchoredThrough: expectedFrom - 1, FailFromSeq: a.FromSeq, Reason: "anchor gap"}, nil
		}
		pub, ok := keys.For(a.KeyID)
		if !ok {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "unknown key"}, nil
		}
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
		expectedFrom = a.ToSeq + 1
		through = a.ToSeq
	}
	return AnchorVerifyResult{OK: true, AnchoredThrough: through}, nil
}

// VerifyAnchorsWithSink runs the DB-side anchor verification, then cross-checks
// the external sink so that DELETING a DB anchor row (which VerifyAnchors alone
// reports only as a coverage gap, and not at all if the whole tail is dropped)
// is caught: the signed copy in the sink survives a DB compromise.
func VerifyAnchorsWithSink(ctx context.Context, db *gorm.DB, sink AnchorSink, keys KeyRegistry, tenantID int64, class string) (AnchorVerifyResult, error) {
	res, err := VerifyAnchors(ctx, db, keys, tenantID, class)
	if err != nil || !res.OK {
		return res, err
	}

	var dbAnchors []AuditAnchor
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("from_seq asc").Find(&dbAnchors).Error; err != nil {
		return AnchorVerifyResult{}, err
	}
	sinkAll, err := sink.List(ctx)
	if err != nil {
		return AnchorVerifyResult{}, err
	}
	// index the sink by (tenant,class,from,to)
	type k struct {
		t    int64
		c    string
		f, o int64
	}
	sinkIdx := make(map[k]AnchorRecord)
	for _, r := range sinkAll {
		if r.TenantID == tenantID && r.ChainClass == class {
			sinkIdx[k{r.TenantID, r.ChainClass, r.FromSeq, r.ToSeq}] = r
		}
	}
	dbIdx := make(map[k]bool)
	for i := range dbAnchors {
		a := &dbAnchors[i]
		dbIdx[k{a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq}] = true
		sr, ok := sinkIdx[k{a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq}]
		if !ok || !bytes.Equal(sr.MerkleRoot, a.MerkleRoot) || !bytes.Equal(sr.Signature, a.Signature) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: res.AnchoredThrough, FailFromSeq: a.FromSeq, Reason: "sink mismatch"}, nil
		}
	}
	// sink record not present in DB -> a DB anchor row was deleted
	for key := range sinkIdx {
		if !dbIdx[key] {
			return AnchorVerifyResult{OK: false, AnchoredThrough: res.AnchoredThrough, FailFromSeq: key.f, Reason: "sink mismatch"}, nil
		}
	}
	return res, nil
}
