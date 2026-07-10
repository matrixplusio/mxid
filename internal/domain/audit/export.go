package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/gorm"
)

type ExportEntry struct {
	Seq       int64  `json:"seq"`
	PrevHash  []byte `json:"prev_hash"`
	EntryHash []byte `json:"entry_hash"`
	Payload   []byte `json:"payload"`
}

type ExportBundle struct {
	TenantID   int64             `json:"tenant_id"`
	ChainClass string            `json:"chain_class"`
	FromSeq    int64             `json:"from_seq"`
	ToSeq      int64             `json:"to_seq"`
	Entries    []ExportEntry     `json:"entries,omitempty"`
	Anchors    []AuditAnchor     `json:"anchors"`
	PubKeys    map[string]string `json:"pub_keys"` // key_id -> base64 raw ed25519 public key
}

// BuildExport gathers a self-contained, third-party-verifiable bundle: the chain
// entries in [fromSeq,toSeq], the signed anchors overlapping that range, and the
// public keys (by key_id) needed to verify them. The HMAC key is never included;
// verification rests entirely on the Ed25519 anchors.
//
// Caveat: [fromSeq,toSeq] should align to anchor boundaries. A range that splits
// an anchor's [FromSeq,ToSeq] fails VerifyExport closed ("missing entries" or
// "anchor gap") rather than partially proving it — export anchor-aligned ranges
// (or the full anchored range) for a clean proof.
func BuildExport(ctx context.Context, db *gorm.DB, keys KeyRegistry, tenantID int64, class string, fromSeq, toSeq int64) (*ExportBundle, error) {
	var entries []AuditEntry
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND seq >= ? AND seq <= ?", tenantID, class, fromSeq, toSeq).
		Order("seq asc").Find(&entries).Error; err != nil {
		return nil, err
	}
	b := &ExportBundle{TenantID: tenantID, ChainClass: class, FromSeq: fromSeq, ToSeq: toSeq, PubKeys: map[string]string{}}
	for _, e := range entries {
		b.Entries = append(b.Entries, ExportEntry{Seq: e.Seq, PrevHash: e.PrevHash, EntryHash: e.EntryHash, Payload: e.Payload})
	}
	// anchors overlapping [fromSeq,toSeq]
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND to_seq >= ? AND from_seq <= ?", tenantID, class, fromSeq, toSeq).
		Order("from_seq asc").Find(&b.Anchors).Error; err != nil {
		return nil, err
	}
	for _, a := range b.Anchors {
		if pub, ok := keys.For(a.KeyID); ok {
			b.PubKeys[a.KeyID] = base64.StdEncoding.EncodeToString(pub)
		}
	}
	return b, nil
}

// WriteExport writes entries.jsonl (one ExportEntry per line) + proof.json (the
// bundle without entries) to dir.
func WriteExport(dir string, b *ExportBundle) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ef, err := os.Create(filepath.Join(dir, "entries.jsonl"))
	if err != nil {
		return err
	}
	defer ef.Close()
	enc := json.NewEncoder(ef)
	for _, e := range b.Entries {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("write entry: %w", err)
		}
	}
	proof := *b
	proof.Entries = nil // entries live in entries.jsonl
	pf, err := os.Create(filepath.Join(dir, "proof.json"))
	if err != nil {
		return err
	}
	defer pf.Close()
	pe := json.NewEncoder(pf)
	pe.SetIndent("", "  ")
	return pe.Encode(proof)
}

// ReadExport reads entries.jsonl + proof.json from dir.
func ReadExport(dir string) (*ExportBundle, error) {
	pf, err := os.Open(filepath.Join(dir, "proof.json"))
	if err != nil {
		return nil, err
	}
	defer pf.Close()
	var b ExportBundle
	if err := json.NewDecoder(pf).Decode(&b); err != nil {
		return nil, fmt.Errorf("parse proof.json: %w", err)
	}
	ef, err := os.Open(filepath.Join(dir, "entries.jsonl"))
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	sc := bufio.NewScanner(ef)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e ExportEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("parse entry: %w", err)
		}
		b.Entries = append(b.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return &b, nil
}

// VerifyExport proves an export bundle offline — NO database, NO HMAC key. For
// each anchor: resolve+trust its key, verify the Ed25519 signature, and recompute
// the Merkle root over the EXPORTED entries in its range. Returns the highest
// anchored seq proven.
//
// This proves the anchored ENTRY-HASH chain is authentic and non-repudiable;
// it does NOT bind Payload to EntryHash (the HMAC key is not exported) —
// payload<->hash integrity is verified operator-side by VerifyChain. An
// offline reviewer who trusts this export alone cannot detect a doctored
// Payload sitting next to its original, correct EntryHash.
func VerifyExport(b *ExportBundle, trusted KeyRegistry) (AnchorVerifyResult, error) {
	// index exported entries by seq
	bySeq := make(map[int64]ExportEntry, len(b.Entries))
	for _, e := range b.Entries {
		bySeq[e.Seq] = e
	}
	var through int64
	expectedFrom := b.FromSeq
	for i := range b.Anchors {
		a := &b.Anchors[i]
		// the bundle's declared pubkey for this key_id must itself be trusted
		pubB64, ok := b.PubKeys[a.KeyID]
		if !ok {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "unknown key"}, nil
		}
		raw, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "unknown key"}, nil
		}
		pub := ed25519.PublicKey(raw)
		if tp, ok := trusted.For(a.KeyID); !ok || !tp.Equal(pub) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "untrusted key"}, nil
		}
		if a.FromSeq != expectedFrom {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "anchor gap"}, nil
		}
		if !VerifyAnchorSig(pub, a) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "bad signature"}, nil
		}
		leaves := make([][]byte, 0, a.ToSeq-a.FromSeq+1)
		for s := a.FromSeq; s <= a.ToSeq; s++ {
			e, ok := bySeq[s]
			if !ok {
				return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "missing entries"}, nil
			}
			leaves = append(leaves, e.EntryHash)
		}
		if !bytes.Equal(MerkleRoot(leaves), a.MerkleRoot) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "root mismatch"}, nil
		}
		through = a.ToSeq
		expectedFrom = a.ToSeq + 1
	}
	// A bundle with ZERO anchors proves nothing — without this guard the loop is
	// simply skipped and OK:true is returned, so an export with all anchors
	// stripped "verifies".
	if len(b.Anchors) == 0 {
		return AnchorVerifyResult{OK: false, AnchoredThrough: 0, FailFromSeq: b.FromSeq, Reason: "no anchors"}, nil
	}
	// The anchors must cover the WHOLE declared [FromSeq,ToSeq] range. Otherwise
	// an attacker can anchor [FromSeq,3], append forged entries 4..ToSeq (which
	// fall outside every anchor range and are never Merkle-checked) and still get
	// OK:true. Require the anchored high-water mark to reach ToSeq.
	if through < b.ToSeq {
		return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: through + 1, Reason: "incomplete coverage"}, nil
	}
	return AnchorVerifyResult{OK: true, AnchoredThrough: through}, nil
}
