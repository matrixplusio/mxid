package audit

import (
	"context"
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
