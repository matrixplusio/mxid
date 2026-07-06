// internal/domain/audit/anchorer.go
package audit

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Anchorer summarizes the un-anchored tail of each chain into a signed Merkle
// root written to an external sink. Single-writer per process (run one).
type Anchorer struct {
	db     *gorm.DB
	priv   ed25519.PrivateKey
	keyID  string
	sink   AnchorSink
	idGen  *snowflake.Generator
	logger *zap.Logger
}

func NewAnchorer(db *gorm.DB, priv ed25519.PrivateKey, sink AnchorSink, idGen *snowflake.Generator, logger *zap.Logger) *Anchorer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Anchorer{db: db, priv: priv, keyID: KeyIDForPublic(pub), sink: sink, idGen: idGen, logger: logger}
}

// AnchorChain anchors entries with seq greater than the chain's last anchored
// to_seq. Returns nil if there is nothing new.
func (a *Anchorer) AnchorChain(ctx context.Context, tenantID int64, class string) (*AuditAnchor, error) {
	var lastTo int64
	row := a.db.WithContext(ctx).Model(&AuditAnchor{}).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Select("COALESCE(MAX(to_seq), 0)")
	if err := row.Scan(&lastTo).Error; err != nil {
		return nil, err
	}

	var entries []AuditEntry
	if err := a.db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND seq > ?", tenantID, class, lastTo).
		Order("seq asc").Find(&entries).Error; err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	leaves := make([][]byte, len(entries))
	for i := range entries {
		leaves[i] = entries[i].EntryHash
	}
	root := MerkleRoot(leaves)
	fromSeq := entries[0].Seq
	toSeq := entries[len(entries)-1].Seq
	sig := SignAnchor(a.priv, tenantID, class, fromSeq, toSeq, root)

	uri, err := a.sink.Put(ctx, AnchorRecord{
		TenantID: tenantID, ChainClass: class, FromSeq: fromSeq, ToSeq: toSeq,
		MerkleRoot: root, Signature: sig, KeyID: a.keyID, CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, err // sink failure -> no DB record, retried next tick
	}

	anchor := &AuditAnchor{
		ID: a.idGen.Generate(), TenantID: tenantID, ChainClass: class,
		FromSeq: fromSeq, ToSeq: toSeq, MerkleRoot: root, Signature: sig,
		KeyID: a.keyID, ExternalURI: uri, CreatedAt: time.Now().UTC(),
	}
	if err := a.db.WithContext(ctx).Create(anchor).Error; err != nil {
		return nil, err
	}
	return anchor, nil
}

// AnchorAll anchors every chain that has a head. Returns the number of new anchors.
func (a *Anchorer) AnchorAll(ctx context.Context) (int, error) {
	var heads []ChainHead
	if err := a.db.WithContext(ctx).Find(&heads).Error; err != nil {
		return 0, err
	}
	var n int
	for _, h := range heads {
		got, err := a.AnchorChain(ctx, h.TenantID, h.ChainClass)
		if err != nil {
			return n, err
		}
		if got != nil {
			n++
		}
	}
	return n, nil
}

// Run ticks AnchorAll every interval until ctx is cancelled. Single-writer:
// run exactly one of these per process (mirrors Chainer.Run's invariant).
func (a *Anchorer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := a.AnchorAll(ctx); err != nil {
			a.logger.Warn("audit anchorer: batch failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
