package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Chainer drains mxid_audit_pending FIFO and appends to mxid_audit_entry,
// maintaining one HMAC hash chain per (tenant_id, chain_class). It is designed
// to run as a single goroutine (single writer) — do not run two concurrently
// against the same DB.
type Chainer struct {
	db     *gorm.DB
	key    []byte
	keyID  string
	logger *zap.Logger
}

func NewChainer(db *gorm.DB, key []byte, keyID string, logger *zap.Logger) *Chainer {
	return &Chainer{db: db, key: key, keyID: keyID, logger: logger}
}

// ProcessBatch chains up to limit pending rows (oldest id first) in one
// transaction. Returns the number of rows chained.
func (c *Chainer) ProcessBatch(ctx context.Context, limit int) (int, error) {
	var processed int
	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var pend []AuditPending
		if err := tx.Order("id asc").Limit(limit).Find(&pend).Error; err != nil {
			return err
		}
		for i := range pend {
			if err := c.chainOne(tx, &pend[i]); err != nil {
				return err
			}
			if err := tx.Delete(&AuditPending{}, "id = ?", pend[i].ID).Error; err != nil {
				return err
			}
			processed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return processed, nil
}

func (c *Chainer) chainOne(tx *gorm.DB, p *AuditPending) error {
	// Load or init the chain head for this (tenant, class).
	var head ChainHead
	err := tx.Where("tenant_id = ? AND chain_class = ?", p.TenantID, p.ChainClass).First(&head).Error
	if err == gorm.ErrRecordNotFound {
		head = ChainHead{TenantID: p.TenantID, ChainClass: p.ChainClass, LastSeq: 0, LastEntryHash: GenesisPrevHash}
	} else if err != nil {
		return err
	}

	seq := head.LastSeq + 1
	payload := ChainPayload{
		TenantID:     p.TenantID,
		ChainClass:   p.ChainClass,
		ActorID:      p.ActorID,
		ActorType:    p.ActorType,
		EventType:    p.EventType,
		ResourceType: p.ResourceType,
		ResourceID:   p.ResourceID,
		Before:       jsonToMap(p.Before),
		After:        jsonToMap(p.After),
		IP:           p.IP,
		UserAgent:    p.UserAgent,
		SessionID:    p.SessionID,
		Detail:       jsonToMap(p.Detail),
		OccurredAt:   p.OccurredAt.UTC().Format(time.RFC3339),
	}
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	entryHash := ComputeEntryHash(c.key, seq, head.LastEntryHash, canonical)

	entry := &AuditEntry{
		TenantID:   p.TenantID,
		ChainClass: p.ChainClass,
		Seq:        seq,
		PrevHash:   head.LastEntryHash,
		EntryHash:  entryHash,
		KeyID:      c.keyID,
		Payload:    canonical,
		Imported:   false,
		CreatedAt:  time.Now().UTC(),
	}
	if err := tx.Create(entry).Error; err != nil {
		return err
	}

	head.LastSeq = seq
	head.LastEntryHash = entryHash
	head.UpdatedAt = time.Now().UTC()
	return tx.Save(&head).Error
}

// Run ticks ProcessBatch every interval until ctx is cancelled. Single
// goroutine — this IS the single writer to the chain; do not start a second
// one against the same DB.
func (c *Chainer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := c.ProcessBatch(ctx, 100); err != nil {
			c.logger.Warn("audit chainer: batch failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func jsonToMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}
