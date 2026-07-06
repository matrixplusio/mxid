package audit

import "time"

// AuditAnchor records one signed Merkle anchor over entries [FromSeq, ToSeq] of
// a (TenantID, ChainClass) chain.
type AuditAnchor struct {
	ID          int64     `gorm:"column:id;primaryKey"`
	TenantID    int64     `gorm:"column:tenant_id;not null"`
	ChainClass  string    `gorm:"column:chain_class;not null;size:16"`
	FromSeq     int64     `gorm:"column:from_seq;not null"`
	ToSeq       int64     `gorm:"column:to_seq;not null"`
	MerkleRoot  []byte    `gorm:"column:merkle_root;not null"`
	Signature   []byte    `gorm:"column:signature;not null"`
	KeyID       string    `gorm:"column:key_id;not null;size:64"`
	ExternalURI string    `gorm:"column:external_uri;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
}

func (AuditAnchor) TableName() string { return "mxid_audit_anchor" }
