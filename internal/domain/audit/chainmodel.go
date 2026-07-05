package audit

import (
	"encoding/json"
	"time"
)

// AuditPending is a captured-but-not-yet-chained event. Written by producers in
// their own transaction; drained FIFO by the Chainer.
type AuditPending struct {
	ID           int64           `gorm:"column:id;primaryKey"`
	TenantID     int64           `gorm:"column:tenant_id;not null"`
	ChainClass   string          `gorm:"column:chain_class;not null;size:16"`
	ActorID      int64           `gorm:"column:actor_id;not null"`
	ActorType    string          `gorm:"column:actor_type;not null;size:16"`
	EventType    string          `gorm:"column:event_type;not null;size:64"`
	ResourceType string          `gorm:"column:resource_type;not null;size:32"`
	ResourceID   int64           `gorm:"column:resource_id;not null"`
	Before       json.RawMessage `gorm:"column:before;type:jsonb"`
	After        json.RawMessage `gorm:"column:after;type:jsonb"`
	IP           string          `gorm:"column:ip;not null;size:64"`
	UserAgent    string          `gorm:"column:user_agent;not null;size:512"`
	SessionID    string          `gorm:"column:session_id;not null;size:128"`
	Detail       json.RawMessage `gorm:"column:detail;type:jsonb;default:'{}'"`
	OccurredAt   time.Time       `gorm:"column:occurred_at;not null"`
}

func (AuditPending) TableName() string { return "mxid_audit_pending" }

// AuditEntry is a chained, append-only audit record.
type AuditEntry struct {
	TenantID   int64           `gorm:"column:tenant_id;primaryKey"`
	ChainClass string          `gorm:"column:chain_class;primaryKey;size:16"`
	Seq        int64           `gorm:"column:seq;primaryKey"`
	PrevHash   []byte          `gorm:"column:prev_hash;not null"`
	EntryHash  []byte          `gorm:"column:entry_hash;not null"`
	KeyID      string          `gorm:"column:key_id;not null;size:64"`
	Payload    json.RawMessage `gorm:"column:payload;type:jsonb;not null"`
	Imported   bool            `gorm:"column:imported;not null"`
	CreatedAt  time.Time       `gorm:"column:created_at;not null"`
}

func (AuditEntry) TableName() string { return "mxid_audit_entry" }

// ChainHead is the mutable tip of one (tenant_id, chain_class) chain.
type ChainHead struct {
	TenantID      int64     `gorm:"column:tenant_id;primaryKey"`
	ChainClass    string    `gorm:"column:chain_class;primaryKey;size:16"`
	LastSeq       int64     `gorm:"column:last_seq;not null"`
	LastEntryHash []byte    `gorm:"column:last_entry_hash;not null"`
	UpdatedAt     time.Time `gorm:"column:updated_at;not null"`
}

func (ChainHead) TableName() string { return "mxid_audit_chain_head" }
