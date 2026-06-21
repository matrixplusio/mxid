// Package outbox is a transactional outbox: durable at-least-once delivery for
// side effects that must survive a crash (offboarding webhooks, later L2 SCIM
// pushes). Producers insert a Message — ideally in the same DB transaction as
// the state change it accompanies — and a Worker claims due rows with FOR
// UPDATE SKIP LOCKED, dispatches by Kind, and backs off / dead-letters on
// failure. See migrations/000043_outbox.up.sql.
package outbox

import (
	"encoding/json"
	"time"
)

// Message status values.
const (
	StatusPending = 0
	StatusDone    = 1
	StatusDead    = 2 // exhausted max_attempts; parked for inspection
)

// DefaultMaxAttempts bounds how many times a message is retried before it is
// dead-lettered.
const DefaultMaxAttempts = 8

// Message is one outbox row.
type Message struct {
	ID          int64           `gorm:"column:id;primaryKey"`
	TenantID    int64           `gorm:"column:tenant_id"`
	Kind        string          `gorm:"column:kind"`
	Payload     json.RawMessage `gorm:"column:payload;type:jsonb"`
	Status      int             `gorm:"column:status"`
	Attempts    int             `gorm:"column:attempts"`
	MaxAttempts int             `gorm:"column:max_attempts"`
	NextAttempt time.Time       `gorm:"column:next_attempt"`
	LastError   string          `gorm:"column:last_error"`
	CreatedAt   time.Time       `gorm:"column:created_at"`
	UpdatedAt   time.Time       `gorm:"column:updated_at"`
}

// TableName maps Message to its table.
func (Message) TableName() string { return "mxid_outbox" }
