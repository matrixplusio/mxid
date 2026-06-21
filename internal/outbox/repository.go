package outbox

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Repository persists and claims outbox messages.
type Repository interface {
	// Enqueue inserts a pending message. Defaults id/max_attempts/next_attempt
	// when unset so callers can pass a bare {Kind, Payload, TenantID}.
	Enqueue(ctx context.Context, msg *Message) error
	// EnqueueTx enqueues on a caller-supplied transaction, so the job is
	// committed atomically with the state change it accompanies (never half
	// written).
	EnqueueTx(tx *gorm.DB, msg *Message) error
	// Claim leases up to `limit` due, pending messages: it selects them FOR
	// UPDATE SKIP LOCKED, bumps attempts and pushes next_attempt out by `lease`
	// (a visibility timeout so a crashed worker's rows reappear), and returns
	// them. Safe to run concurrently across replicas.
	Claim(ctx context.Context, limit int, lease time.Duration) ([]*Message, error)
	// MarkDone marks a message delivered.
	MarkDone(ctx context.Context, id int64) error
	// Fail records an error and either reschedules (next_attempt = now+backoff)
	// or dead-letters the message once it has exhausted max_attempts.
	Fail(ctx context.Context, msg *Message, errMsg string, backoff time.Duration) error
}

type gormRepository struct {
	db    *gorm.DB
	idGen interface{ Generate() int64 }
}

// NewRepository builds the gorm-backed outbox repository. idGen mints message
// ids when a caller leaves Message.ID zero.
func NewRepository(db *gorm.DB, idGen interface{ Generate() int64 }) Repository {
	return &gormRepository{db: db, idGen: idGen}
}

func (r *gormRepository) defaults(msg *Message) {
	if msg.ID == 0 && r.idGen != nil {
		msg.ID = r.idGen.Generate()
	}
	if msg.MaxAttempts == 0 {
		msg.MaxAttempts = DefaultMaxAttempts
	}
	now := time.Now()
	if msg.NextAttempt.IsZero() {
		msg.NextAttempt = now
	}
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = now
	}
	msg.UpdatedAt = now
	if len(msg.Payload) == 0 {
		msg.Payload = []byte("{}")
	}
}

func (r *gormRepository) Enqueue(ctx context.Context, msg *Message) error {
	r.defaults(msg)
	return r.db.WithContext(ctx).Create(msg).Error
}

func (r *gormRepository) EnqueueTx(tx *gorm.DB, msg *Message) error {
	r.defaults(msg)
	return tx.Create(msg).Error
}

func (r *gormRepository) Claim(ctx context.Context, limit int, lease time.Duration) ([]*Message, error) {
	var msgs []*Message
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []int64
		if err := tx.Model(&Message{}).
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ? AND next_attempt <= ?", StatusPending, time.Now()).
			Order("next_attempt ASC").
			Limit(limit).
			Pluck("id", &ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		now := time.Now()
		if err := tx.Model(&Message{}).Where("id IN ?", ids).Updates(map[string]any{
			"attempts":     gorm.Expr("attempts + 1"),
			"next_attempt": now.Add(lease),
			"updated_at":   now,
		}).Error; err != nil {
			return err
		}
		return tx.Where("id IN ?", ids).Order("next_attempt ASC").Find(&msgs).Error
	})
	return msgs, err
}

func (r *gormRepository) MarkDone(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Model(&Message{}).Where("id = ?", id).Updates(map[string]any{
		"status":     StatusDone,
		"updated_at": time.Now(),
	}).Error
}

func (r *gormRepository) Fail(ctx context.Context, msg *Message, errMsg string, backoff time.Duration) error {
	now := time.Now()
	updates := map[string]any{"last_error": errMsg, "updated_at": now}
	// msg.Attempts already reflects this attempt (bumped at claim time).
	if msg.Attempts >= msg.MaxAttempts {
		updates["status"] = StatusDead
	} else {
		updates["next_attempt"] = now.Add(backoff)
	}
	return r.db.WithContext(ctx).Model(&Message{}).Where("id = ?", msg.ID).Updates(updates).Error
}
