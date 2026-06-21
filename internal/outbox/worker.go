package outbox

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Handler processes one message of a given Kind. Returning an error reschedules
// the message with backoff (or dead-letters it once attempts are exhausted);
// returning nil marks it done. Handlers must be idempotent — at-least-once
// delivery means a message can be retried after a crash mid-processing.
type Handler func(ctx context.Context, msg *Message) error

// Worker polls the outbox and dispatches due messages to registered handlers.
type Worker struct {
	repo     Repository
	logger   *zap.Logger
	mu       sync.RWMutex
	handlers map[string]Handler

	interval time.Duration // poll cadence
	batch    int           // max messages claimed per tick
	lease    time.Duration // visibility timeout while a message is in flight
	baseBO   time.Duration // base backoff
	maxBO    time.Duration // backoff cap
}

// NewWorker builds a worker with sane defaults.
func NewWorker(repo Repository, logger *zap.Logger) *Worker {
	return &Worker{
		repo:     repo,
		logger:   logger,
		handlers: make(map[string]Handler),
		interval: 5 * time.Second,
		batch:    20,
		lease:    60 * time.Second,
		baseBO:   10 * time.Second,
		maxBO:    30 * time.Minute,
	}
}

// Register binds a handler to a message Kind. Not safe to call concurrently
// with Run, so register everything before starting the worker.
func (w *Worker) Register(kind string, h Handler) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handlers[kind] = h
}

// Run polls until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick claims and dispatches one batch. Exported-ish for tests via the package.
func (w *Worker) tick(ctx context.Context) {
	msgs, err := w.repo.Claim(ctx, w.batch, w.lease)
	if err != nil {
		w.logger.Warn("outbox: claim failed", zap.Error(err))
		return
	}
	for _, m := range msgs {
		w.dispatch(ctx, m)
	}
}

func (w *Worker) dispatch(ctx context.Context, m *Message) {
	w.mu.RLock()
	h, ok := w.handlers[m.Kind]
	w.mu.RUnlock()
	if !ok {
		// No handler registered (e.g. an EE consumer not built into this
		// binary). Back off rather than hot-loop; it may be wired on a peer.
		_ = w.repo.Fail(ctx, m, "no handler for kind "+m.Kind, w.backoff(m.Attempts))
		return
	}
	if err := h(ctx, m); err != nil {
		if ferr := w.repo.Fail(ctx, m, err.Error(), w.backoff(m.Attempts)); ferr != nil {
			w.logger.Warn("outbox: mark-fail failed", zap.Int64("id", m.ID), zap.Error(ferr))
		}
		return
	}
	if derr := w.repo.MarkDone(ctx, m.ID); derr != nil {
		w.logger.Warn("outbox: mark-done failed", zap.Int64("id", m.ID), zap.Error(derr))
	}
}

// backoff grows exponentially with the attempt count, capped. attempts is the
// number already made (>=1 by the time a message fails).
func (w *Worker) backoff(attempts int) time.Duration {
	d := w.baseBO
	for i := 1; i < attempts && d < w.maxBO; i++ {
		d *= 2
	}
	if d > w.maxBO {
		d = w.maxBO
	}
	return d
}
