package outbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// fakeRepo is an in-memory Repository for worker logic tests (the SKIP LOCKED
// claim SQL itself is exercised by integration tests against Postgres).
type fakeRepo struct {
	claim  []*Message
	done   []int64
	failed []failRec
	dead   []int64
}

type failRec struct {
	id      int64
	errMsg  string
	backoff time.Duration
}

func (f *fakeRepo) Enqueue(context.Context, *Message) error { return nil }
func (f *fakeRepo) EnqueueTx(*gorm.DB, *Message) error      { return nil }
func (f *fakeRepo) Claim(context.Context, int, time.Duration) ([]*Message, error) {
	c := f.claim
	f.claim = nil // one batch then empty
	return c, nil
}
func (f *fakeRepo) MarkDone(_ context.Context, id int64) error {
	f.done = append(f.done, id)
	return nil
}
func (f *fakeRepo) Fail(_ context.Context, msg *Message, errMsg string, backoff time.Duration) error {
	f.failed = append(f.failed, failRec{msg.ID, errMsg, backoff})
	if msg.Attempts >= msg.MaxAttempts {
		f.dead = append(f.dead, msg.ID)
	}
	return nil
}

func newWorker(r Repository) *Worker {
	return NewWorker(r, zap.NewNop())
}

func TestWorker_DispatchSuccess(t *testing.T) {
	r := &fakeRepo{claim: []*Message{{ID: 1, Kind: "k", Attempts: 1, MaxAttempts: 8}}}
	w := newWorker(r)
	w.Register("k", func(context.Context, *Message) error { return nil })
	w.tick(context.Background())
	if len(r.done) != 1 || r.done[0] != 1 {
		t.Fatalf("want MarkDone(1), got %v", r.done)
	}
	if len(r.failed) != 0 {
		t.Fatalf("unexpected failures: %v", r.failed)
	}
}

func TestWorker_HandlerErrorReschedules(t *testing.T) {
	r := &fakeRepo{claim: []*Message{{ID: 2, Kind: "k", Attempts: 1, MaxAttempts: 8}}}
	w := newWorker(r)
	w.Register("k", func(context.Context, *Message) error { return errors.New("boom") })
	w.tick(context.Background())
	if len(r.done) != 0 {
		t.Fatalf("must not mark done on error")
	}
	if len(r.failed) != 1 || r.failed[0].id != 2 || r.failed[0].backoff <= 0 {
		t.Fatalf("want one Fail with positive backoff, got %v", r.failed)
	}
	if len(r.dead) != 0 {
		t.Fatalf("must not dead-letter before max attempts")
	}
}

func TestWorker_DeadLettersAtMaxAttempts(t *testing.T) {
	r := &fakeRepo{claim: []*Message{{ID: 3, Kind: "k", Attempts: 8, MaxAttempts: 8}}}
	w := newWorker(r)
	w.Register("k", func(context.Context, *Message) error { return errors.New("still failing") })
	w.tick(context.Background())
	if len(r.dead) != 1 || r.dead[0] != 3 {
		t.Fatalf("want dead-letter of id 3, got %v", r.dead)
	}
}

func TestWorker_NoHandlerFails(t *testing.T) {
	r := &fakeRepo{claim: []*Message{{ID: 4, Kind: "unknown", Attempts: 1, MaxAttempts: 8}}}
	w := newWorker(r)
	w.tick(context.Background())
	if len(r.failed) != 1 {
		t.Fatalf("want Fail for unhandled kind, got %v", r.failed)
	}
	if len(r.done) != 0 {
		t.Fatalf("must not mark done for unhandled kind")
	}
}

func TestWorker_BackoffGrowsAndCaps(t *testing.T) {
	w := NewWorker(&fakeRepo{}, zap.NewNop())
	b1 := w.backoff(1)
	b2 := w.backoff(2)
	b3 := w.backoff(3)
	if !(b1 < b2 && b2 < b3) {
		t.Fatalf("backoff should grow: %v %v %v", b1, b2, b3)
	}
	if w.backoff(100) != w.maxBO {
		t.Fatalf("backoff should cap at %v, got %v", w.maxBO, w.backoff(100))
	}
}
