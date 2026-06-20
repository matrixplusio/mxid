package offboarding

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/event"
)

type fakeDisabler struct {
	called bool
	err    error
}

func (f *fakeDisabler) Disable(_ context.Context, _ int64) error {
	f.called = true
	return f.err
}

type fakeKiller struct {
	called bool
	killed int
	err    error
}

func (f *fakeKiller) KillAllByUser(_ context.Context, _ int64) (int, error) {
	f.called = true
	return f.killed, f.err
}

type fakeLookup struct{}

func (fakeLookup) Lookup(_ context.Context, _ int64) (string, int64, error) {
	return "alice", 100, nil
}

func newBus(t *testing.T) (*event.Bus, *[]event.Event) {
	t.Helper()
	bus := event.NewBus(zap.NewNop())
	var got []event.Event
	done := make(chan struct{}, 8)
	bus.Subscribe(event.UserOffboarded, func(_ context.Context, e event.Event) {
		got = append(got, e)
		done <- struct{}{}
	})
	return bus, &got
}

func TestOffboard_DisablesKillsAndAudits(t *testing.T) {
	d := &fakeDisabler{}
	k := &fakeKiller{killed: 3}
	bus, _ := newBus(t)
	svc := NewService(d, k, fakeLookup{}, bus, zap.NewNop())

	if err := svc.Offboard(context.Background(), 42); err != nil {
		t.Fatalf("Offboard() error = %v", err)
	}
	if !d.called {
		t.Error("expected user to be disabled")
	}
	if !k.called {
		t.Error("expected sessions to be killed")
	}
}

func TestOffboard_DisableFailureAborts(t *testing.T) {
	d := &fakeDisabler{err: errors.New("db down")}
	k := &fakeKiller{}
	bus, _ := newBus(t)
	svc := NewService(d, k, fakeLookup{}, bus, zap.NewNop())

	if err := svc.Offboard(context.Background(), 42); err == nil {
		t.Fatal("expected error when disable fails")
	}
	if k.called {
		t.Error("must not kill sessions when disable failed — account still active")
	}
}

func TestOffboard_SessionKillFailureIsNonFatal(t *testing.T) {
	d := &fakeDisabler{}
	k := &fakeKiller{err: errors.New("redis hiccup")}
	bus, _ := newBus(t)
	svc := NewService(d, k, fakeLookup{}, bus, zap.NewNop())

	// Account is already disabled — a session-store error must not fail the
	// offboard.
	if err := svc.Offboard(context.Background(), 42); err != nil {
		t.Fatalf("Offboard() should tolerate session-kill failure, got %v", err)
	}
}
