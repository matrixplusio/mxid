package saml

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// miniredisClient spins up an in-process Redis server and returns a connected
// client. The server and client are cleaned up automatically when t ends.
func miniredisClient(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestSessionIndexStore_RecordGet(t *testing.T) {
	s := NewSessionIndexStore(miniredisClient(t))
	ref := SAMLSessionRef{SessionIndex: "idx-1", NameID: "user@x", SPEntityID: "sp-entity"}
	if err := s.Record(context.Background(), 5001, 1001, ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), 5001, 1001)
	if err != nil || len(got) != 1 || got[0].SessionIndex != "idx-1" {
		t.Fatalf("want stored ref, got %+v err=%v", got, err)
	}
}

func TestSessionIndexStore_GetMissing(t *testing.T) {
	s := NewSessionIndexStore(miniredisClient(t))
	got, err := s.Get(context.Background(), 9999, 8888)
	if err != nil {
		t.Fatalf("unexpected error on miss: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result on miss, got %+v", got)
	}
}

func TestSessionIndexStore_Delete(t *testing.T) {
	s := NewSessionIndexStore(miniredisClient(t))
	ref := SAMLSessionRef{SessionIndex: "idx-2", NameID: "user@y", SPEntityID: "sp-entity-2"}
	if err := s.Record(context.Background(), 5002, 1002, ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), 5002, 1002); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), 5002, 1002)
	if err != nil {
		t.Fatalf("unexpected error after delete: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty after delete, got %+v", got)
	}
}

func TestSessionIndexStore_Overwrite(t *testing.T) {
	s := NewSessionIndexStore(miniredisClient(t))
	ref1 := SAMLSessionRef{SessionIndex: "idx-old", NameID: "user@z", SPEntityID: "sp"}
	ref2 := SAMLSessionRef{SessionIndex: "idx-new", NameID: "user@z", SPEntityID: "sp"}
	if err := s.Record(context.Background(), 6001, 2001, ref1, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(context.Background(), 6001, 2001, ref2, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), 6001, 2001)
	if err != nil || len(got) != 1 || got[0].SessionIndex != "idx-new" {
		t.Fatalf("want overwritten ref, got %+v err=%v", got, err)
	}
}
