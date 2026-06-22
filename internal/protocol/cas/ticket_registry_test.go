package cas

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

func TestServiceRegistry_RecordList(t *testing.T) {
	r := NewServiceRegistry(miniredisClient(t))
	if err := r.RecordService(context.Background(), 5001, 1001, "https://js.example/cas", "ST-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := r.ListServices(context.Background(), 5001, 1001)
	if err != nil || len(got) != 1 || got[0].ServiceURL != "https://js.example/cas" {
		t.Fatalf("want recorded service, got %+v err=%v", got, err)
	}
}

func TestServiceRegistry_ListMissing(t *testing.T) {
	r := NewServiceRegistry(miniredisClient(t))
	got, err := r.ListServices(context.Background(), 9999, 8888)
	if err != nil {
		t.Fatalf("unexpected error on miss: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result on miss, got %+v", got)
	}
}

func TestServiceRegistry_MultipleServices(t *testing.T) {
	r := NewServiceRegistry(miniredisClient(t))
	ctx := context.Background()
	if err := r.RecordService(ctx, 5002, 1002, "https://app1.example/cas", "ST-A", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordService(ctx, 5002, 1002, "https://app2.example/cas", "ST-B", time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := r.ListServices(ctx, 5002, 1002)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 services, got %d: %+v", len(got), got)
	}
}

func TestServiceRegistry_Clear(t *testing.T) {
	r := NewServiceRegistry(miniredisClient(t))
	ctx := context.Background()
	if err := r.RecordService(ctx, 6001, 2001, "https://js.example/cas", "ST-X", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.Clear(ctx, 6001, 2001); err != nil {
		t.Fatal(err)
	}
	got, err := r.ListServices(ctx, 6001, 2001)
	if err != nil {
		t.Fatalf("unexpected error after clear: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty after clear, got %+v", got)
	}
}

func TestServiceRegistry_TicketPreserved(t *testing.T) {
	r := NewServiceRegistry(miniredisClient(t))
	ctx := context.Background()
	if err := r.RecordService(ctx, 7001, 3001, "https://svc.example/", "ST-TICKET-99", time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := r.ListServices(ctx, 7001, 3001)
	if err != nil || len(got) != 1 || got[0].Ticket != "ST-TICKET-99" {
		t.Fatalf("want ticket preserved, got %+v err=%v", got, err)
	}
}
