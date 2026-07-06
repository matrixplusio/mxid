package audit

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSink_AppendsJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.log")
	sink := NewFileSink(path)

	rec := AnchorRecord{TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 3,
		MerkleRoot: []byte{1, 2, 3}, Signature: []byte{4, 5}, KeyID: "k1", CreatedAt: time.Unix(0, 0).UTC()}
	uri, err := sink.Put(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "file://") {
		t.Fatalf("uri %q", uri)
	}
	// second append -> file has 2 lines
	if _, err := sink.Put(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(sc.Text(), `"tenant_id":7`) {
			n++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("want 2 appended lines, got %d", n)
	}
}

func TestFileSink_ListRoundTrips(t *testing.T) {
	dir := t.TempDir()
	sink := NewFileSink(dir + "/anchors.log")
	recs := []AnchorRecord{
		{TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 3, MerkleRoot: []byte{1}, Signature: []byte{2}, KeyID: "k1"},
		{TenantID: 7, ChainClass: "data", FromSeq: 4, ToSeq: 4, MerkleRoot: []byte{3}, Signature: []byte{4}, KeyID: "k1"},
	}
	for _, r := range recs {
		if _, err := sink.Put(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := sink.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].FromSeq != 1 || got[1].ToSeq != 4 {
		t.Fatalf("list round-trip wrong: %+v", got)
	}
}

func TestFileSink_ListEmptyWhenNoFile(t *testing.T) {
	sink := NewFileSink(t.TempDir() + "/none.log")
	got, err := sink.List(context.Background())
	if err != nil {
		t.Fatalf("missing file should be empty, not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestFileSink_CreatesMissingParentDir(t *testing.T) {
	// path whose parent dir does NOT exist yet (the production default is a
	// relative "data/..." that fails on a fresh deploy without this).
	dir := t.TempDir()
	path := dir + "/nested/sub/anchors.log"
	sink := NewFileSink(path)
	if _, err := sink.Put(context.Background(), AnchorRecord{TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 1, MerkleRoot: []byte{1}, Signature: []byte{2}, KeyID: "k1"}); err != nil {
		t.Fatalf("Put should create the missing parent dir, got: %v", err)
	}
	got, err := sink.List(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("list after auto-mkdir: n=%d err=%v", len(got), err)
	}
}
