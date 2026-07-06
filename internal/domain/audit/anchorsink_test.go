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
	if n != 2 {
		t.Fatalf("want 2 appended lines, got %d", n)
	}
}
