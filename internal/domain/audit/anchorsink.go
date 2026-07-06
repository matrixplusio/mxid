package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AnchorRecord is the payload written to an AnchorSink.
type AnchorRecord struct {
	TenantID   int64     `json:"tenant_id"`
	ChainClass string    `json:"chain_class"`
	FromSeq    int64     `json:"from_seq"`
	ToSeq      int64     `json:"to_seq"`
	MerkleRoot []byte    `json:"merkle_root"`
	Signature  []byte    `json:"signature"`
	KeyID      string    `json:"key_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// AnchorSink is where signed Merkle roots are durably written OUTSIDE the primary
// DB, so a signed root survives a DB compromise. FileSink is the CE default; a
// production deployment implements this against S3 Object Lock (WORM).
type AnchorSink interface {
	Put(ctx context.Context, rec AnchorRecord) (uri string, err error)
}

// FileSink appends one JSON line per record to a local file. Best-effort WORM
// (an on-host attacker could still edit it — production uses object-lock storage);
// its value is that the Ed25519 signature makes any edit detectable.
type FileSink struct {
	mu   sync.Mutex
	path string
}

func NewFileSink(path string) *FileSink { return &FileSink{path: path} }

func (s *FileSink) Put(_ context.Context, rec AnchorRecord) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("open anchor sink: %w", err)
	}
	defer f.Close()
	off, err := f.Seek(0, 2) // current end = this record's offset
	if err != nil {
		return "", err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return "", fmt.Errorf("append anchor: %w", err)
	}
	return fmt.Sprintf("file://%s#%d", s.path, off), nil
}
