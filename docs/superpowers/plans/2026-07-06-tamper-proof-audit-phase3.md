# Tamper-Proof Audit — Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add external Merkle-root anchoring with Ed25519 signatures so the audit chain gains non-repudiation beyond the HMAC key: signed Merkle roots of chain segments are written to a pluggable sink outside the DB, and verification recomputes + checks them.

**Architecture:** An `Anchorer` periodically takes the un-anchored tail of each `(tenant_id, chain_class)` chain, builds a Merkle root over the entries' `entry_hash` leaves, signs `(tenant, class, from_seq, to_seq, root)` with an operator-provided Ed25519 key, writes the signed record to a pluggable `AnchorSink` (local append-only file by default; S3 Object Lock in production), and records it in `mxid_audit_anchor`. Verification recomputes each anchor's Merkle root from the stored entries and checks the signature — so tampering is caught even by someone who holds the HMAC key, as long as they don't also control the external sink + Ed25519 private key.

**Tech Stack:** Go 1.25, `crypto/ed25519` + `crypto/sha256` (stdlib), gorm, existing `internal/domain/audit` (Phase 1/2), `pkg/crypto`, `internal/bootstrap` config.

## Decisions (locked with the user 2026-07-06)

- **Sink:** pluggable `AnchorSink` interface. Ship a local append-only **FileSink** (CE default) + the `mxid_audit_anchor` DB index. S3 Object Lock is a documented production sink implementing the same interface (NOT built in this phase — no AWS SDK dependency added now).
- **Signing key:** operator-provided via env `MXID_CRYPTO_AUDIT_ANCHOR_KEY` (base64 of a 32-byte Ed25519 seed). NOT the license key (that lives only in the license-authority repo). Release-mode `validateSecrets` fails closed if anchoring is enabled without it. Public key is derivable and exportable for third-party offline verification.

## Global Constraints

- Module `github.com/imkerbos/mxid`. Snowflake `int64` IDs.
- **The Phase 2 append-only trigger blocks UPDATE/DELETE on `mxid_audit_entry`.** Anchoring MUST NOT update entries — it only INSERTs `mxid_audit_anchor` rows + writes the sink. (Range-based: the anchor references entries by `[from_seq, to_seq]`, it does not stamp entries.) Do not add an `anchored` column to `mxid_audit_entry`.
- Merkle scheme is FROZEN (verification depends on it): leaves = each entry's `entry_hash` (32 bytes) in ascending `seq` order; internal node = `SHA256(left ‖ right)`; an odd node count duplicates the last node at that level; a single leaf is its own root; an empty range has no anchor.
- Signed message is FROZEN: `"mxid-audit-anchor-v1" ‖ tenant_id(be8) ‖ uint16(len(class))(be2) ‖ class ‖ from_seq(be8) ‖ to_seq(be8) ‖ merkle_root(32)`. Ed25519 over these exact bytes. Binds the root to its range so a root can't be replayed for a different segment.
- Ed25519 key: `ed25519.NewKeyFromSeed(seed)` where seed is the 32 raw bytes decoded from the base64 env value. `key_id` = first 16 hex chars of `SHA256(publicKey)`.
- New migration is `000052` (latest is `000051`).
- Anchoring is single-writer per process, same as the chainer (runs in the same goroutine or a sibling); it reads committed entries, so it needs no business-tx coupling.

## File Structure

- `internal/domain/audit/merkle.go` — `MerkleRoot([][]byte) []byte`. (create)
- `pkg/crypto/ed25519.go` — `Ed25519FromSeed`, thin sign/verify helpers. (create)
- `internal/domain/audit/anchor.go` — `AnchorRecord`, canonical signed-message builder, `SignAnchor`/`VerifyAnchorSig`. (create)
- `internal/domain/audit/anchormodel.go` — `AuditAnchor` gorm model. (create)
- `internal/domain/audit/anchorsink.go` — `AnchorSink` interface + `FileSink`. (create)
- `internal/domain/audit/anchorer.go` — `Anchorer` (AnchorChain / AnchorAll / Run). (create)
- `internal/domain/audit/verify.go` — extend with `VerifyAnchors`. (modify)
- `internal/bootstrap/config.go` — anchor key + sink config + validateSecrets. (modify)
- `app/run.go` — start anchorer; verify-audit reports anchor status. (modify)
- `app/audit_verify.go` — include anchor verification in output. (modify)
- `migrations/000052_audit_anchor.up.sql` / `.down.sql`. (create)

---

### Task 1: Merkle root

**Files:**
- Create: `internal/domain/audit/merkle.go`
- Test: `internal/domain/audit/merkle_test.go`

**Interfaces:**
- Produces: `func MerkleRoot(leaves [][]byte) []byte` — nil for empty; the single leaf for len 1; else the SHA256 binary-tree root (duplicate-last on odd counts).

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/merkle_test.go
package audit

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func h2(a, b []byte) []byte {
	s := sha256.Sum256(append(append([]byte{}, a...), b...))
	return s[:]
}

func TestMerkleRoot_Empty(t *testing.T) {
	if MerkleRoot(nil) != nil {
		t.Fatal("empty should be nil")
	}
}

func TestMerkleRoot_Single(t *testing.T) {
	leaf := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !bytes.Equal(MerkleRoot([][]byte{leaf}), leaf) {
		t.Fatal("single leaf is its own root")
	}
}

func TestMerkleRoot_Two(t *testing.T) {
	a := []byte("a")
	b := []byte("b")
	got := MerkleRoot([][]byte{a, b})
	if !bytes.Equal(got, h2(a, b)) {
		t.Fatalf("two-leaf root mismatch")
	}
}

func TestMerkleRoot_Three_DuplicatesLast(t *testing.T) {
	a, b, c := []byte("a"), []byte("b"), []byte("c")
	// level1: h(a,b), h(c,c); root: h(h(a,b), h(c,c))
	want := h2(h2(a, b), h2(c, c))
	got := MerkleRoot([][]byte{a, b, c})
	if !bytes.Equal(got, want) {
		t.Fatalf("three-leaf duplicate-last root mismatch")
	}
}

func TestMerkleRoot_Deterministic(t *testing.T) {
	ls := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	if !bytes.Equal(MerkleRoot(ls), MerkleRoot(ls)) {
		t.Fatal("not deterministic")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestMerkleRoot -v`
Expected: FAIL — `undefined: MerkleRoot`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/merkle.go
package audit

import "crypto/sha256"

// MerkleRoot returns the SHA-256 Merkle root over leaves, in the given order.
// FROZEN scheme (verification depends on it): internal node = SHA256(left‖right);
// an odd node count duplicates the last node at that level; a single leaf is its
// own root; nil for an empty input.
func MerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1]) // duplicate last
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestMerkleRoot -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/merkle.go internal/domain/audit/merkle_test.go
git commit -m "feat(audit): Merkle root for anchor segments"
```

---

### Task 2: Ed25519 helpers in pkg/crypto

**Files:**
- Create: `pkg/crypto/ed25519.go`
- Test: `pkg/crypto/ed25519_test.go`

**Interfaces:**
- Produces:
  - `func Ed25519FromSeed(seed []byte) (ed25519.PrivateKey, error)` — errors if `len(seed) != ed25519.SeedSize` (32).
  - `func Ed25519Sign(priv ed25519.PrivateKey, msg []byte) []byte`
  - `func Ed25519Verify(pub ed25519.PublicKey, msg, sig []byte) bool`

- [ ] **Step 1: Write the failing test**

```go
// pkg/crypto/ed25519_test.go
package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestEd25519_SignVerifyRoundTrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv, err := Ed25519FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("anchor message")
	sig := Ed25519Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	if !Ed25519Verify(pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if Ed25519Verify(pub, []byte("tampered"), sig) {
		t.Fatal("tampered message accepted")
	}
}

func TestEd25519FromSeed_BadLen(t *testing.T) {
	if _, err := Ed25519FromSeed([]byte("short")); err == nil {
		t.Fatal("expected error for wrong seed length")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/crypto/ -run TestEd25519 -v`
Expected: FAIL — `undefined: Ed25519FromSeed`

- [ ] **Step 3: Write minimal implementation**

```go
// pkg/crypto/ed25519.go
package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// Ed25519FromSeed builds a private key from a 32-byte seed.
func Ed25519FromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Ed25519Sign signs msg with priv.
func Ed25519Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Ed25519Verify reports whether sig is a valid signature of msg by pub.
func Ed25519Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/crypto/ -run TestEd25519 -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/ed25519.go pkg/crypto/ed25519_test.go
git commit -m "feat(crypto): Ed25519 seed/sign/verify helpers for audit anchoring"
```

---

### Task 3: Migration 000052 + AuditAnchor model

**Files:**
- Create: `migrations/000052_audit_anchor.up.sql` / `.down.sql`
- Create: `internal/domain/audit/anchormodel.go`
- Test: `internal/domain/audit/anchormodel_test.go`

**Interfaces:**
- Produces: table `mxid_audit_anchor`; `AuditAnchor` struct with `TableName()`.

- [ ] **Step 1: Write the up migration**

```sql
-- migrations/000052_audit_anchor.up.sql
-- External anchoring index. Each row records that entries [from_seq, to_seq] of
-- a (tenant_id, chain_class) chain were summarized into merkle_root, signed with
-- Ed25519 (key_id), and written to an external sink (external_uri). Verification
-- recomputes the root from the entries and checks the signature. This table is a
-- LOCAL index; the signed root's tamper-evidence comes from the signature + the
-- external sink copy, not from this table (which is inside the DB blast radius).
CREATE TABLE IF NOT EXISTS mxid_audit_anchor (
    id           BIGINT       PRIMARY KEY,
    tenant_id    BIGINT       NOT NULL,
    chain_class  VARCHAR(16)  NOT NULL,
    from_seq     BIGINT       NOT NULL,
    to_seq       BIGINT       NOT NULL,
    merkle_root  BYTEA        NOT NULL,
    signature    BYTEA        NOT NULL,
    key_id       VARCHAR(64)  NOT NULL,
    external_uri TEXT         NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_anchor_chain
    ON mxid_audit_anchor(tenant_id, chain_class, to_seq);
```

- [ ] **Step 2: Write the down migration**

```sql
-- migrations/000052_audit_anchor.down.sql
DROP TABLE IF EXISTS mxid_audit_anchor;
```

- [ ] **Step 3: Write the model + failing test**

```go
// internal/domain/audit/anchormodel_test.go
package audit

import "testing"

func TestAuditAnchorTableName(t *testing.T) {
	if (AuditAnchor{}).TableName() != "mxid_audit_anchor" {
		t.Fatal("wrong table name")
	}
}
```

```go
// internal/domain/audit/anchormodel.go
package audit

import "time"

// AuditAnchor records one signed Merkle anchor over entries [FromSeq, ToSeq] of
// a (TenantID, ChainClass) chain.
type AuditAnchor struct {
	ID          int64     `gorm:"column:id;primaryKey"`
	TenantID    int64     `gorm:"column:tenant_id;not null"`
	ChainClass  string    `gorm:"column:chain_class;not null;size:16"`
	FromSeq     int64     `gorm:"column:from_seq;not null"`
	ToSeq       int64     `gorm:"column:to_seq;not null"`
	MerkleRoot  []byte    `gorm:"column:merkle_root;not null"`
	Signature   []byte    `gorm:"column:signature;not null"`
	KeyID       string    `gorm:"column:key_id;not null;size:64"`
	ExternalURI string    `gorm:"column:external_uri;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
}

func (AuditAnchor) TableName() string { return "mxid_audit_anchor" }
```

- [ ] **Step 4: Run + apply**

Run: `go test ./internal/domain/audit/ -run TestAuditAnchorTableName -v` → PASS.
Apply to dev pg: from the host, `migrate -path migrations -database "postgres://postgres:$PW@localhost:5432/mxid?sslmode=disable" up` (read `$PW` from `.env` without echoing). Confirm `mxid_audit_anchor` exists. (The container has no `migrate` binary; the host does at `/opt/homebrew/bin/migrate`.)

- [ ] **Step 5: Commit**

```bash
git add migrations/000052_audit_anchor.up.sql migrations/000052_audit_anchor.down.sql internal/domain/audit/anchormodel.go internal/domain/audit/anchormodel_test.go
git commit -m "feat(audit): audit_anchor table + model"
```

---

### Task 4: Anchor signing (canonical message + sign/verify)

**Files:**
- Create: `internal/domain/audit/anchor.go`
- Test: `internal/domain/audit/anchor_test.go`

**Interfaces:**
- Consumes: `crypto.Ed25519Sign/Verify`.
- Produces:
  - `func AnchorSigMessage(tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte`
  - `func KeyIDForPublic(pub ed25519.PublicKey) string` — first 16 hex of SHA256(pub).
  - `func SignAnchor(priv ed25519.PrivateKey, tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte`
  - `func VerifyAnchorSig(pub ed25519.PublicKey, a *AuditAnchor) bool`

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/anchor_test.go
package audit

import (
	"crypto/ed25519"
	"testing"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestSignVerifyAnchor(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	root := []byte("rootrootrootrootrootrootrootroot")
	sig := SignAnchor(priv, 7, "data", 1, 10, root)

	a := &AuditAnchor{TenantID: 7, ChainClass: "data", FromSeq: 1, ToSeq: 10, MerkleRoot: root, Signature: sig}
	if !VerifyAnchorSig(pub, a) {
		t.Fatal("valid anchor sig rejected")
	}
	// tamper the range -> sig invalid (message binds the range)
	a.ToSeq = 11
	if VerifyAnchorSig(pub, a) {
		t.Fatal("range tamper accepted")
	}
	a.ToSeq = 10
	a.MerkleRoot = []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	if VerifyAnchorSig(pub, a) {
		t.Fatal("root tamper accepted")
	}
}

func TestKeyIDStable(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	if KeyIDForPublic(pub) != KeyIDForPublic(pub) || len(KeyIDForPublic(pub)) != 16 {
		t.Fatal("key id unstable or wrong length")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run 'TestSignVerifyAnchor|TestKeyID' -v`
Expected: FAIL — `undefined: SignAnchor`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/anchor.go
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/imkerbos/mxid/pkg/crypto"
)

const anchorSigDomain = "mxid-audit-anchor-v1"

// AnchorSigMessage builds the FROZEN signed message binding a Merkle root to its
// chain and seq range: domain ‖ tenant(be8) ‖ len(class)(be2) ‖ class ‖
// from(be8) ‖ to(be8) ‖ root.
func AnchorSigMessage(tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte {
	buf := make([]byte, 0, len(anchorSigDomain)+8+2+len(class)+8+8+len(root))
	buf = append(buf, anchorSigDomain...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(tenantID))
	buf = append(buf, b8[:]...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], uint16(len(class)))
	buf = append(buf, b2[:]...)
	buf = append(buf, class...)
	binary.BigEndian.PutUint64(b8[:], uint64(fromSeq))
	buf = append(buf, b8[:]...)
	binary.BigEndian.PutUint64(b8[:], uint64(toSeq))
	buf = append(buf, b8[:]...)
	buf = append(buf, root...)
	return buf
}

// KeyIDForPublic is the first 16 hex chars of SHA256(pub) — a short stable id.
func KeyIDForPublic(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// SignAnchor signs the canonical anchor message.
func SignAnchor(priv ed25519.PrivateKey, tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte {
	return crypto.Ed25519Sign(priv, AnchorSigMessage(tenantID, class, fromSeq, toSeq, root))
}

// VerifyAnchorSig recomputes the canonical message from the anchor's fields and
// verifies its signature.
func VerifyAnchorSig(pub ed25519.PublicKey, a *AuditAnchor) bool {
	msg := AnchorSigMessage(a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq, a.MerkleRoot)
	return crypto.Ed25519Verify(pub, msg, a.Signature)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run 'TestSignVerifyAnchor|TestKeyID' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/anchor.go internal/domain/audit/anchor_test.go
git commit -m "feat(audit): range-bound Ed25519 anchor signing"
```

---

### Task 5: AnchorSink interface + FileSink

**Files:**
- Create: `internal/domain/audit/anchorsink.go`
- Test: `internal/domain/audit/anchorsink_test.go`

**Interfaces:**
- Produces:
  - `type AnchorSink interface { Put(ctx context.Context, rec AnchorRecord) (uri string, err error) }`
  - `type AnchorRecord struct { TenantID int64; ChainClass string; FromSeq, ToSeq int64; MerkleRoot, Signature []byte; KeyID string; CreatedAt time.Time }`
  - `func NewFileSink(path string) *FileSink` — appends one JSON line per record to the file (create/append, 0600); `uri` = `file://<path>#<byteOffset>`.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/anchorsink_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestFileSink -v`
Expected: FAIL — `undefined: NewFileSink`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/anchorsink.go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestFileSink -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/anchorsink.go internal/domain/audit/anchorsink_test.go
git commit -m "feat(audit): AnchorSink interface + local FileSink"
```

---

### Task 6: Anchorer — build, sign, sink, persist (incremental)

**Files:**
- Create: `internal/domain/audit/anchorer.go`
- Test: `internal/domain/audit/anchorer_test.go`

**Interfaces:**
- Consumes: `AuditEntry`, `AuditAnchor`, `MerkleRoot`, `SignAnchor`, `KeyIDForPublic`, `AnchorSink`, `*snowflake.Generator`.
- Produces:
  - `type Anchorer struct { ... }`
  - `func NewAnchorer(db *gorm.DB, priv ed25519.PrivateKey, sink AnchorSink, idGen *snowflake.Generator, logger *zap.Logger) *Anchorer`
  - `func (a *Anchorer) AnchorChain(ctx, tenantID int64, class string) (*AuditAnchor, error)` — anchors entries with `seq > lastAnchoredToSeq` up to the chain head; returns nil if nothing new.
  - `func (a *Anchorer) AnchorAll(ctx) (int, error)` — anchors every chain head; returns count of new anchors.

**Behavior (tested):** `AnchorChain` finds `max(to_seq)` in `mxid_audit_anchor` for the chain (0 if none), selects entries with `seq > that` ordered by seq, builds `MerkleRoot` over their `entry_hash`, signs `(tenant, class, from=firstSeq, to=lastSeq, root)`, calls `sink.Put`, inserts an `AuditAnchor`. Idempotent: a second call with no new entries returns `(nil, nil)`.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/anchorer_test.go
package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func TestAnchorer_AnchorsAndIsIncremental(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	// chain 3 entries into (7,"data")
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)

	priv := testKey(t)
	sink := NewFileSink(t.TempDir() + "/a.log")
	an := NewAnchorer(db, priv, sink, gen, zap.NewNop())

	got, err := an.AnchorChain(context.Background(), 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.FromSeq != 1 || got.ToSeq != 3 {
		t.Fatalf("anchor range wrong: %+v", got)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !VerifyAnchorSig(pub, got) {
		t.Fatal("anchor sig invalid")
	}
	// second call: nothing new
	again, err := an.AnchorChain(context.Background(), 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if again != nil {
		t.Fatalf("expected no new anchor, got %+v", again)
	}
	// add one more entry -> incremental anchor from seq 4
	seedPending(t, db, gen, 7, "data", "e")
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	inc, err := an.AnchorChain(context.Background(), 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if inc == nil || inc.FromSeq != 4 || inc.ToSeq != 4 {
		t.Fatalf("incremental anchor wrong: %+v", inc)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestAnchorer -v`
Expected: FAIL — `undefined: NewAnchorer`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/anchorer.go
package audit

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Anchorer summarizes the un-anchored tail of each chain into a signed Merkle
// root written to an external sink. Single-writer per process (run one).
type Anchorer struct {
	db     *gorm.DB
	priv   ed25519.PrivateKey
	keyID  string
	sink   AnchorSink
	idGen  *snowflake.Generator
	logger *zap.Logger
}

func NewAnchorer(db *gorm.DB, priv ed25519.PrivateKey, sink AnchorSink, idGen *snowflake.Generator, logger *zap.Logger) *Anchorer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Anchorer{db: db, priv: priv, keyID: KeyIDForPublic(pub), sink: sink, idGen: idGen, logger: logger}
}

// AnchorChain anchors entries with seq greater than the chain's last anchored
// to_seq. Returns nil if there is nothing new.
func (a *Anchorer) AnchorChain(ctx context.Context, tenantID int64, class string) (*AuditAnchor, error) {
	var lastTo int64
	row := a.db.WithContext(ctx).Model(&AuditAnchor{}).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Select("COALESCE(MAX(to_seq), 0)")
	if err := row.Scan(&lastTo).Error; err != nil {
		return nil, err
	}

	var entries []AuditEntry
	if err := a.db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ? AND seq > ?", tenantID, class, lastTo).
		Order("seq asc").Find(&entries).Error; err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	leaves := make([][]byte, len(entries))
	for i := range entries {
		leaves[i] = entries[i].EntryHash
	}
	root := MerkleRoot(leaves)
	fromSeq := entries[0].Seq
	toSeq := entries[len(entries)-1].Seq
	sig := SignAnchor(a.priv, tenantID, class, fromSeq, toSeq, root)

	uri, err := a.sink.Put(ctx, AnchorRecord{
		TenantID: tenantID, ChainClass: class, FromSeq: fromSeq, ToSeq: toSeq,
		MerkleRoot: root, Signature: sig, KeyID: a.keyID, CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, err // sink failure -> no DB record, retried next tick
	}

	anchor := &AuditAnchor{
		ID: a.idGen.Generate(), TenantID: tenantID, ChainClass: class,
		FromSeq: fromSeq, ToSeq: toSeq, MerkleRoot: root, Signature: sig,
		KeyID: a.keyID, ExternalURI: uri, CreatedAt: time.Now().UTC(),
	}
	if err := a.db.WithContext(ctx).Create(anchor).Error; err != nil {
		return nil, err
	}
	return anchor, nil
}

// AnchorAll anchors every chain that has a head. Returns the number of new anchors.
func (a *Anchorer) AnchorAll(ctx context.Context) (int, error) {
	var heads []ChainHead
	if err := a.db.WithContext(ctx).Find(&heads).Error; err != nil {
		return 0, err
	}
	var n int
	for _, h := range heads {
		got, err := a.AnchorChain(ctx, h.TenantID, h.ChainClass)
		if err != nil {
			return n, err
		}
		if got != nil {
			n++
		}
	}
	return n, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestAnchorer -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/anchorer.go internal/domain/audit/anchorer_test.go
git commit -m "feat(audit): anchorer builds and persists signed Merkle anchors"
```

---

### Task 7: Verify anchors (recompute + signature check)

**Files:**
- Modify: `internal/domain/audit/verify.go`
- Test: `internal/domain/audit/verify_anchor_test.go`

**Interfaces:**
- Consumes: `AuditAnchor`, `AuditEntry`, `MerkleRoot`, `VerifyAnchorSig`.
- Produces:
  - `type AnchorVerifyResult struct { OK bool; AnchoredThrough int64; FailFromSeq int64; Reason string }`
  - `func VerifyAnchors(ctx context.Context, db *gorm.DB, pub ed25519.PublicKey, tenantID int64, class string) (AnchorVerifyResult, error)`

**Contract:** walks anchors in `from_seq` order; for each, (a) recompute `MerkleRoot` over `mxid_audit_entry` rows in `[from_seq, to_seq]` and require it equals the stored `merkle_root`; (b) `VerifyAnchorSig`. Any mismatch ⇒ `OK=false` with `Reason` in {`root mismatch`,`bad signature`,`missing entries`} and `FailFromSeq`. `AnchoredThrough` = highest `to_seq` verified clean.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/verify_anchor_test.go
package audit

import (
	"context"
	"crypto/ed25519"
	"testing"

	"go.uber.org/zap"
)

func anchoredDB(t *testing.T) (*gorm.DB, ed25519.PublicKey) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 3; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	priv := testKey(t)
	an := NewAnchorer(db, priv, NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())
	if _, err := an.AnchorChain(context.Background(), 7, "data"); err != nil {
		t.Fatal(err)
	}
	return db, priv.Public().(ed25519.PublicKey)
}

func TestVerifyAnchors_Clean(t *testing.T) {
	db, pub := anchoredDB(t)
	res, err := VerifyAnchors(context.Background(), db, pub, 7, "data")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.AnchoredThrough != 3 {
		t.Fatalf("clean anchors failed: %+v", res)
	}
}

func TestVerifyAnchors_TamperedEntryBreaksRoot(t *testing.T) {
	db, pub := anchoredDB(t)
	// tamper an entry's hash inside the anchored range -> recomputed root differs
	db.Model(&AuditEntry{}).Where("tenant_id = ? AND chain_class = ? AND seq = ?", 7, "data", 2).
		Update("entry_hash", []byte("tamperedtamperedtamperedtampered"))
	res, _ := VerifyAnchors(context.Background(), db, pub, 7, "data")
	if res.OK || res.Reason != "root mismatch" {
		t.Fatalf("tamper not caught: %+v", res)
	}
}

func TestVerifyAnchors_WrongKeyFailsSig(t *testing.T) {
	db, _ := anchoredDB(t)
	otherSeed := make([]byte, ed25519.SeedSize)
	otherSeed[0] = 99
	wrongPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	res, _ := VerifyAnchors(context.Background(), db, wrongPub, 7, "data")
	if res.OK || res.Reason != "bad signature" {
		t.Fatalf("wrong key not caught: %+v", res)
	}
}
```

Add imports to the test's block: `"gorm.io/gorm"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestVerifyAnchors -v`
Expected: FAIL — `undefined: VerifyAnchors`

- [ ] **Step 3: Write minimal implementation**

Append to `internal/domain/audit/verify.go` (add imports `crypto/ed25519`, `bytes` already present):

```go
// AnchorVerifyResult reports the outcome of checking a chain's anchors.
type AnchorVerifyResult struct {
	OK              bool
	AnchoredThrough int64
	FailFromSeq     int64
	Reason          string // "", "root mismatch", "bad signature", "missing entries"
}

// VerifyAnchors recomputes each anchor's Merkle root from the stored entries and
// checks its Ed25519 signature. Detects tampering even by a holder of the HMAC
// chain key, provided they do not also hold the anchor private key.
func VerifyAnchors(ctx context.Context, db *gorm.DB, pub ed25519.PublicKey, tenantID int64, class string) (AnchorVerifyResult, error) {
	var anchors []AuditAnchor
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND chain_class = ?", tenantID, class).
		Order("from_seq asc").Find(&anchors).Error; err != nil {
		return AnchorVerifyResult{}, err
	}
	var through int64
	for i := range anchors {
		a := &anchors[i]
		if !VerifyAnchorSig(pub, a) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "bad signature"}, nil
		}
		var entries []AuditEntry
		if err := db.WithContext(ctx).
			Where("tenant_id = ? AND chain_class = ? AND seq >= ? AND seq <= ?", tenantID, class, a.FromSeq, a.ToSeq).
			Order("seq asc").Find(&entries).Error; err != nil {
			return AnchorVerifyResult{}, err
		}
		if int64(len(entries)) != a.ToSeq-a.FromSeq+1 {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "missing entries"}, nil
		}
		leaves := make([][]byte, len(entries))
		for j := range entries {
			leaves[j] = entries[j].EntryHash
		}
		if !bytes.Equal(MerkleRoot(leaves), a.MerkleRoot) {
			return AnchorVerifyResult{OK: false, AnchoredThrough: through, FailFromSeq: a.FromSeq, Reason: "root mismatch"}, nil
		}
		through = a.ToSeq
	}
	return AnchorVerifyResult{OK: true, AnchoredThrough: through}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestVerifyAnchors -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/verify.go internal/domain/audit/verify_anchor_test.go
git commit -m "feat(audit): verify anchors recompute Merkle root and check signature"
```

---

### Task 8: Anchor config (key + sink) + validateSecrets

**Files:**
- Modify: `internal/bootstrap/config.go` (add `CryptoConfig.AuditAnchorKey`, an `AuditConfig`/sink path, validateSecrets)
- Modify: `.env.example`, `configs/config.yaml`
- Test: `internal/bootstrap/config_test.go` (add a release-mode anchor-key case)

**Interfaces:**
- Produces: `cfg.Crypto.AuditAnchorKey` (base64 ed25519 seed), `cfg.Audit.AnchorSinkPath` (file path, default e.g. `data/audit-anchors.log`), `cfg.Audit.AnchorEnabled` (bool).

- [ ] **Step 1: Add config fields + validateSecrets rule + test**

Mirror the existing `AuditChainKey` handling (Phase 1). Add to `CryptoConfig`: `AuditAnchorKey string` (env `MXID_CRYPTO_AUDIT_ANCHOR_KEY`). Add an `Audit` config section (or reuse an existing one) with `AnchorEnabled bool` (env `MXID_AUDIT_ANCHOR_ENABLED`, default true) and `AnchorSinkPath string` (env `MXID_AUDIT_ANCHOR_SINK_PATH`, default `data/audit-anchors.log`).

In `validateSecrets()` (release mode only), after the existing audit-chain-key check, add:

```go
	if c.Audit.AnchorEnabled {
		anchorKey := strings.TrimSpace(c.Crypto.AuditAnchorKey)
		if anchorKey == "" {
			return fmt.Errorf("crypto.audit_anchor_key not set but audit anchoring is enabled; export MXID_CRYPTO_AUDIT_ANCHOR_KEY=$(openssl rand -base64 32) or set MXID_AUDIT_ANCHOR_ENABLED=false")
		}
	}
```

Add a test `TestValidateSecrets_ReleaseRequiresAnchorKeyWhenEnabled` mirroring the existing anchor/KEK release tests: release + AnchorEnabled=true + empty AuditAnchorKey → error; set the key → passes. Add `AuditAnchorKey`/`Audit.AnchorEnabled` to the OTHER release-mode test fixtures so they stay green.

Add to `.env.example`: `MXID_CRYPTO_AUDIT_ANCHOR_KEY=` (empty) + `MXID_AUDIT_ANCHOR_ENABLED=true` + `MXID_AUDIT_ANCHOR_SINK_PATH=data/audit-anchors.log`, with a comment. Add matching keys to `configs/config.yaml`.

- [ ] **Step 2: Build + test**

Run: `go build ./... && go test ./internal/bootstrap/... -run TestValidateSecrets -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/bootstrap/config.go internal/bootstrap/config_test.go .env.example configs/config.yaml
git commit -m "feat(audit): audit anchor key + sink config, release fail-closed"
```

---

### Task 9: Anchorer run loop + app wiring

**Files:**
- Modify: `internal/domain/audit/anchorer.go` (add `Run`)
- Modify: `app/run.go` (construct + start the anchorer alongside the chainer)
- Test: `internal/domain/audit/anchorer_run_test.go`

**Interfaces:**
- Produces: `func (a *Anchorer) Run(ctx context.Context, interval time.Duration)` — ticks `AnchorAll` until ctx cancel.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/anchorer_run_test.go
package audit

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestAnchorer_RunAnchorsThenStops(t *testing.T) {
	db := newTestDB(t)
	gen := newTestIDGen(t)
	for i := 0; i < 2; i++ {
		seedPending(t, db, gen, 7, "data", "e")
	}
	NewChainer(db, []byte("k"), "default", zap.NewNop()).ProcessBatch(context.Background(), 100)
	an := NewAnchorer(db, testKey(t), NewFileSink(t.TempDir()+"/a.log"), gen, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { an.Run(ctx, 5*time.Millisecond); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
	var n int64
	db.Model(&AuditAnchor{}).Count(&n)
	if n < 1 {
		t.Fatalf("expected at least one anchor, got %d", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestAnchorer_Run -v`
Expected: FAIL — `an.Run undefined`

- [ ] **Step 3: Implement Run + wire**

Append to `anchorer.go` (add `"time"` import if needed):

```go
// Run ticks AnchorAll every interval until ctx is cancelled. Single goroutine.
func (a *Anchorer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := a.AnchorAll(ctx); err != nil {
			a.logger.Warn("audit anchorer: batch failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
```

In `app/run.go`, next to the chainer wiring (the `audit.NewChainer(...)` + `go chainer.Run(...)` block), when `a.Config.Audit.AnchorEnabled`: decode `a.Config.Crypto.AuditAnchorKey` (base64 → 32-byte seed → `crypto.Ed25519FromSeed`; on decode/length error, `a.Logger.Fatal`), build `sink := audit.NewFileSink(a.Config.Audit.AnchorSinkPath)`, `anchorer := audit.NewAnchorer(a.DB, priv, sink, a.IDGen, a.Logger)`, and `go anchorer.Run(context.Background(), 60*time.Second)`. (Anchoring cadence 60s default; it only writes when a chain has new entries.)

- [ ] **Step 4: Verify**

Run: `go test ./internal/domain/audit/ -run TestAnchorer -v && go build ./...`
Expected: PASS + build clean.

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/anchorer.go internal/domain/audit/anchorer_run_test.go app/run.go
git commit -m "feat(audit): run anchorer loop + wire into app startup"
```

---

### Task 10: verify-audit CLI reports anchor status

**Files:**
- Modify: `app/audit_verify.go`
- Test: covered by Task 7 (VerifyAnchors) + manual smoke.

**Interfaces:**
- Consumes: `audit.VerifyAnchors`, the anchor public key (derived from the configured seed).

- [ ] **Step 1: Extend runVerifyAudit**

After the existing per-chain `VerifyChain` line, when anchoring is configured, derive the anchor public key from `a.Config.Crypto.AuditAnchorKey` (base64 seed → `crypto.Ed25519FromSeed` → `.Public()`), call `audit.VerifyAnchors(ctx, a.DB, pub, h.TenantID, h.ChainClass)`, and print `  anchors: verified through seq %d — %s` (OK / `FAIL from seq %d (%s)`). A failed anchor verification makes the command exit non-zero (extend the existing `failed` flag).

```go
// inside the per-head loop, after the chain verify:
if anchorPub != nil {
	ares, err := audit.VerifyAnchors(ctx, a.DB, anchorPub, h.TenantID, h.ChainClass)
	if err != nil {
		return err
	}
	astatus := "OK"
	if !ares.OK {
		failed = true
		astatus = fmt.Sprintf("FAIL from seq %d (%s)", ares.FailFromSeq, ares.Reason)
	}
	fmt.Printf("  anchors tenant=%d class=%s: verified through seq %d — %s\n",
		h.TenantID, h.ChainClass, ares.AnchoredThrough, astatus)
}
```
Derive `anchorPub` once before the loop (nil if anchoring not configured / key absent — then skip anchor reporting).

- [ ] **Step 2: Build + dev-container smoke**

Run: `go build ./...`
Then in the dev container run `verify-audit` and confirm it prints chain + anchor lines without error (0 chains/anchors is fine). Capture output.

- [ ] **Step 3: Commit**

```bash
git add app/audit_verify.go
git commit -m "feat(audit): verify-audit reports anchor verification status"
```

---

## Self-Review

**Spec coverage (design §5 external anchoring + §12 open items):**
- Merkle root over entry hashes: Task 1. ✅
- Ed25519 signing, operator-provided key, range-bound message: Tasks 2, 4, 8. ✅
- Pluggable sink + FileSink default (S3 documented, deferred): Task 5. ✅
- audit_anchor table (range-based, no entry UPDATE → trigger-safe): Task 3. ✅
- Anchorer build/sign/persist incremental + run loop + wiring: Tasks 6, 9. ✅
- Verify extends to anchors (recompute + signature): Task 7. ✅
- CLI anchor status: Task 10. ✅
- **Deferred:** S3 Object Lock sink impl (interface ready); export CLI (Phase 4); UI badges (Phase 5); key rotation (key_id is recorded, but multi-key verify is future).

**Placeholder scan:** All code steps carry full code. Task 8/9/10 reference existing wiring points with the exact pattern to mirror (the Phase 1 chain-key + chainer wiring) — concrete, not placeholders.

**Type consistency:** `MerkleRoot`, `Ed25519FromSeed/Sign/Verify`, `AnchorSigMessage`, `SignAnchor`, `VerifyAnchorSig`, `KeyIDForPublic`, `AnchorSink`/`AnchorRecord`/`FileSink`, `Anchorer` (`AnchorChain`/`AnchorAll`/`Run`), `AuditAnchor`, `VerifyAnchors`/`AnchorVerifyResult` are consistent across tasks.

## Risks / follow-ups

- **FileSink is not true WORM** — an on-host attacker can edit it; the Ed25519 signature makes edits *detectable* but not *impossible*. Genuine non-repudiation needs the S3 Object Lock sink (or publishing signed roots externally). Documented; the interface is ready.
- **Anchor private key loss** = no new anchors verifiable; **key compromise + DB access** = forged anchors. Operator must protect + back up `MXID_CRYPTO_AUDIT_ANCHOR_KEY` like the KEK.
- **Trigger vs future retention:** anchors are append-only by convention (no trigger on `mxid_audit_anchor` yet); if entry retention/pruning is ever added, anchored ranges must be pruned in lockstep or verification will report "missing entries".
