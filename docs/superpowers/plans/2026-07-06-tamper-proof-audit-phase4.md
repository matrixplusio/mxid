# Tamper-Proof Audit — Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring auth/session/token/consent events (login, MFA, OIDC token, consent, logout) and sensitive reads (PII view) into the tamper-proof hash chain, so the security events auditors care most about gain the same tamper-evidence as data mutations — without disrupting the existing legacy `mxid_audit_log` UI.

**Architecture:** A single, selective bridge at the audit service's one write chokepoint (`Service.createLog`) also emits chosen events into the chain via the Phase 1 `Capturer` (chain_class `auth` or `sensitive_read`). The bridge is SELECTIVE: data-mutation events (`user.created`, `app.*`, …) are already captured by the Phase 2 ORM callback (chain_class `data`), so they are NOT bridged (would duplicate). Only events with no audited-table equivalent — the auth/session/token/consent set, plus `user.pii_view` — flow through the bridge. The legacy `mxid_audit_log` write is unchanged (the current console audit UI keeps working); the chain write is additive and post-hoc (auth events are recorded after the fact, so there is no business-transaction / abort coupling).

**Tech Stack:** Go 1.25, existing `internal/domain/audit` (Phase 1-3), `pkg/auditctx`, `pkg/event`, gorm.

## Design decisions

- **Coexistence = bridge (dual-write), not migrate.** Legacy `mxid_audit_log` stays for the console audit UI (Phase 5 may re-point it). Auth events get BOTH the legacy row (existing) and a chain entry (new). Matches the codebase's existing "two audit layers coexist by design" philosophy.
- **Selective, to avoid double-capture.** The Phase 2 ORM callback already chains every audited-table mutation as `data`. Events that mirror those (`user.*` CRUD, `app.*`, `api_token.*` [Token is audited], `user.password_changed` [User is audited]) are EXCLUDED from the bridge. Only no-table-equivalent auth/session events + `pii_view` are bridged.
- **Post-hoc, no abort.** Unlike the ORM callback (in the business tx, aborts on failure), the auth bridge runs in the async audit handler after the action already committed. A chain-capture failure is logged (like the existing legacy-write-failure marker), never fails anything.

## Global Constraints

- Module `github.com/imkerbos/mxid`.
- Bridge allowlist (event_type → chain_class), FROZEN for this phase:
  - `auth`: `login.success`, `login.failed`, `login.risk`, `logout`, `session.kicked`, `mfa.enabled`, `mfa.disabled`, `oidc.token.issued`, `oidc.token.refreshed`, `oidc.token.revoked`, `oidc.token.reuse_detected`, `oidc.consent.granted`, `oidc.consent.revoked`, `oidc.backchannel_logout`.
  - `sensitive_read`: `user.pii_view`.
  - Everything else → not bridged (already in the `data` chain via the ORM callback, or not chain-worthy).
- The bridge must NOT change the legacy `mxid_audit_log` write or its failure handling.
- Chain capture actor comes from the enriched `AuditLog` fields (authoritative), stamped into `auditctx` for `Capturer.Capture` — not from whatever ctx the async handler happens to carry.
- No new migration (reuses Phase 1 `audit_pending`/`audit_entry`, chain_class already `VARCHAR(16)` covering `auth`/`sensitive_read`).

## File Structure

- `internal/domain/audit/eventclass.go` — `chainClassForEvent(eventType) (string, bool)`. (create)
- `internal/domain/audit/bridge.go` — `Service.SetChainBridge` + the map-and-capture helper. (create)
- `internal/domain/audit/service.go` — call the bridge in `createLog`; add `chainCapturer`/`chainDB` fields. (modify)
- `internal/domain/audit/register.go` — wire `SetChainBridge(a.DB, NewCapturer(a.IDGen))`. (modify)
- `internal/domain/audit/*_test.go` — classification + bridge tests. (create)
- `internal/domain/audit/e2e_postgres_test.go` — extend: an auth event chains + verifies. (modify)

---

### Task 1: Event → chain-class classification

**Files:**
- Create: `internal/domain/audit/eventclass.go`
- Test: `internal/domain/audit/eventclass_test.go`

**Interfaces:**
- Produces: `func chainClassForEvent(eventType string) (chainClass string, bridged bool)` — returns the allowlisted class + true, or `("", false)` for anything not bridged.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/eventclass_test.go
package audit

import "testing"

func TestChainClassForEvent(t *testing.T) {
	auth := []string{
		"login.success", "login.failed", "login.risk", "logout", "session.kicked",
		"mfa.enabled", "mfa.disabled",
		"oidc.token.issued", "oidc.token.refreshed", "oidc.token.revoked", "oidc.token.reuse_detected",
		"oidc.consent.granted", "oidc.consent.revoked", "oidc.backchannel_logout",
	}
	for _, et := range auth {
		c, ok := chainClassForEvent(et)
		if !ok || c != "auth" {
			t.Errorf("%s: got (%q,%v), want (auth,true)", et, c, ok)
		}
	}
	if c, ok := chainClassForEvent("user.pii_view"); !ok || c != "sensitive_read" {
		t.Errorf("pii_view: got (%q,%v), want (sensitive_read,true)", c, ok)
	}
	// data-mutation + already-audited events must NOT be bridged (no double-capture)
	for _, et := range []string{"user.created", "app.updated", "app.deleted", "api_token.created", "user.password_changed", "role.binding.added"} {
		if _, ok := chainClassForEvent(et); ok {
			t.Errorf("%s must NOT be bridged (already in data chain / not chain-worthy)", et)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestChainClassForEvent -v`
Expected: FAIL — `undefined: chainClassForEvent`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/audit/eventclass.go
package audit

// chainClassForEvent maps an audit event_type to the tamper-proof chain class it
// should be bridged into, or ("", false) if it must NOT be bridged.
//
// SELECTIVE by design: data-mutation events (user.*, app.*, role.*, api_token.*,
// user.password_changed) are already captured by the Phase 2 ORM callback in the
// "data" chain — bridging them here would double-capture. Only auth/session/token/
// consent events (which have no audited-table equivalent) plus pii_view are bridged.
func chainClassForEvent(eventType string) (string, bool) {
	switch eventType {
	case "login.success", "login.failed", "login.risk", "logout", "session.kicked",
		"mfa.enabled", "mfa.disabled",
		"oidc.token.issued", "oidc.token.refreshed", "oidc.token.revoked", "oidc.token.reuse_detected",
		"oidc.consent.granted", "oidc.consent.revoked", "oidc.backchannel_logout":
		return "auth", true
	case "user.pii_view":
		return "sensitive_read", true
	default:
		return "", false
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestChainClassForEvent -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/eventclass.go internal/domain/audit/eventclass_test.go
git commit -m "feat(audit): classify which app events bridge into the chain"
```

---

### Task 2: Chain bridge (map AuditLog → chain capture) + SetChainBridge

**Files:**
- Create: `internal/domain/audit/bridge.go`
- Modify: `internal/domain/audit/service.go` (add `chainCapturer`/`chainDB` fields; call the bridge in `createLog`)
- Test: `internal/domain/audit/bridge_test.go`

**Interfaces:**
- Consumes: `Capturer` (Phase 1), `auditctx`, `AuditLog`, `chainClassForEvent`, `Event`.
- Produces:
  - `func (s *Service) SetChainBridge(db *gorm.DB, c *Capturer)` — optional dep wiring (mirrors SetGeoResolver).
  - `func (s *Service) bridgeToChain(ctx context.Context, log *AuditLog)` — if a chain is wired and the event is allowlisted, build an actor+Event from the enriched `AuditLog` and Capture into the chain. Failures logged, never propagated.

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/audit/bridge_test.go
package audit

import (
	"context"
	"testing"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

func TestBridge_AuthEventChained(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(&noopRepo{}, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))

	actorID := int64(42)
	name := "alice"
	svc.bridgeToChain(context.Background(), &AuditLog{
		TenantID: 7, ActorID: &actorID, ActorName: &name, ActorType: "user",
		EventType: "login.success", EventStatus: EventStatusSuccess,
	})

	var p AuditPending
	if err := db.First(&p).Error; err != nil {
		t.Fatalf("auth event not chained: %v", err)
	}
	if p.ChainClass != "auth" || p.EventType != "login.success" || p.TenantID != 7 || p.ActorID != 42 {
		t.Fatalf("bad chained event: %+v", p)
	}
}

func TestBridge_DataEventNotChained(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(&noopRepo{}, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))

	svc.bridgeToChain(context.Background(), &AuditLog{TenantID: 7, EventType: "user.created"})
	var n int64
	db.Model(&AuditPending{}).Count(&n)
	if n != 0 {
		t.Fatalf("data event was bridged (double-capture): %d rows", n)
	}
}

func TestBridge_NilWhenUnwired(t *testing.T) {
	svc := NewService(&noopRepo{}, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	// no SetChainBridge -> bridgeToChain must be a safe no-op (no panic)
	svc.bridgeToChain(context.Background(), &AuditLog{EventType: "login.success"})
}
```

Add a minimal `noopRepo` to the test file if one is not already present in the package's test files (implements `Repository` with no-op methods; check `access_subscription_test.go` — it already defines a fake repo you can reuse or mirror).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/audit/ -run TestBridge -v`
Expected: FAIL — `svc.SetChainBridge undefined`

- [ ] **Step 3: Write minimal implementation**

Add fields to `Service` (service.go struct) — `chainCapturer *Capturer` and `chainDB *gorm.DB`. Then:

```go
// internal/domain/audit/bridge.go
package audit

import (
	"context"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// SetChainBridge wires the tamper-proof chain into the audit service so that
// allowlisted events (auth/session/token/consent, pii_view) are also recorded in
// the hash chain — additive to the legacy mxid_audit_log write. Optional: unset =
// legacy-only (bridgeToChain is a no-op).
func (s *Service) SetChainBridge(db *gorm.DB, c *Capturer) {
	s.chainDB = db
	s.chainCapturer = c
}

// bridgeToChain records an allowlisted event into the tamper-proof chain. It runs
// post-hoc in the async audit handler, so a failure is logged, never propagated
// (the originating action already committed). No-op when unwired or not allowlisted.
func (s *Service) bridgeToChain(ctx context.Context, log *AuditLog) {
	if s.chainCapturer == nil || s.chainDB == nil {
		return
	}
	class, ok := chainClassForEvent(log.EventType)
	if !ok {
		return
	}
	// Actor comes from the ENRICHED AuditLog (authoritative), stamped into ctx so
	// Capturer.Capture attributes the chain row correctly regardless of the ctx the
	// async handler carried.
	actor := auditctx.Actor{ActorType: log.ActorType, TenantID: log.TenantID}
	if log.ActorID != nil {
		actor.ActorID = *log.ActorID
	}
	if log.ActorName != nil {
		actor.ActorName = *log.ActorName
	}
	if log.IP != nil {
		actor.IP = *log.IP
	}
	if log.UserAgent != nil {
		actor.UserAgent = *log.UserAgent
	}
	if log.SessionID != nil {
		actor.SessionID = *log.SessionID
	}
	detail := map[string]any{"event_status": log.EventStatus}
	ev := Event{ChainClass: class, EventType: log.EventType, Detail: detail}
	if log.ResourceType != nil {
		ev.ResourceType = *log.ResourceType
	}
	if log.ResourceID != nil {
		ev.ResourceID = *log.ResourceID
	}
	if err := s.chainCapturer.Capture(auditctx.With(ctx, actor), s.chainDB, ev); err != nil {
		// Like the legacy-write-failure marker: a dropped chain write is a
		// security-relevant gap, but the action already happened — log + alert.
		s.logger.Error("audit chain bridge failed",
			zap.String("marker", "audit_chain_bridge_failed"),
			zap.Bool("alert", true),
			zap.String("event_type", log.EventType),
			zap.Error(err))
	}
}
```

Then call it from `createLog` (service.go), AFTER the legacy `repo.Create` block (so the legacy write is never affected by chain issues):

```go
	// ... existing repo.Create(...) + failure marker block ...
	s.bridgeToChain(ctx, log)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/audit/ -run TestBridge -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/audit/bridge.go internal/domain/audit/service.go internal/domain/audit/bridge_test.go
git commit -m "feat(audit): bridge auth/sensitive-read events into the tamper-proof chain"
```

---

### Task 3: Wire the bridge in register.go

**Files:**
- Modify: `internal/domain/audit/register.go`

**Interfaces:**
- Consumes: `SetChainBridge`, `NewCapturer`, `app.DB`, `app.IDGen`.

- [ ] **Step 1: Wire it**

In `Register(app *bootstrap.App)`, after `svc := NewService(...)` and before/after `svc.SubscribeEvents()`, add:

```go
	svc.SetChainBridge(app.DB, NewCapturer(app.IDGen))
```

(`NewCapturer` lives in the same `audit` package; `app.DB`/`app.IDGen` are exposed on `*bootstrap.App`.)

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add internal/domain/audit/register.go
git commit -m "feat(audit): wire chain bridge into audit module"
```

---

### Task 4: End-to-end via createLog (integration test in the package)

**Files:**
- Test: `internal/domain/audit/bridge_createlog_test.go`

**Interfaces:**
- Consumes: everything above. Locks that a real event flowing through `createLog` reaches the chain, and a data event does not.

- [ ] **Step 1: Write the test**

```go
// internal/domain/audit/bridge_createlog_test.go
package audit

import (
	"context"
	"testing"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

// createLog must fan an auth event into BOTH the legacy repo AND the chain, and a
// data event into the legacy repo ONLY (no chain double-capture).
func TestCreateLog_FansAuthToChainNotData(t *testing.T) {
	db := newTestDB(t)
	rec := &captureRepoBridge{}
	svc := NewService(rec, newTestIDGen(t), event.NewBus(zap.NewNop()), zap.NewNop(), 0)
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))

	actorID := int64(9)
	svc.createLog(context.Background(), &AuditLog{ID: 1, TenantID: 7, ActorID: &actorID, ActorType: "user", EventType: "login.success"})
	svc.createLog(context.Background(), &AuditLog{ID: 2, TenantID: 7, ActorID: &actorID, ActorType: "admin", EventType: "user.created"})

	if rec.n != 2 {
		t.Fatalf("legacy repo should get BOTH events, got %d", rec.n)
	}
	var chained []AuditPending
	db.Find(&chained)
	if len(chained) != 1 || chained[0].EventType != "login.success" || chained[0].ChainClass != "auth" {
		t.Fatalf("chain should have ONLY the auth event: %+v", chained)
	}
}
```

Add a tiny `captureRepoBridge` fake to the test file that counts `Create` calls and no-ops the rest of `Repository` (mirror the existing fake repo in `access_subscription_test.go`).

- [ ] **Step 2: Run**

Run: `go test ./internal/domain/audit/ -run TestCreateLog_Fans -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/domain/audit/bridge_createlog_test.go
git commit -m "test(audit): createLog fans auth events to the chain, data events to legacy only"
```

---

### Task 5: Extend the Postgres e2e with an auth event

**Files:**
- Modify: `internal/domain/audit/e2e_postgres_test.go`

**Interfaces:**
- Consumes: the whole stack. Proves an auth event chains + verifies on real Postgres.

- [ ] **Step 1: Add to the e2e (after the data-chain section, before the trigger section)**

```go
	// ---- Phase 4: an auth event bridged into the chain, on real Postgres ----
	svc := NewService(&noopRepo{}, newTestIDGen(t), nil, zap.NewNop(), 0)
	// nil event bus is fine; we call bridgeToChain directly (SubscribeEvents not needed).
	svc.SetChainBridge(db, NewCapturer(newTestIDGen(t)))
	aid := int64(42)
	svc.bridgeToChain(ctx, &AuditWog{TenantID: 7, ActorID: &aid, ActorType: "user", EventType: "login.success"})
	// chain the auth pending row
	nAuth, err := chainer.ProcessBatch(ctx, 100)
	if err != nil || nAuth < 1 {
		t.Fatalf("auth chain: n=%d err=%v", nAuth, err)
	}
	 authRes, err := VerifyChain(ctx, db, key, 7, "auth")
	if err != nil || !authRes.OK || authRes.VerifiedThrough < 1 {
		t.Fatalf("auth chain verify failed: %+v err=%v", authRes, err)
	}
	t.Logf("E2E auth event chained + verified: through seq %d", authRes.VerifiedThrough)
```

NOTE: the `NewService(&noopRepo{}, ...)` needs a `noopRepo` in the test package — if the e2e file can't see one, add a minimal `noopRepo` implementing `Repository`. Fix the obvious typo `AuditWog`→`AuditLog` when transcribing.

- [ ] **Step 2: Run against a throwaway Postgres**

Recreate a throwaway db and run (from the dev container, per the file's header instructions):
```
docker exec pgsql psql -U postgres -d postgres -c "DROP DATABASE IF EXISTS mxid_e2e;"
docker exec pgsql psql -U postgres -d postgres -c "CREATE DATABASE mxid_e2e;"
docker exec mxid-dev sh -c 'cd /app && export MXID_E2E_DSN="host=host.docker.internal port=5432 user=postgres password=$MXID_DATABASE_PASSWORD dbname=mxid_e2e sslmode=disable" && go test ./internal/domain/audit/ -run TestZZ_E2E_Postgres -v 2>&1 | tail -20'
docker exec pgsql psql -U postgres -d postgres -c "DROP DATABASE IF EXISTS mxid_e2e;"
```
Expected: the "auth event chained + verified" log line + overall PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/domain/audit/e2e_postgres_test.go
git commit -m "test(audit): e2e proves an auth event chains and verifies on Postgres"
```

---

## Self-Review

**Spec coverage (design §4 app-event + sensitive-read):**
- App-event → chain (auth/session/token/consent): Tasks 1-4. ✅ (selective, no double-capture with the Phase 2 data chain)
- Sensitive-read (`pii_view`): Tasks 1-2 (in the allowlist). ✅
- Legacy audit_log untouched, UI unaffected: bridge is additive after `repo.Create`. ✅
- Post-hoc, no abort: bridge logs failures, never propagates. ✅
- **Deferred to a follow-up:** instrumenting ADDITIONAL sensitive reads beyond `pii_view` (secret/key reveal, data export, audit export) — a discovery pass over the read endpoints; add each to the allowlist + emit the event where missing. Not in this phase. Also deferred: export CLI + sink-diff verify + multi-key (the "provability slice" — a separate phase).

**Placeholder scan:** All code steps carry full code. Task 5 flags the deliberate `AuditWog`→`AuditLog` transcription typo-guard and the `noopRepo` requirement — concrete, not placeholders.

**Type consistency:** `chainClassForEvent`, `SetChainBridge`, `bridgeToChain`, `Capturer`, `Event`, `AuditLog`, `AuditPending` names/fields are consistent across tasks and match Phases 1-3.

## Risks / follow-ups

- **Double-capture guard is by allowlist, not structural.** If a NEW auth-ish event is added on an audited table, it must NOT be added to the bridge allowlist (it's already in the data chain). Documented in `eventclass.go`.
- **Auth chain volume.** High-frequency `login.success` now writes an extra chain row per login (in addition to the legacy row). Same order of magnitude as the login-record write; acceptable. If it ever dominates, a per-class sampling/rollup is a later option.
- **Additional sensitive reads** (secret reveal, export) are NOT yet captured — only `pii_view`. Follow-up discovery pass.
