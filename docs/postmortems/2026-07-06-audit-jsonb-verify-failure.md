# Postmortem: audit chain VerifyChain fails on Postgres (jsonb payload)

- Date found: 2026-07-06 (during tamper-proof audit Phase 2, by a real-Postgres e2e)
- Severity: High (the audit integrity guarantee was non-functional on production Postgres)
- Origin: Phase 1 (tamper-proof audit chain), commit `810e217`/`1dc3583`
- Fixed: `26d433f` (migration `000051`), merged to `dev` in `54df0ca`

## Summary

The tamper-proof audit log's `VerifyChain` recomputes each entry's HMAC over the
canonical JSON bytes stored in `mxid_audit_entry.payload` and compares to the
stored `entry_hash`. The `payload` column was declared `jsonb`. Postgres
**normalizes** jsonb on write/read-back — it reorders object keys and injects
whitespace — so the bytes read back differ from the compact, struct-ordered
bytes that were originally hashed. The recomputed hash therefore never matched,
and **every chain failed verification on Postgres**.

The whole point of Phase 1 (a verifiable, tamper-evident audit log) was silently
broken in the one environment that matters: production Postgres.

## Why it wasn't caught

All Phase 1 unit tests ran against **sqlite** (`glebarez/sqlite`). sqlite stores
the value verbatim (no jsonb normalization), so the round-trip preserved bytes
and every test passed. The bug was invisible to the entire unit suite and to
per-task + whole-branch code review — it only surfaces on a real Postgres
driver.

It was found by deliberately running an end-to-end integration test against a
throwaway Postgres database before merging Phase 2.

## Root cause

`jsonb` is a *normalized* storage type, not a byte-preserving one. Hashing bytes
and then storing them in jsonb violates the invariant "the bytes I hashed are
the bytes I can read back."

## Fix

`mxid_audit_entry.payload` changed `jsonb` → **`bytea`**:
- `bytea` round-trips the exact bytes verbatim (no normalization), so the
  recompute matches.
- The pg driver returns `bytea` as `[]byte`, which `json.RawMessage` scans
  (a `text` column returns a `string`, which `json.RawMessage` cannot `Scan`).
- Query JSON with `convert_from(payload,'UTF8')::jsonb` when needed.

Migration `000051_audit_entry_payload_bytea`. Model tag in
`internal/domain/audit/chainmodel.go`.

## Prevention

- Added a **gated Postgres e2e integration test**
  (`internal/domain/audit/e2e_postgres_test.go`, runs only when `MXID_E2E_DSN`
  points at a throwaway DB) that exercises capture → chain → verify → trigger on
  a real Postgres driver. This guards the regression.
- Lesson: **sqlite unit tests cannot catch driver/type-specific behavior**
  (jsonb normalization, numeric precision, collation). Any integrity or
  serialization guarantee that depends on exact bytes must be verified against
  the production driver, not just sqlite.
- General rule: never store hashed bytes in a normalizing column type. Use
  `bytea`/`text` for anything whose exact byte representation is
  security-relevant.
