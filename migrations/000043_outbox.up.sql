-- Transactional outbox (Phase 1.2 foundation). Durable at-least-once delivery
-- for side effects that must NOT be lost on a crash — the offboarding webhook
-- to a customer's IT/HR system, and (later) L2 SCIM deprovision pushes. The
-- in-memory event bus is at-most-once (a process restart drops in-flight
-- handlers); a security action like "tell IT to close this account" can't ride
-- that.
--
-- A producer INSERTs a row (ideally in the same DB transaction as the state
-- change it accompanies, so the job is never half-committed). A worker claims
-- due rows with FOR UPDATE SKIP LOCKED — safe across replicas with no leader
-- election — dispatches by `kind`, and on failure backs off via next_attempt
-- until max_attempts, then parks the row as dead (status=2) for inspection.

CREATE TABLE IF NOT EXISTS mxid_outbox (
    id           BIGINT       PRIMARY KEY,
    tenant_id    BIGINT       NOT NULL DEFAULT 0,
    kind         VARCHAR(64)  NOT NULL,                 -- dispatch key, e.g. "offboarding.webhook"
    payload      JSONB        NOT NULL DEFAULT '{}',
    status       SMALLINT     NOT NULL DEFAULT 0,       -- 0 pending, 1 done, 2 dead
    attempts     INT          NOT NULL DEFAULT 0,
    max_attempts INT          NOT NULL DEFAULT 8,
    next_attempt TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_error   TEXT         NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Claim index: the worker only ever scans due, pending rows.
CREATE INDEX IF NOT EXISTS idx_outbox_claim ON mxid_outbox(next_attempt) WHERE status = 0;
