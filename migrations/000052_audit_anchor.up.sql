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
