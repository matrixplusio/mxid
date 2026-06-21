-- Per-app outbound provisioning config (Phase 1.2, L2). Holds the SCIM/admin
-- credentials a customer's IT granted for an app, so offboarding can deactivate
-- the downstream account (SCIM PATCH active=false) — not just cut SSO.
--
-- The schema is foundational and stays in CE (grandfathered); the actual SCIM
-- connector that consumes it lives ONLY in the EE binary and is license-gated
-- on `scim`. `enabled` defaults false: even with credentials configured, an
-- admin must explicitly turn it on, so MXID never touches a customer's
-- production directory by accident.
--
-- The token is AES-encrypted at rest (crypto master key); the API never echoes
-- it back. Tenant-scoped.

CREATE TABLE IF NOT EXISTS mxid_app_provisioning (
    app_id     BIGINT       PRIMARY KEY,
    tenant_id  BIGINT       NOT NULL,
    enabled    BOOLEAN      NOT NULL DEFAULT FALSE,
    connector  VARCHAR(32)  NOT NULL DEFAULT 'scim2', -- connector type; scim2 for now
    base_url   VARCHAR(512) NOT NULL DEFAULT '',       -- SCIM service provider base URL
    token_enc  TEXT         NOT NULL DEFAULT '',       -- AES-encrypted bearer token
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_app_provisioning_tenant ON mxid_app_provisioning(tenant_id);
