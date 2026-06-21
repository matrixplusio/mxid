-- Offboarding review trail (Phase 1.2, L3). When an admin offboards a user we
-- record what was done and, for every app the user could reach, an item the
-- admin can tick off after verifying downstream cleanup.
--
-- L1 apps (SSO-controlled) have their access cut automatically by the offboard
-- action itself; the items still surface so the admin has a complete checklist
-- and can confirm apps that also keep their own local accounts. The `tier`
-- column is forward-looking: L2 (SCIM auto-deprovision) and L3 (manual only)
-- refine it once those land.
--
-- Tenant-scoped: both tables carry tenant_id so the console panel and the
-- gorm tenant-isolation plugin filter per tenant.

CREATE TABLE IF NOT EXISTS mxid_offboarding_task (
    id              BIGINT       PRIMARY KEY,
    tenant_id       BIGINT       NOT NULL,
    user_id         BIGINT       NOT NULL,
    username        VARCHAR(128) NOT NULL DEFAULT '',
    status          SMALLINT     NOT NULL DEFAULT 0, -- 0 = open (items pending), 1 = resolved (all items done)
    sessions_killed INT          NOT NULL DEFAULT 0,
    item_count      INT          NOT NULL DEFAULT 0,
    done_count      INT          NOT NULL DEFAULT 0,
    created_by      BIGINT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_offboarding_task_tenant ON mxid_offboarding_task(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS mxid_offboarding_item (
    id         BIGINT       PRIMARY KEY,
    task_id    BIGINT       NOT NULL,
    tenant_id  BIGINT       NOT NULL,
    app_id     BIGINT       NOT NULL,
    app_name   VARCHAR(128) NOT NULL DEFAULT '',
    app_code   VARCHAR(64)  NOT NULL DEFAULT '',
    tier       VARCHAR(8)   NOT NULL DEFAULT 'L1',  -- L1 auto-cut / L2 scim / L3 manual
    status     SMALLINT     NOT NULL DEFAULT 0,     -- 0 = pending, 1 = done
    done_by    BIGINT,
    done_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_offboarding_item_task ON mxid_offboarding_item(task_id);
CREATE INDEX IF NOT EXISTS idx_offboarding_item_tenant ON mxid_offboarding_item(tenant_id, status);
