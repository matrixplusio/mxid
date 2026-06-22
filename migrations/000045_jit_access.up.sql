-- JIT Privileged Access (temporary elevation). A user requests a higher role
-- for a bounded window; an approver grants it; the grant materializes as a
-- TIME-BOUND row in the existing binding tables on the requester's OWN user id
-- (no shared admin account). Resolvers filter expired/revoked rows, a sweeper
-- cleans them up, and every transition is audited.

-- 1. Time-bound columns on the two binding tables that back the two role
--    systems: console RBAC (mxid_role_binding) and SSO app_roles
--    (mxid_app_role_binding). NULL expires_at == permanent binding (unchanged
--    behavior). status: 1 active, 2 expired, 3 revoked.
ALTER TABLE mxid_role_binding
    ADD COLUMN IF NOT EXISTS grant_id   BIGINT      NULL,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS status     SMALLINT    NOT NULL DEFAULT 1;

ALTER TABLE mxid_app_role_binding
    ADD COLUMN IF NOT EXISTS grant_id   BIGINT      NULL,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS status     SMALLINT    NOT NULL DEFAULT 1;

-- Sweeper / resolver hot path: only ever scan rows that actually expire.
CREATE INDEX IF NOT EXISTS idx_role_binding_expiry
    ON mxid_role_binding(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_app_role_binding_expiry
    ON mxid_app_role_binding(expires_at) WHERE expires_at IS NOT NULL;

-- 2. Eligibility: WHO may request WHICH role, for how long, approved by WHOM.
--    target_kind distinguishes the two role systems:
--      'console' -> role_id references mxid_role        (backend admin)
--      'app'     -> role_id references mxid_app_role     (SSO app_roles claim)
CREATE TABLE IF NOT EXISTS mxid_access_eligibility (
    id                     BIGINT       PRIMARY KEY,
    tenant_id              BIGINT       NOT NULL DEFAULT 0,
    target_kind            VARCHAR(16)  NOT NULL,                 -- 'console' | 'app'
    role_id                BIGINT       NOT NULL,                 -- mxid_role.id OR mxid_app_role.id per target_kind
    scope_type             VARCHAR(16)  NULL,                     -- NULL=global, 'org', 'group' (console only)
    scope_id               BIGINT       NULL,
    app_id                 BIGINT       NULL,                     -- required when target_kind='app': which app the role lives on
    requester_subject_type VARCHAR(16)  NOT NULL,                 -- 'any' | 'user' | 'group' | 'org'
    requester_subject_id   BIGINT       NOT NULL DEFAULT 0,       -- 0 when 'any'
    allowed_durations      JSONB        NOT NULL DEFAULT '[3600,14400,86400,259200,604800]',
    max_duration_seconds   INT          NOT NULL DEFAULT 604800,  -- 7d ceiling (max)
    approver_subject_type  VARCHAR(16)  NOT NULL DEFAULT 'role',  -- 'role' | 'group' | 'user' | 'auto'
    approver_subject_id    BIGINT       NOT NULL DEFAULT 0,       -- the governance role/group/user id; 0 when 'auto'
    require_justification  BOOLEAN      NOT NULL DEFAULT TRUE,
    require_stepup         BOOLEAN      NOT NULL DEFAULT TRUE,
    status                 SMALLINT     NOT NULL DEFAULT 1,       -- 1 enabled, 2 disabled
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by             BIGINT       NULL,
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_access_eligibility_tenant ON mxid_access_eligibility(tenant_id);

-- 3. Request: one row per ask. The lifecycle record; the live grant lives in
--    the binding table referenced by binding_id once approved.
CREATE TABLE IF NOT EXISTS mxid_access_request (
    id                  BIGINT       PRIMARY KEY,
    tenant_id           BIGINT       NOT NULL DEFAULT 0,
    requester_id        BIGINT       NOT NULL,
    eligibility_id      BIGINT       NOT NULL,
    target_kind         VARCHAR(16)  NOT NULL,                    -- copied from eligibility at request time
    role_id             BIGINT       NOT NULL,
    scope_type          VARCHAR(16)  NULL,
    scope_id            BIGINT       NULL,
    app_id              BIGINT       NULL,
    requested_seconds   INT          NOT NULL,
    justification       TEXT         NOT NULL DEFAULT '',
    status              VARCHAR(16)  NOT NULL DEFAULT 'pending',  -- pending|approved|rejected|cancelled|expired|revoked
    approver_id         BIGINT       NULL,
    decided_at          TIMESTAMPTZ  NULL,
    decision_reason     TEXT         NOT NULL DEFAULT '',
    activated_at        TIMESTAMPTZ  NULL,
    expires_at          TIMESTAMPTZ  NULL,
    binding_id          BIGINT       NULL,                        -- the mxid_role_binding / mxid_app_role_binding row id
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_access_request_tenant_status ON mxid_access_request(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_access_request_requester ON mxid_access_request(requester_id);

-- 4. Governance permissions + system roles (separation of duties). Approval
--    authority is a dedicated permission, NOT the target business role.
--
--    NOTE: tenant_id=1 is the default system tenant (required by mxid_tenant FK).
--    ID range 904500xxx is reserved for JIT governance seed to avoid collision
--    with the sequential permission catalog (max 243 as of migration 000039).
--
--    audit.read (code) already exists as id=200 (migration 000016); the INSERT
--    is silently skipped via ON CONFLICT DO NOTHING on (tenant_id, code).
--
--    auditor role (code='auditor') already exists as id=4 (migration 000016);
--    its INSERT is similarly skipped — do NOT reference 904500012 in
--    mxid_role_permission because that id will not be created.
INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action, created_at)
VALUES
  (904500001, 1, 'Approve access requests',  'access.request.approve',   'access', 'approve', NOW()),
  (904500002, 1, 'Manage access eligibility','access.eligibility.manage', 'access', 'manage',  NOW()),
  (904500003, 1, 'Read audit log',            'audit.read',               'audit',  'read',    NOW())
ON CONFLICT DO NOTHING;

INSERT INTO mxid_role (id, tenant_id, name, code, type, description, created_at, updated_at)
VALUES
  (904500011, 1, 'Access Approver', 'access-approver', 1, 'Approves JIT elevation requests (governance, separation of duties)', NOW(), NOW()),
  (904500012, 1, 'Auditor',         'auditor',          1, 'Read-only access to the audit log',                                  NOW(), NOW())
ON CONFLICT DO NOTHING;

-- Wire access-approver (904500011) to its two JIT permissions.
-- Wire auditor (existing id=4) to audit.read (existing id=200) — idempotent.
-- access-approver also gets super_admin grant via 1000+p.id convention in
-- runtime authz, but we seed the role_permission rows explicitly here.
INSERT INTO mxid_role_permission (id, role_id, permission_id, created_at)
VALUES
  (904500021, 904500011, 904500001, NOW()),  -- access-approver -> access.request.approve
  (904500022, 904500011, 904500002, NOW())   -- access-approver -> access.eligibility.manage
ON CONFLICT DO NOTHING;

-- Ensure auditor (id=4) has audit.read (id=200). Uses SELECT to resolve the
-- real permission id (200) regardless of whether 904500003 was inserted or
-- skipped, avoiding a hard-coded FK to a potentially non-existent id.
INSERT INTO mxid_role_permission (id, role_id, permission_id, created_at)
SELECT 4000 + p.id, 4, p.id, NOW()
FROM mxid_permission p
WHERE p.tenant_id = 1 AND p.code = 'audit.read'
ON CONFLICT DO NOTHING;
