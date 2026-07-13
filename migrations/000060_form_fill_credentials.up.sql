-- Form-fill (SWA) credential storage. Schema is CE-foundational (grandfathered,
-- like branding); the credential LOGIC ships only in mxid-ee behind the
-- `form_fill` license feature. See docs/FORM-FILL-SSO-DESIGN.md §2.

-- per_user mode reuses mxid_app_account (already has UNIQUE(app_id,user_id) + a
-- NOT-NULL FK to mxid_user). Only a staleness column is new.
ALTER TABLE mxid_app_account ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

-- shared mode: one app-level credential all authorized users launch with. A
-- separate table (not a user_id=0 sentinel row in mxid_app_account, which the
-- NOT-NULL FK to mxid_user would reject). Credential is AES-256-GCM at rest via
-- crypto.Secret, masked in JSON.
CREATE TABLE IF NOT EXISTS mxid_app_shared_credential (
    app_id       BIGINT       PRIMARY KEY REFERENCES mxid_app(id) ON DELETE CASCADE,
    account      VARCHAR(256) NOT NULL,
    credential   VARCHAR(512),
    last_used_at TIMESTAMPTZ,
    created_by   BIGINT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE mxid_app_shared_credential IS 'Form-fill shared/service-account credential, one per app (credential_mode=shared). EE-gated logic.';
