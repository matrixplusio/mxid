-- Form-fill extension binding tokens. A per-install secret held ONLY in the
-- extension's isolated chrome.storage; reveal requires it in addition to the
-- session cookie + step-up, so a different (malicious, host-permitted) extension
-- cannot read a credential even within the step-up window. Schema is
-- CE-foundational; the pairing/validation logic ships in mxid-ee (form_fill).
-- See docs/FORM-FILL-EXTENSION-TOKEN-BINDING.md.
CREATE TABLE IF NOT EXISTS mxid_formfill_ext_token (
    id           BIGINT       PRIMARY KEY,
    user_id      BIGINT       NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    token_hash   VARCHAR(64)  NOT NULL,          -- sha256(token) hex; plaintext never stored
    device_label VARCHAR(128),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ  NOT NULL,
    UNIQUE(token_hash)
);
CREATE INDEX IF NOT EXISTS idx_formfill_ext_token_user ON mxid_formfill_ext_token(user_id);
