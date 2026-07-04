-- Make username uniqueness soft-delete-aware, matching the email/phone partial
-- indexes already on this table. The original inline UNIQUE(tenant_id, username)
-- counted soft-deleted rows, so a deleted user's username could never be reused
-- and a collision surfaced as a raw 23505 -> generic 500 instead of a clean
-- "username exists" (the app-level GetByUsername pre-check excludes soft-deleted
-- rows, so it passed and the INSERT then hit the constraint).
ALTER TABLE mxid_user DROP CONSTRAINT IF EXISTS mxid_user_tenant_id_username_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_tenant_username
    ON mxid_user(tenant_id, username) WHERE deleted_at IS NULL;
