-- Revert to the non-soft-delete-aware unique constraint. This can fail if a
-- soft-deleted row now shares (tenant_id, username) with a live row (which the
-- up migration deliberately allows); resolve such collisions before rolling back.
DROP INDEX IF EXISTS idx_user_tenant_username;

ALTER TABLE mxid_user
    ADD CONSTRAINT mxid_user_tenant_id_username_key UNIQUE (tenant_id, username);
