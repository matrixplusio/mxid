-- migrations/000050_audit_entry_append_only.up.sql
-- Append-only hard floor for the chained audit log. A BEFORE UPDATE/DELETE
-- trigger raises unconditionally, so no code path (or DBA, short of dropping
-- the trigger) can rewrite or remove a chained entry. This is the DB-level
-- complement to the HMAC hash chain: the chain DETECTS tampering; this trigger
-- PREVENTS the mutation outright. Role-based GRANT hardening (a restricted app
-- role) is deferred to ops setup; this trigger binds regardless of role.

CREATE OR REPLACE FUNCTION mxid_audit_entry_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'mxid_audit_entry is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_entry_append_only ON mxid_audit_entry;
CREATE TRIGGER trg_audit_entry_append_only
    BEFORE UPDATE OR DELETE ON mxid_audit_entry
    FOR EACH ROW EXECUTE FUNCTION mxid_audit_entry_append_only();
