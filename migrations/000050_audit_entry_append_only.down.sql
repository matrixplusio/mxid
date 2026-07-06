-- migrations/000050_audit_entry_append_only.down.sql
DROP TRIGGER IF EXISTS trg_audit_entry_append_only ON mxid_audit_entry;
DROP FUNCTION IF EXISTS mxid_audit_entry_append_only();
