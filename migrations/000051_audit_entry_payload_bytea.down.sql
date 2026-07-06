ALTER TABLE mxid_audit_entry ALTER COLUMN payload TYPE jsonb USING convert_from(payload, 'UTF8')::jsonb;
