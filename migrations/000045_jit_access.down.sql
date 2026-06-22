-- Remove auditor->audit.read binding added by this migration (4000+200=4200).
-- The auditor role (id=4) and audit.read permission (id=200) pre-date this
-- migration and are NOT dropped here.
DELETE FROM mxid_role_permission WHERE id IN (904500021, 904500022, 4200);
DELETE FROM mxid_role WHERE id IN (904500011, 904500012);
DELETE FROM mxid_permission WHERE id IN (904500001, 904500002, 904500003);
DROP TABLE IF EXISTS mxid_access_request;
DROP TABLE IF EXISTS mxid_access_eligibility;
DROP INDEX IF EXISTS idx_app_role_binding_expiry;
DROP INDEX IF EXISTS idx_role_binding_expiry;
ALTER TABLE mxid_app_role_binding DROP COLUMN IF EXISTS grant_id, DROP COLUMN IF EXISTS expires_at, DROP COLUMN IF EXISTS status;
ALTER TABLE mxid_role_binding DROP COLUMN IF EXISTS grant_id, DROP COLUMN IF EXISTS expires_at, DROP COLUMN IF EXISTS status;
