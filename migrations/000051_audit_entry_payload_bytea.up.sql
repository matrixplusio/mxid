-- Store mxid_audit_entry.payload as BYTEA, not jsonb. The payload holds the exact
-- canonical JSON bytes that were HMAC-hashed into entry_hash. jsonb normalizes
-- (reorders object keys, injects whitespace) on read-back, so VerifyChain's
-- recompute over the read-back bytes no longer matches the stored hash and every
-- chain fails verification on Postgres. BYTEA round-trips the bytes verbatim and
-- the driver returns []byte (which json.RawMessage scans; TEXT returns a string
-- that it cannot). Query JSON via convert_from(payload,'UTF8')::jsonb.
-- (Any pre-existing jsonb rows were already unverifiable; the cast only changes
-- storage type — there is no correct hash to lose.)
ALTER TABLE mxid_audit_entry ALTER COLUMN payload TYPE bytea USING convert_to(payload::text, 'UTF8');
