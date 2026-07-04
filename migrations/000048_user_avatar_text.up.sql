-- Avatar is stored inline as a base64 data URL (data:image/...;base64,...), not
-- a short URL. A 2 MB image encodes to ~2.8 M characters, far past the old
-- VARCHAR(512) which rejected every real photo with "value too long". Widen to
-- TEXT so the data URL fits.
ALTER TABLE mxid_user ALTER COLUMN avatar TYPE TEXT;
