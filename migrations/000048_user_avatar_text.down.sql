-- Truncate to the old VARCHAR(512) bound; base64 data URLs longer than that are
-- clipped (they would otherwise block the type change). Rolling back after real
-- avatars have been uploaded is inherently lossy.
ALTER TABLE mxid_user ALTER COLUMN avatar TYPE VARCHAR(512) USING left(avatar, 512);
