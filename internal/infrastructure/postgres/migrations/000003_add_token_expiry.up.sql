-- Copyright The Linux Foundation and each contributor to LFX.
-- SPDX-License-Identifier: MIT

-- When a token stops validating; NULL means it never expires. Expired rows stay listed and keep their name until
-- revoked, so the partial indexes on revoked_at stay as they are.
ALTER TABLE tokens ADD COLUMN expires_at timestamptz;

ALTER TABLE tokens ADD CONSTRAINT tokens_expires_after_created CHECK (expires_at IS NULL OR expires_at > created_at);
