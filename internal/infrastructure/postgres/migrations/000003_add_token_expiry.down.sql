-- Copyright The Linux Foundation and each contributor to LFX.
-- SPDX-License-Identifier: MIT

ALTER TABLE tokens DROP CONSTRAINT tokens_expires_after_created;

ALTER TABLE tokens DROP COLUMN expires_at;
