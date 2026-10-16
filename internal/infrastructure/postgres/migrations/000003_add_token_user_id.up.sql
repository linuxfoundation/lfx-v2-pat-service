-- Copyright The Linux Foundation and each contributor to LFX.
-- SPDX-License-Identifier: MIT

-- The owner's Auth0 user ID, which the token exchange signs in as. Rows issued before it was captured stay NULL
-- and fail validation, so their owners issue new tokens.
ALTER TABLE tokens ADD COLUMN user_id text;
