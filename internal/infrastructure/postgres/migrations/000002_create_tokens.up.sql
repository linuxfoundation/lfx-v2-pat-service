-- Copyright The Linux Foundation and each contributor to LFX.
-- SPDX-License-Identifier: MIT

-- One row per issued token. The secret is never stored: lookup_id is the public locator embedded in it and
-- secret_hash is SHA-256(salt || random part). Revoked rows stay for audit and so a lookup_id is never reused.
CREATE TABLE tokens (
    uid           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text        NOT NULL,
    email         text,
    audience      text        NOT NULL REFERENCES audiences (slug),
    name          text        NOT NULL,
    lookup_id     text        NOT NULL,
    salt          bytea       NOT NULL,
    secret_hash   bytea       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    CONSTRAINT tokens_name_len      CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT tokens_lookup_id_len CHECK (char_length(lookup_id) = 12),
    CONSTRAINT tokens_hash_len      CHECK (octet_length(secret_hash) = 32 AND octet_length(salt) = 16)
);

-- Validation hot path: one indexed lookup. Revoked rows are included so a lookup_id is never reused.
CREATE UNIQUE INDEX tokens_lookup_id_key ON tokens (lookup_id);

-- A user may not hold two active tokens with the same name (case-insensitive) for one audience.
CREATE UNIQUE INDEX tokens_active_name_key ON tokens (username, audience, lower(name)) WHERE revoked_at IS NULL;

-- Owner listing and the active-token count behind the per-audience limit.
CREATE INDEX tokens_owner_active_idx ON tokens (username, audience, created_at DESC) WHERE revoked_at IS NULL;
