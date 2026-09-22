-- Copyright The Linux Foundation and each contributor to LFX.
-- SPDX-License-Identifier: MIT

-- Audiences are the services tokens can be minted for. They are rows rather than code so a new audience is a
-- seed migration, and the Go code only ever references the seed slug in tests.
CREATE TABLE audiences (
    slug         text        PRIMARY KEY,
    display_name text        NOT NULL,
    token_prefix text        NOT NULL UNIQUE,
    enabled      boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audiences_slug_fmt   CHECK (slug ~ '^[a-z][a-z0-9-]{1,31}$'),
    -- The secret parser splits at the first underscore, so a prefix carries exactly one, at its end.
    CONSTRAINT audiences_prefix_fmt CHECK (token_prefix ~ '^[a-z0-9]{2,8}_$')
);

INSERT INTO audiences (slug, display_name, token_prefix)
VALUES ('insights', 'LFX Insights', 'lfi_');
