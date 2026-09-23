<!-- Copyright The Linux Foundation and each contributor to LFX. -->
<!-- SPDX-License-Identifier: MIT -->

# Secret format

A secret is what the user pastes into a script or CI job. Its shape:

```
<prefix><lookup id><random part>
lfi_    Ab3kZ9QmT2xL 32 base62 characters
```

- **prefix**: the audience's `token_prefix` from the `audiences` table, `[a-z0-9]{2,8}_`. It is the only
  underscore in a secret, which is what the parser splits on.
- **lookup id**: 12 base62 characters from `crypto/rand`. It is a public locator, stored in plain text under a
  unique index and returned by list as `lookup_id`. Knowing it reveals nothing about the random part.
- **random part**: 32 base62 characters from `crypto/rand`, about 190 bits of entropy. This is the only
  confidential piece and it is never stored.

## What is stored

Per token: `lookup_id`, a 16-byte random `salt`, and `secret_hash = SHA-256(salt || random part)`.

Validation parses the presented secret, runs one indexed query on `lookup_id` joined on an enabled audience whose
prefix matches, recomputes the hash with the stored salt, and compares in constant time. Every failure of that
check (malformed, unknown, wrong random part, revoked, disabled audience) is reported identically. The one earlier
rejection is the request body itself: a missing, empty or over-128-character `secret` is a `400` from Goa before
the secret is parsed.

## Why SHA-256 and not a slow hash

Slow key-derivation functions such as bcrypt or argon2 exist to make guessing feasible passwords expensive. The
random part is not guessable: at 190 bits, no hash speed makes enumeration possible, so a fast hash costs nothing
in security and keeps validation well inside the Auth0 action's budget. The per-row salt defeats precomputation
across tokens, which satisfies ADR-0006's salted-hash requirement.

## Why a lookup id inside the secret

A per-row salt means the hash cannot be computed before the row is found. Embedding a public locator in the
secret makes validation a single indexed lookup (ADR-0020's requirement for the exchange hot path) without
resorting to a server-side pepper that would have to be rotated.

## Generation

Characters are drawn with rejection sampling (bytes at or above 248 are discarded) so every base62 character is
equally likely. A lookup id collision, which is astronomically unlikely, is retried once.
