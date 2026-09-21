<!-- Copyright The Linux Foundation and each contributor to LFX. -->
<!-- SPDX-License-Identifier: MIT -->

# API

Every endpoint sits behind Heimdall and expects `Authorization: Bearer <Heimdall-issued JWT>`. Bodies and
responses are JSON in snake_case. The optional `?v=1` query parameter LFX One appends is accepted on every
method. The OpenAPI document is served at `/_tokens/openapi3.json`.

## Endpoints

| Method | Path | Caller | Success |
|---|---|---|---|
| `POST` | `/tokens` `{name, audience}` | user | `201 {secret, token}` |
| `GET` | `/tokens?audience=` | user | `200 {tokens: [...]}`, newest first |
| `GET` | `/tokens/{uid}` | user | `200` token |
| `DELETE` | `/tokens/{uid}` | user | `204` |
| `POST` | `/_tokens/validate` `{secret}` | allow-listed machine principal | `200 {uid, username, audience, email?}` |

A token is `{uid, name, audience, lookup_id, username, created_at, last_used_at?}`. The plaintext `secret`
appears once, in the create response. List and get identify a token by its public `lookup_id` and never carry
the secret, the salt or the hash.

`name` is trimmed, 1 to 100 characters, free of control characters, and unique (case-insensitively) among the
caller's active tokens for the audience. A revoked token's name can be reused. `audience` is a slug from the
`audiences` table; `insights` is the seed.

The list is not paginated: `TOKEN_MAX_ACTIVE_PER_AUDIENCE` bounds it.

## Errors

Errors use Goa's default body (`name`, `message`) except two that carry a stable `error` code, which LFX One
forwards to its UI as `upstreamCode`:

| Status | Body | When |
|---|---|---|
| `409` | `{"error": "token_name_taken"}` | an active token with that name already exists for the caller and audience |
| `409` | `{"error": "token_limit_reached"}` | the caller already holds the maximum active tokens for the audience |
| `404` | `{"error": "invalid_token"}` | validate: unknown, malformed, or revoked secret, or a disabled audience |
| `400` | message starts with `unknown_audience` | create: unknown or disabled audience slug |
| `400` | | invalid body, unknown `v`, or a `uid` that is not a UUID |
| `401` | | missing, invalid or anonymous bearer token |
| `403` | | a machine principal on a token route, or a principal outside the allow-list on validate |
| `503` | | the database is unreachable |

Owner scoping is enforced by the service: a token another user owns reads as `404`, and revoke is idempotent
(`204` once, `404` after). Every rejected secret on validate is the same `404` body, so a caller cannot tell an
unknown secret from a revoked one.

## Principal policy

Heimdall's `create_jwt` finalizer emits a `principal` claim: the LFID username for a user, `<client_id>@clients`
for an OAuth client-credentials token, and `_anonymous` when the anonymous authenticator applies. The service
refuses `_anonymous` outright. Token routes accept user principals only. `POST /_tokens/validate` requires the
`token:validate` scope in the design and, at runtime, a principal listed in `VALIDATOR_PRINCIPALS`, which each
environment sets to the Auth0 Actions client. An empty list refuses every validate call.

The Heimdall RuleSet ends every rule in `allow_all` because there is no OpenFGA type for tokens; the policy
above is what the gateway delegates to the service.

## Validation flow

The Auth0 action obtains a client-credentials token for the LFX v2 API, calls `POST /_tokens/validate` through
the gateway with the secret the end user presented, and receives the owner's `username`, the `audience` the
token was minted for, and the `email` captured at issuance. The action must compare `audience` with the one it
is exchanging for. A successful validation records `last_used_at`; a failed one records nothing.
