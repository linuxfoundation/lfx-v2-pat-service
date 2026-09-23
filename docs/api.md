<!-- Copyright The Linux Foundation and each contributor to LFX. -->
<!-- SPDX-License-Identifier: MIT -->

# API

The token and validate endpoints sit behind Heimdall and expect `Authorization: Bearer <Heimdall-issued JWT>`;
bodies and responses are JSON in snake_case, and the optional `?v=1` query parameter LFX One appends is accepted
on each of them. The OpenAPI document at `/_tokens/openapi3.json` is served without a token.

## Endpoints

| Method | Path | Caller | Success |
|---|---|---|---|
| `POST` | `/tokens` `{name, audience}` | user | `201 {secret, token}` |
| `GET` | `/tokens?audience=` | user | `200 {tokens: [...]}`, newest first |
| `DELETE` | `/tokens/{uid}` | user | `204` |
| `POST` | `/_tokens/validate` `{secret}` | machine principal in the validator team | `200 {uid, username, audience, email?}` |

A token is `{uid, name, audience, lookup_id, username, created_at, last_used_at?}`. The plaintext `secret`
appears once, in the create response. List and revoke address a token by `uid`, expose its public `lookup_id`, and
never carry the secret, the salt or the hash.

`name` is trimmed, 1 to 100 characters, free of control characters, and unique (case-insensitively) among the
caller's active tokens for the audience. A revoked token's name can be reused. `audience` is a slug from the
`audiences` table; `insights` is the seed.

The list is not paginated: a caller holds at most `TOKEN_MAX_ACTIVE_PER_AUDIENCE` active tokens per audience, so
an unfiltered list is bounded by that limit times the number of audiences.

## Errors

Errors use Goa's default body (`name`, `message`) except two that carry a stable `error` code next to `message`, which LFX One
forwards to its UI as `upstreamCode`:

| Status | Body | When |
|---|---|---|
| `409` | `{"error": "token_name_taken", "message": "..."}` | an active token with that name already exists for the caller and audience |
| `409` | `{"error": "token_limit_reached", "message": "..."}` | the caller already holds the maximum active tokens for the audience |
| `404` | `{"error": "invalid_token", "message": "..."}` | validate: unknown, malformed, or revoked secret, or a disabled audience |
| `400` | message starts with `unknown_audience` | create: unknown or disabled audience slug |
| `400` | | invalid body, unknown `v`, a `uid` that is not a UUID, or a `secret` that is missing, empty or longer than 128 characters (rejected before the credential check) |
| `401` | | missing, invalid or anonymous bearer token |
| `403` | | a machine principal on a token route; on validate, Heimdall rejects callers outside the validator team |
| `503` | | the database is unreachable |

Owner scoping is enforced by the service: a token another user owns reads as `404`, and revoke is idempotent
(`204` once, `404` after). Every rejected secret on validate is the same `404` body, so a caller cannot tell an
unknown secret from a revoked one.

## Principal policy

Heimdall's `create_jwt` finalizer emits a `principal` claim: the LFID username for a user, `<client_id>@clients`
for an OAuth client-credentials token, and `_anonymous` when the anonymous authenticator applies. The service
refuses `_anonymous` outright. Token routes accept user principals only. `POST /_tokens/validate` applies no
principal check in the service; it is authorized at the gateway, where the RuleSet runs an OpenFGA check that the
caller is a `member` of the validator team (`app.validatorTeamName`, default `pat_validator`). That team holds the
Auth0 Actions client per environment, and until its member tuples exist the route denies every caller.

The token routes end in `allow_all` in the Heimdall RuleSet because there is no OpenFGA type for tokens; the
ownership policy above is what the gateway delegates to the service for those routes.

## Validation flow

The Auth0 action obtains a client-credentials token for the LFX v2 API, calls `POST /_tokens/validate` through
the gateway with the secret the end user presented, and receives the owner's `username`, the `audience` the
token was minted for, and the `email` captured at issuance. The action must compare `audience` with the one it
is exchanging for. A successful validation records `last_used_at` on a best-effort basis: a failure to record it is logged and the
validation still succeeds. A failed validation records nothing.
