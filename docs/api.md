<!-- Copyright The Linux Foundation and each contributor to LFX. -->
<!-- SPDX-License-Identifier: MIT -->

# API

The token and validate endpoints sit behind Heimdall and expect `Authorization: Bearer <Heimdall-issued JWT>`;
bodies and responses are JSON in snake_case, and the optional `?v=1` query parameter LFX One appends is accepted
on each of them. The OpenAPI document at `/_tokens/openapi3.json` is served without a token.

## Endpoints

| Method   | Path                                      | Caller                                  | Success                                 |
|----------|-------------------------------------------|-----------------------------------------|-----------------------------------------|
| `POST`   | `/tokens` `{name, audience, expiration?}` | user                                    | `201 {secret, token}`                   |
| `GET`    | `/tokens?audience=`                       | user                                    | `200 {tokens: [...]}`, newest first     |
| `DELETE` | `/tokens/{uid}`                           | user                                    | `204`                                   |
| `POST`   | `/_tokens/validate` `{secret}`            | machine principal in the validator team | `200 {uid, username, audience, email?}` |

A token is `{uid, name, audience, lookup_id, username, created_at, last_used_at?, expires_at?}`. The plaintext
`secret` appears once, in the create response. List returns each token with its public `lookup_id` and never the
secret, the salt or the hash. Revoke addresses a token by `uid`.

`expiration` is `30d`, `60d`, `90d`, `1y` or `none`, the default. The service counts it from creation, a year being
a calendar year, and returns the result as `expires_at`, which is absent for a token that never expires. An expired
token stops validating at `expires_at` but stays in the list, keeping its name and its slot under the limit, until
it is revoked.

`name` is trimmed, 1 to 100 characters, free of control characters, and unique (case-insensitively) among the
caller's active tokens for the audience. A revoked token's name can be reused. `audience` is a slug from the
`audiences` table; `insights` is the seed.

The list is not paginated: a caller holds at most `TOKEN_MAX_ACTIVE_PER_AUDIENCE` active tokens per audience, so
an unfiltered list is bounded by that limit times the number of audiences.

## Errors

Every error an endpoint returns has the same body, `{"error": "<code>", "message": "..."}`. Requests that match
no route are rejected by Heimdall before they reach the service. The `error` code is stable and LFX One
forwards it to its UI as `upstreamCode`; `message` is for humans and may change. The `X-Request-Id` response header
correlates a failure with the server logs.

| Status | `error`               | When                                                                                                                                |
|--------|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `400`  | `invalid_name`        | create: `name` is empty, blank, longer than 100 characters, or contains control characters                                          |
| `400`  | `invalid_expiration`  | create: `expiration` is not one of `30d`, `60d`, `90d`, `1y` or `none`                                                              |
| `400`  | `invalid_uid`         | revoke: `uid` is not a UUID                                                                                                         |
| `400`  | `unknown_audience`    | create: the audience slug is malformed, unknown or disabled; list: the audience filter is malformed                                 |
| `400`  | `invalid_request`     | any other malformed input: invalid JSON, unknown `v`, or a `secret` that is missing, empty or longer than 128 characters            |
| `401`  | `unauthorized`        | missing, invalid or anonymous bearer token                                                                                          |
| `403`  | `forbidden`           | a machine principal on a token route; on validate, Heimdall rejects callers outside the validator team before the service sees them |
| `404`  | `token_not_found`     | revoke: no active token with that `uid` is owned by the caller                                                                      |
| `404`  | `invalid_token`       | validate: the secret is unknown, malformed, expired, revoked, or its audience is disabled                                           |
| `409`  | `token_name_taken`    | the caller already has an active token with that name for the audience (case-insensitive)                                           |
| `409`  | `token_limit_reached` | the caller already holds `TOKEN_MAX_ACTIVE_PER_AUDIENCE` active tokens for the audience                                             |
| `500`  | `internal_error`      | an unexpected failure; the cause is only in the server log                                                                          |
| `503`  | `service_unavailable` | the database is unreachable                                                                                                         |

Owner scoping is enforced by the service: a token another user owns reads as `404`, and revoke is idempotent
(`204` once, `404` after). Every rejected secret on validate is the same `404` body, so a caller cannot tell an
unknown secret from a revoked or expired one.

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
