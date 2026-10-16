# LFX V2 Personal Access Token Service

Issues, lists, revokes and validates long-lived personal access tokens, scoped to an audience. The first audience
is LFX Insights, whose secrets start with `lfi_`. LFX One's Developer Settings manages tokens on the user's behalf
through the platform gateway, and an Auth0 Custom Token Exchange action validates them when the Insights
Cloudflare Worker exchanges a secret for a short-lived JWT.

The design is recorded in the Insights repository: ADR-0006 (token exchange), ADR-0015 (issuance in LFX One)
and ADR-0020 (this service on the platform cluster).

## API

The token and validate endpoints sit behind Heimdall and expect `Authorization: Bearer <Heimdall-issued JWT>`;
their bodies and responses are JSON in snake_case, and the optional `?v=1` query parameter that LFX One appends
is accepted on each of them. The probes answer plain text to the kubelet, and the OpenAPI document, generated
from `design/`, is served at `/_tokens/openapi3.json` without a token.

| Method   | Path                           | Caller                                  | Success                                 |
|----------|--------------------------------|-----------------------------------------|-----------------------------------------|
| `POST`   | `/tokens` `{name, audience}`   | user                                    | `201 {secret, token}`                   |
| `GET`    | `/tokens?audience=`            | user                                    | `200 {tokens: [...]}`, newest first     |
| `DELETE` | `/tokens/{uid}`                | user                                    | `204`                                   |
| `POST`   | `/_tokens/validate` `{secret}` | machine principal in the validator team | `200 {uid, username, audience, email?}` |
| `GET`    | `/livez`, `/readyz`            | probes                                  | `200`                                   |

A token is `{uid, name, audience, lookup_id, username, created_at, last_used_at?}`. The plaintext `secret`
appears once, in the create response. List returns each token with its public `lookup_id`
and never the secret, the salt or the hash. Revoke addresses a token by `uid`.

Validate answers with the owner, not the token: its `uid` is the owner's Auth0 user ID, captured at issuance, and
its `audience` is the identifier of the Auth0 API the token's audience maps to in `AUDIENCE_API_IDENTIFIERS`.

Errors use Goa's default body (`name`, `message`) except two that carry a stable `error` code next to `message`, which LFX One
forwards to its UI:

| Status | Body                                                 | When                                                                                                                                                                                                             |
|--------|------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `409`  | `{"error": "token_name_taken", "message": "..."}`    | the caller already has an active token with that name for the audience (case-insensitive)                                                                                                                        |
| `409`  | `{"error": "token_limit_reached", "message": "..."}` | the caller already holds `TOKEN_MAX_ACTIVE_PER_AUDIENCE` active tokens for the audience                                                                                                                          |
| `404`  | `{"error": "invalid_token", "message": "..."}`       | validate: the secret is unknown, malformed, revoked, issued without an owner Auth0 user ID, or its audience is disabled; a missing, empty or over-128-character `secret` is a `400` from body validation instead |
| `400`  | message starts with `unknown_audience`               | create: the audience slug is unknown or disabled                                                                                                                                                                 |
| `401`  |                                                      | missing, invalid or anonymous bearer token; on create, a JWT without the owner's Auth0 user ID                                                                                                                   |
| `403`  |                                                      | a machine principal on a token route; on validate, Heimdall rejects callers outside the validator team before the service sees them                                                                              |
| `500`  |                                                      | validate: the token's audience has no entry in `AUDIENCE_API_IDENTIFIERS`                                                                                                                                        |

Owner scoping is enforced here rather than at the gateway: a token another user owns reads as `404`, revoke is
idempotent (`204` once, `404` after), and every rejected secret on validate is the same `404` so callers cannot
tell an unknown secret from a revoked one.

### Who may call what

Heimdall forwards a JWT whose `principal` claim is the LFID username for a user, or `<client_id>@clients` for an
OAuth client-credentials token. On the create route the chart's RuleSet also adds `user_id`, the Auth0 `sub` of the
caller's token, which the service stores so the token exchange can sign in as the owner. Token routes accept user
principals only. `POST /_tokens/validate` is authorized at the gateway: the chart's RuleSet runs an OpenFGA check
that the caller is a `member` of the validator team (`app.validatorTeamName`, default `pat_validator`), which holds
the Auth0 Actions client per environment. Until that team's member tuples exist in an environment's OpenFGA store
the route denies every caller, so a missing grant fails closed.

### Audiences

Audiences are rows in the `audiences` table, seeded by migration (`insights` with prefix `lfi_`). Adding one is a
new seed migration; disabling one (`enabled = false`) stops both issuance and validation for it.

## Secrets

See [docs/secret-format.md](docs/secret-format.md). In short: `<prefix><12-char lookup id><32-char random part>`,
base62. The store keeps a per-row salt and SHA-256(salt || random part); validation is one indexed lookup by
`lookup_id` followed by a constant-time compare.

## Configuration

The service reads its configuration from environment variables (CLI flags `-p`, `-bind`, `-d` override the first three).

| Variable                                       | Default                                 | Purpose                                                                                             |
|------------------------------------------------|-----------------------------------------|-----------------------------------------------------------------------------------------------------|
| `PORT`                                         | `8080`                                  | HTTP listen port                                                                                    |
| `HOST`                                         | `0.0.0.0`                               | Interface to bind on                                                                                |
| `DEBUG`                                        | `false`                                 | Mounts the pprof endpoints under `/debug/pprof`; log verbosity itself comes from `LOG_LEVEL`        |
| `LOG_LEVEL`                                    | `info`                                  | `debug`, `info`, `warn` or `error`                                                                  |
| `LOG_ADD_SOURCE`                               | `true`                                  | Add the source location to log lines                                                                |
| `JWKS_URL`                                     | `http://heimdall:4457/.well-known/jwks` | JWKS endpoint used to verify Heimdall-issued JWTs                                                   |
| `AUDIENCE`                                     | `lfx-v2-pat-service`                    | Expected `aud` claim of the Heimdall-issued JWT                                                     |
| `ISSUER`                                       | `heimdall`                              | Expected `iss` claim of the Heimdall-issued JWT                                                     |
| `JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL`       |                                         | Local development only: skip JWT verification and attribute every request to this principal         |
| `STORE`                                        | `postgres`                              | `postgres`, or `memory` for a local run without a database (nothing persists)                       |
| `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` |                                         | Postgres connection, read from the RDS secret in the chart; all four required when `STORE=postgres` |
| `PGPORT`                                       | `5432`                                  | Postgres port; optional                                                                             |
| `PGSSLMODE`                                    | `verify-full`                           | libpq SSL mode; anything weaker is refused unless `PG_ALLOW_INSECURE_SSLMODE=true`                  |
| `PGSSLROOTCERT`                                |                                         | Path to the PEM bundle file that signs the database server certificate; empty uses the system roots |
| `PG_ALLOW_INSECURE_SSLMODE`                    | `false`                                 | Local development only: accept `disable`, `require` and other modes that skip server verification   |
| `PG_MAX_CONNS`                                 | `10`                                    | Connection pool size                                                                                |
| `DB_MIGRATE_ON_START`                          | `true`                                  | Apply pending migrations before listening                                                           |
| `TOKEN_MAX_ACTIVE_PER_AUDIENCE`                | `25`                                    | Active tokens one user may hold per audience                                                        |
| `AUDIENCE_API_IDENTIFIERS`                     | `{}`                                    | JSON object mapping each audience slug to its Auth0 API identifier, which validate returns          |
| `KO_DATA_PATH`                                 | `.`                                     | Directory holding `gen/http/openapi3.json`; set by ko and the Dockerfile                            |
| `OTEL_*`                                       |                                         | OpenTelemetry exporter settings, see `pkg/telemetry`                                                |

## Local development

```bash
make apigen     # regenerate gen/ after changing design/ (gen/ is committed)
make verify     # fail if committed gen/ differs from design/ (runs in PR CI)
make build      # bin/lfx-v2-pat-service
make test
make db-up      # disposable Postgres 16 in Docker on 127.0.0.1:5433 (DB_PORT=... to change)
make lint
make fmt
make helm-lint  # render the chart with the default and the local example values
```

Run the service against the local database with JWT verification disabled:

```bash
PGHOST=localhost PGPORT=5433 PGUSER=pat PGPASSWORD=pat PGDATABASE=pat PGSSLMODE=disable PG_ALLOW_INSECURE_SSLMODE=true \
JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL=alice AUDIENCE_API_IDENTIFIERS='{"insights":"https://insights-api.local/"}' \
./bin/lfx-v2-pat-service
```

Then walk the lifecycle (the bearer value is ignored while the mock principal is set, and the mock caller's Auth0
user ID is `auth0|<principal>`; outside the cluster there is no Heimdall, so the validate call is open to the mock
principal too):

```bash
curl -s -XPOST localhost:8080/tokens -H 'Authorization: Bearer x' -H 'Content-Type: application/json' \
  -d '{"name":"ci","audience":"insights"}'                       # 201: note the secret and the uid
curl -s localhost:8080/tokens -H 'Authorization: Bearer x'      # 200: lookup_id, never the secret
curl -s -XPOST localhost:8080/_tokens/validate -H 'Authorization: Bearer x' -H 'Content-Type: application/json' \
  -d '{"secret":"lfi_..."}'                                      # 200: {uid, username, audience}; email only when the JWT carried one
TOKEN_UID=...   # the uid from the create response
curl -s -XDELETE "localhost:8080/tokens/$TOKEN_UID" -H 'Authorization: Bearer x' -o /dev/null -w '%{http_code}\n'  # 204
```

Migrations live in `internal/infrastructure/postgres/migrations` and are applied at startup (`DB_MIGRATE_ON_START`).
`STORE=memory` runs the same code paths against an in-memory store when no database is at hand.

## Layout

```text
design/                         Goa design; make apigen regenerates gen/
gen/                            generated transport, committed
cmd/pat-api/                    main, HTTP server, and the Goa adapter (cmd/pat-api/service)
internal/domain/                caller identity, models, and one port per capability
internal/service/               use-cases: Manager (issue/list/revoke) and Validator
internal/infrastructure/auth/   Heimdall JWT verification
internal/infrastructure/postgres/  pool, migrations, repositories
internal/infrastructure/mock/   in-memory repositories (tests and STORE=memory)
pkg/secret/                     secret generation, parsing, hashing
charts/lfx-v2-pat-service/      Helm chart with the Heimdall RuleSet and HTTPRoute
```

## Deployment

The chart reads the Postgres credential from the Secret the ArgoCD ExternalSecret materialises
(`database.external.secretName`, five keys). The validate route is gated by OpenFGA team membership: platform
DevOps writes `user:<Auth0 Actions client_id>@clients member team:pat_validator` into each environment's store
(the name comes from `app.validatorTeamName`). Each environment also sets `app.audienceApiIdentifiers` to the
identifiers of its Auth0 tenant's APIs. See `charts/lfx-v2-pat-service/values.yaml`.

The database link uses `sslmode=verify-full`, so the pod must trust the CA that signs the RDS certificate. The
chart mounts it read-only at `/etc/pat/db-ca` and sets `PGSSLROOTCERT` to the file path: put the AWS RDS CA bundle in
`database.caBundle.pem`, or name a ConfigMap that holds it in `database.caBundle.existingConfigMap`. The CA is read at
startup: inline `pem` changes roll the pods automatically, while an `existingConfigMap` needs a restart. `disable`,
`allow`, `prefer`, `require` and `verify-ca` skip encryption or part of the server check, so they are for a local
database only and need `database.allowInsecureSSLMode: true`.
