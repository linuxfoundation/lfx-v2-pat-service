# LFX V2 Personal Access Token Service

Creating and managing long lived personal access tokens for different audiences

## Service Setup

**Delete this section after working through the template PRs:**

- [ ] [Merge the OpenTofu PR](https://github.com/linuxfoundation/lfx-v2-opentofu/pull/256) to create service accounts used in the ArgoCD PR
- [ ] [Merge the ArgoCD PR](https://github.com/linuxfoundation/lfx-v2-argocd/pull/1608) to deploy the new service
- [ ] [Merge the Backstage Config PR](https://github.com/linuxfoundation/lfx-backstage/pull/81) to sync the service into Backstage


## Getting Started

1. Generate the Goa API code (this repo does not commit generated code — it must be generated once before the module will build):

   ```bash
   make apigen
   ```

   Commit the resulting `gen/` directory along with your other changes.
2. Implement your service logic in `internal/service/service.go` and wire any dependencies in `internal/container/container.go`.

## Configuration

The service reads its configuration from environment variables (CLI flags `-p`, `-bind`, `-d` override the first three).

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `HOST` | `0.0.0.0` | Interface to bind on |
| `DEBUG` | `false` | Mounts the pprof and log-level toggle endpoints and logs request payloads; log verbosity itself comes from `LOG_LEVEL` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `LOG_ADD_SOURCE` | `true` | Add the source location to log lines |
| `JWKS_URL` | `http://heimdall:4457/.well-known/jwks` | JWKS endpoint used to verify Heimdall-issued JWTs |
| `AUDIENCE` | `lfx-v2-pat-service` | Expected `aud` claim of the Heimdall-issued JWT |
| `ISSUER` | `heimdall` | Expected `iss` claim of the Heimdall-issued JWT |
| `JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL` | | Local development only: skip JWT verification and attribute every request to this principal |
| `STORE` | `postgres` | `postgres`, or `memory` for a local run without a database (nothing persists) |
| `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` | | Postgres connection, read from the RDS secret in the chart; all four required when `STORE=postgres` |
| `PGPORT` | `5432` | Postgres port; optional |
| `PGSSLMODE` | `require` | libpq SSL mode; `disable` for a local database |
| `PG_MAX_CONNS` | `10` | Connection pool size |
| `DB_MIGRATE_ON_START` | `true` | Apply pending migrations before listening |
| `TOKEN_MAX_ACTIVE_PER_AUDIENCE` | `25` | Active tokens one user may hold per audience |
| `OTEL_*` | | OpenTelemetry exporter settings, see `pkg/telemetry` |

## Local development

```bash
make apigen     # regenerate gen/ after changing design/
make build      # bin/lfx-v2-pat-service
make test
make db-up      # disposable Postgres 16 in Docker on 127.0.0.1:5433 (DB_PORT=... to change)
make lint
make fmt
```

Run the service against the local database with JWT verification disabled:

```bash
PGHOST=localhost PGPORT=5433 PGUSER=pat PGPASSWORD=pat PGDATABASE=pat PGSSLMODE=disable \
JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL=alice ./bin/lfx-v2-pat-service
```

Migrations live in `internal/infrastructure/postgres/migrations` and are applied at startup (`DB_MIGRATE_ON_START`).
