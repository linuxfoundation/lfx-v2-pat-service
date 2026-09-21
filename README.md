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
| `DEBUG` | `false` | Debug logging, pprof and payload logging |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `LOG_ADD_SOURCE` | `true` | Add the source location to log lines |
| `JWKS_URL` | `http://heimdall:4457/.well-known/jwks` | JWKS endpoint used to verify Heimdall-issued JWTs |
| `AUDIENCE` | `lfx-v2-pat-service` | Expected `aud` claim of the Heimdall-issued JWT |
| `ISSUER` | `heimdall` | Expected `iss` claim of the Heimdall-issued JWT |
| `OTEL_*` | | OpenTelemetry exporter settings, see `pkg/telemetry` |

## Local development

```bash
make apigen   # regenerate gen/ after changing design/
make build    # bin/lfx-v2-pat-service
make test
make lint
make fmt
```
