// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package constants defines application-wide constants.
package constants

// Environment variable names
const (
	EnvPort  = "PORT"
	EnvHost  = "HOST"
	EnvDebug = "DEBUG"

	EnvJWKSURL            = "JWKS_URL"
	EnvAudience           = "AUDIENCE"
	EnvIssuer             = "ISSUER"
	EnvMockLocalPrincipal = "JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL"

	// Database credentials arrive as the five libpq-standard variables the chart reads from the RDS secret.
	EnvPGHost     = "PGHOST"
	EnvPGPort     = "PGPORT"
	EnvPGUser     = "PGUSER"
	EnvPGPassword = "PGPASSWORD"
	EnvPGDatabase = "PGDATABASE"
	EnvPGSSLMode  = "PGSSLMODE"
	// EnvPGSSLRootCert is the path to the PEM bundle file that signs the database server certificate; empty uses the system roots.
	EnvPGSSLRootCert = "PGSSLROOTCERT"
	// EnvPGAllowInsecureSSLMode permits an sslmode weaker than verify-full. Local development only.
	EnvPGAllowInsecureSSLMode = "PG_ALLOW_INSECURE_SSLMODE"
	EnvPGMaxConns             = "PG_MAX_CONNS"

	EnvStore                = "STORE"
	EnvMigrateOnStart       = "DB_MIGRATE_ON_START"
	EnvMaxActivePerAudience = "TOKEN_MAX_ACTIVE_PER_AUDIENCE"

	EnvKoDataPath = "KO_DATA_PATH"
)

// Default values
const (
	DefaultHost     = "0.0.0.0"
	DefaultHTTPPort = "8080"

	DefaultJWKSURL  = "http://heimdall:4457/.well-known/jwks"
	DefaultAudience = "lfx-v2-pat-service"
	DefaultIssuer   = "heimdall"

	DefaultPGPort     = "5432"
	DefaultPGSSLMode  = PGSSLModeVerifyFull
	DefaultPGMaxConns = 10

	DefaultStore                = StorePostgres
	DefaultMigrateOnStart       = true
	DefaultMaxActivePerAudience = 25

	DefaultKoDataPath = "."
)

// PGSSLModeVerifyFull is the only sslmode that authenticates the server: weaker modes skip the chain or
// host-name check, so anyone on the network path could terminate TLS and read the credential.
const PGSSLModeVerifyFull = "verify-full"

// Store selects the token store. Postgres is the default; the in-memory store is an explicit opt-in for local
// runs without a database and never persists anything.
const (
	StorePostgres = "postgres"
	StoreMemory   = "memory"
)

// AudienceInsights is the audience slug seeded by the first migration. Audiences are data; Go references only
// this seed, for examples and tests.
const AudienceInsights = "insights"

// Error codes carried in the "error" field of custom error bodies. lfx-one forwards them to its UI as upstreamCode,
// which is the only way a 409 or 404 keeps a distinguishable cause.
const (
	ErrCodeTokenNameTaken    = "token_name_taken"
	ErrCodeTokenLimitReached = "token_limit_reached"
	ErrCodeInvalidToken      = "invalid_token"
	ErrCodeUnknownAudience   = "unknown_audience"
)

// TokenNameMaxLength bounds a token's display name; mirrors the tokens_name_len check constraint.
const TokenNameMaxLength = 100

// Principal forms Heimdall's create_jwt finalizer emits besides plain LFID usernames.
const (
	AnonymousPrincipal    = "_anonymous"
	ClientPrincipalSuffix = "@clients"
)
