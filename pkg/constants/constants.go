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
	EnvPGMaxConns = "PG_MAX_CONNS"

	EnvMigrateOnStart       = "DB_MIGRATE_ON_START"
	EnvValidatorPrincipals  = "VALIDATOR_PRINCIPALS"
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
	DefaultPGSSLMode  = "require"
	DefaultPGMaxConns = 10

	DefaultMigrateOnStart       = true
	DefaultMaxActivePerAudience = 25

	DefaultKoDataPath = "."
)

// AudienceInsights is the audience slug seeded by the first migration. Audiences are data; Go references only
// this seed, for examples and tests.
const AudienceInsights = "insights"

// ScopeValidate is the JWT scope the validate endpoint requires. JWTAuth uses its presence to switch from the
// user-principal policy to the allow-listed machine-principal policy.
const ScopeValidate = "token:validate"

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
