// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package config

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFromEnvDefaults(t *testing.T) {
	cfg, err := FromEnv(env(nil))
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8080", cfg.ServerAddress())
	assert.False(t, cfg.Debug)
	assert.Equal(t, "http://heimdall:4457/.well-known/jwks", cfg.JWKSUrl)
	assert.Equal(t, "lfx-v2-pat-service", cfg.Audience)
	assert.Equal(t, "heimdall", cfg.Issuer)
	assert.Empty(t, cfg.MockLocalPrincipal)
	assert.Equal(t, "5432", cfg.PGPort)
	assert.Equal(t, "require", cfg.PGSSLMode)
	assert.Equal(t, 10, cfg.PGMaxConns)
	assert.Equal(t, "postgres", cfg.Store)
	assert.True(t, cfg.MigrateOnStart)
	assert.Empty(t, cfg.ValidatorPrincipals)
	assert.Equal(t, 25, cfg.MaxActivePerAudience)
	assert.False(t, cfg.DatabaseConfigured())
}

func TestFromEnvReadsEverything(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{
		"HOST": "*", "PORT": "9090", "DEBUG": "true",
		"JWKS_URL": "http://h:1/jwks", "AUDIENCE": "aud", "ISSUER": "iss",
		"JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL": " alice ",
		"PGHOST":                                 "db", "PGPORT": "5433", "PGUSER": "u", "PGPASSWORD": "p", "PGDATABASE": "d", "PGSSLMODE": "disable",
		"PG_MAX_CONNS": "3", "DB_MIGRATE_ON_START": "false", "STORE": "memory",
		"VALIDATOR_PRINCIPALS": "a@clients,b@clients", "TOKEN_MAX_ACTIVE_PER_AUDIENCE": "7",
	}))
	require.NoError(t, err)

	assert.Equal(t, ":9090", cfg.ServerAddress())
	assert.True(t, cfg.Debug)
	assert.Equal(t, "http://h:1/jwks", cfg.JWKSUrl)
	assert.Equal(t, "aud", cfg.Audience)
	assert.Equal(t, "iss", cfg.Issuer)
	assert.Equal(t, "alice", cfg.MockLocalPrincipal)
	assert.True(t, cfg.DatabaseConfigured())
	assert.Equal(t, 3, cfg.PGMaxConns)
	assert.False(t, cfg.MigrateOnStart)
	assert.Equal(t, "memory", cfg.Store)
	assert.Equal(t, "a@clients,b@clients", cfg.ValidatorPrincipals)
	assert.Equal(t, 7, cfg.MaxActivePerAudience)
}

func TestFromEnvRejectsBadNumbersAndBooleans(t *testing.T) {
	for _, m := range []map[string]string{
		{"PG_MAX_CONNS": "0"},
		{"PG_MAX_CONNS": "ten"},
		{"TOKEN_MAX_ACTIVE_PER_AUDIENCE": "-1"},
		{"DB_MIGRATE_ON_START": "maybe"},
		{"STORE": "redis"},
	} {
		_, err := FromEnv(env(m))
		assert.Error(t, err, "%v", m)
	}
}

func TestPostgresURLEscapesCredentials(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{
		"PGHOST": "db.internal", "PGUSER": "pat@svc", "PGPASSWORD": "p@ss:w/rd?#", "PGDATABASE": "pat", "PGSSLMODE": "verify-full",
	}))
	require.NoError(t, err)

	for _, scheme := range []string{"postgres", "pgx5"} {
		u, err := url.Parse(cfg.PostgresURL(scheme))
		require.NoError(t, err)
		assert.Equal(t, scheme, u.Scheme)
		assert.Equal(t, "pat@svc", u.User.Username())
		pw, _ := u.User.Password()
		assert.Equal(t, "p@ss:w/rd?#", pw)
		assert.Equal(t, "db.internal:5432", u.Host)
		assert.Equal(t, "/pat", u.Path)
		assert.Equal(t, "verify-full", u.Query().Get("sslmode"))
	}
}

func TestDatabaseConfiguredNeedsAllFour(t *testing.T) {
	full := map[string]string{"PGHOST": "h", "PGUSER": "u", "PGPASSWORD": "p", "PGDATABASE": "d"}
	for missing := range full {
		m := map[string]string{}
		for k, v := range full {
			if k != missing {
				m[k] = v
			}
		}
		cfg, err := FromEnv(env(m))
		require.NoError(t, err)
		assert.False(t, cfg.DatabaseConfigured(), "missing %s", missing)
	}
}
