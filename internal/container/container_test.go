// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package container

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/auth"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewContainerWithMockPrincipal(t *testing.T) {
	cfg, err := config.FromEnv(func(k string) string {
		return map[string]string{
			"JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL": "alice",
			"VALIDATOR_PRINCIPALS":                   "alice",
			"STORE":                                  "memory",
		}[k]
	})
	require.NoError(t, err)

	c, err := NewContainer(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	assert.IsType(t, auth.Static{}, c.Auth)
	caller, err := c.Auth.Authenticate(context.Background(), "ignored")
	require.NoError(t, err)
	assert.Equal(t, "alice", caller.Principal)
	assert.True(t, c.Validators.Allowed("alice"))
	assert.True(t, c.Ready(context.Background()))
	require.NotNil(t, c.Service)
	out, err := c.Service.Readyz(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "OK\n", string(out))
}

func TestNewContainerWithJWTAuth(t *testing.T) {
	cfg, err := config.FromEnv(func(k string) string { return map[string]string{"STORE": "memory"}[k] })
	require.NoError(t, err)

	c, err := NewContainer(context.Background(), cfg)
	require.NoError(t, err)

	assert.IsType(t, &auth.JWTAuth{}, c.Auth)
	assert.False(t, c.Validators.Allowed("anyone"))
}

func TestNewContainerRejectsBadJWKSURL(t *testing.T) {
	cfg, err := config.FromEnv(func(k string) string {
		return map[string]string{"JWKS_URL": "http://[::1", "STORE": "memory"}[k]
	})
	require.NoError(t, err)

	_, err = NewContainer(context.Background(), cfg)

	assert.Error(t, err)
}

func TestNewContainerPostgresNeedsCredentials(t *testing.T) {
	cfg, err := config.FromEnv(func(string) string { return "" })
	require.NoError(t, err)

	_, err = NewContainer(context.Background(), cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "PGHOST")
}

// TestNewContainerWithPostgres exercises the migrate-then-connect path against the database named by
// TEST_DATABASE_URL, the same opt-in the live repository tests use.
func TestNewContainerWithPostgres(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	u, err := url.Parse(raw)
	require.NoError(t, err)
	password, _ := u.User.Password()
	env := map[string]string{
		"STORE":                                  "postgres",
		"PGHOST":                                 u.Hostname(),
		"PGPORT":                                 u.Port(),
		"PGUSER":                                 u.User.Username(),
		"PGPASSWORD":                             password,
		"PGDATABASE":                             strings.TrimPrefix(u.Path, "/"),
		"PGSSLMODE":                              u.Query().Get("sslmode"),
		"JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL": "alice",
	}
	cfg, err := config.FromEnv(func(k string) string { return env[k] })
	require.NoError(t, err)

	c, err := NewContainer(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	assert.True(t, c.Ready(context.Background()))
	created, err := c.Manager.Create(context.Background(), domain.Caller{Principal: "alice"}, "container-test", "insights")
	require.NoError(t, err)
	require.NoError(t, c.Manager.Revoke(context.Background(), created.Token.UID, "alice"))
}
