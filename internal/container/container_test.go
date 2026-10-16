// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package container

import (
	"context"
	"testing"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/auth"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewContainerWithMockPrincipal(t *testing.T) {
	cfg, err := config.FromEnv(func(k string) string {
		return map[string]string{
			"JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL": "alice",
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
	assert.NotEmpty(t, caller.UserID, "the mock caller must be able to issue tokens")
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
