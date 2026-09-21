// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"testing"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goa "goa.design/goa/v3/pkg"
)

func always(v bool) func(context.Context) bool {
	return func(context.Context) bool { return v }
}

func TestLivez(t *testing.T) {
	result, err := New(always(false)).Livez(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "OK\n", string(result))
}

func TestReadyz(t *testing.T) {
	tests := []struct {
		name  string
		ready bool
	}{
		{name: "ready returns OK", ready: true},
		{name: "not ready returns ServiceUnavailable", ready: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := New(always(tt.ready)).Readyz(context.Background())

			if tt.ready {
				require.NoError(t, err)
				assert.Equal(t, "OK\n", string(result))
				return
			}
			assert.Nil(t, result)
			var serr *goa.ServiceError
			require.ErrorAs(t, err, &serr)
			assert.Equal(t, "ServiceUnavailable", serr.Name)
			assert.True(t, serr.Temporary)
		})
	}
}

func TestJWTAuthPassesContextThrough(t *testing.T) {
	ctx := context.Background()

	got, err := New(always(true)).JWTAuth(ctx, "any", nil)

	require.NoError(t, err)
	assert.Equal(t, ctx, got)
}

func TestTokenMethodsAreNotImplemented(t *testing.T) {
	s := New(always(true))
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"create-token", func() error { _, err := s.CreateToken(ctx, &svc.CreateTokenPayload{}); return err }},
		{"list-tokens", func() error { _, err := s.ListTokens(ctx, &svc.ListTokensPayload{}); return err }},
		{"get-token", func() error { _, err := s.GetToken(ctx, &svc.GetTokenPayload{}); return err }},
		{"delete-token", func() error { return s.DeleteToken(ctx, &svc.DeleteTokenPayload{}) }},
		{"validate-token", func() error { _, err := s.ValidateToken(ctx, &svc.ValidateTokenPayload{}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var serr *goa.ServiceError
			require.ErrorAs(t, tt.call(), &serr)
			assert.Equal(t, "NotImplemented", serr.Name)
		})
	}
}
