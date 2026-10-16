// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeimdallClaimsValidate(t *testing.T) {
	tests := []struct {
		principal string
		valid     bool
	}{
		{"alice", true},
		{"abc123@clients", true},
		{"", false},
		{"_anonymous", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.principal), func(t *testing.T) {
			err := (&HeimdallClaims{Principal: tt.principal}).Validate(context.Background())
			assert.Equal(t, tt.valid, err == nil, "got %v", err)
		})
	}
}

func TestHeimdallClaimsReadTheUserIDClaim(t *testing.T) {
	var claims HeimdallClaims
	require.NoError(t, json.Unmarshal([]byte(`{"principal":"alice","user_id":"auth0|alice-id"}`), &claims))

	assert.Equal(t, "auth0|alice-id", claims.UserID)
}

func TestNewJWTAuthRejectsBadURLs(t *testing.T) {
	_, err := NewJWTAuth(Config{JWKSURL: "http://[::1", Issuer: "heimdall", Audience: "svc"})
	assert.Error(t, err)
	_, err = NewJWTAuth(Config{JWKSURL: "http://heimdall:4457/.well-known/jwks", Issuer: "://bad", Audience: "svc"})
	assert.Error(t, err)
	_, err = NewJWTAuth(Config{JWKSURL: "jwks", Issuer: "heimdall", Audience: "svc"})
	assert.Error(t, err, "relative JWKS URL")
	_, err = NewJWTAuth(Config{JWKSURL: "ftp://heimdall/jwks", Issuer: "heimdall", Audience: "svc"})
	assert.Error(t, err, "non-http JWKS URL")
}

func TestAuthenticateRejectsMalformedTokenAsUnauthorized(t *testing.T) {
	a, err := NewJWTAuth(Config{JWKSURL: "http://127.0.0.1:1/.well-known/jwks", Issuer: "heimdall", Audience: "svc"})
	require.NoError(t, err)

	_, err = a.Authenticate(context.Background(), "not-a-jwt")

	assert.True(t, errors.IsUnauthorized(err), "got %v", err)
}

func TestSanitizeDropsDeepNesting(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"a: b", "a: b"},
		{"a: b: c", "a: b"},
		{"a: b: c: d", "a: b"},
		{"could not parse the token: go-jose/go-jose/jwt: compact JWS format must have three parts", "could not parse the token: compact JWS format must have three parts"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitize(fmt.Errorf("%s", tt.in)))
		})
	}
}

func TestStatic(t *testing.T) {
	caller := domain.Caller{Principal: "alice", Email: "alice@example.com"}
	got, err := Static{Caller: caller}.Authenticate(context.Background(), "anything")
	require.NoError(t, err)
	assert.Equal(t, caller, got)

	_, err = Static{Err: errors.NewUnauthorized("nope")}.Authenticate(context.Background(), "anything")
	assert.True(t, errors.IsUnauthorized(err))
}
