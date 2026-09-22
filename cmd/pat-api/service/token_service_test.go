// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"fmt"
	"testing"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/auth"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/mock"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	pkgerrors "github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goa "goa.design/goa/v3/pkg"
)

// bearerAuth resolves the bearer token itself as the principal, so a request chooses its caller by sending
// "Authorization: Bearer <principal>". An empty token is unauthenticated.
type bearerAuth struct{}

func (bearerAuth) Authenticate(_ context.Context, token string) (domain.Caller, error) {
	if token == "" {
		return domain.Caller{}, pkgerrors.NewUnauthorized("missing bearer token")
	}
	return domain.Caller{Principal: token, Email: token + "@example.com"}, nil
}

func newDeps(ready bool, authenticator domain.Authenticator) (Deps, *mock.TokenRepository) {
	audiences := mock.NewAudienceRepository()
	tokens := mock.NewTokenRepository(audiences)
	tokens.SetReady(ready)
	return Deps{
		Auth:      authenticator,
		Manager:   service.NewManager(tokens, tokens, audiences, 3),
		Validator: service.NewValidator(tokens),
		Ready:     tokens.Ready,
	}, tokens
}

func serviceErrorName(t *testing.T, err error) string {
	t.Helper()
	var serr *goa.ServiceError
	require.ErrorAs(t, err, &serr)
	return serr.Name
}

func TestLivez(t *testing.T) {
	deps, _ := newDeps(false, bearerAuth{})

	result, err := New(deps).Livez(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "OK\n", string(result))
}

func TestReadyz(t *testing.T) {
	for _, ready := range []bool{true, false} {
		t.Run(fmt.Sprintf("ready=%v", ready), func(t *testing.T) {
			deps, _ := newDeps(ready, bearerAuth{})

			result, err := New(deps).Readyz(context.Background())

			if ready {
				require.NoError(t, err)
				assert.Equal(t, "OK\n", string(result))
				return
			}
			assert.Nil(t, result)
			assert.Equal(t, "ServiceUnavailable", serviceErrorName(t, err))
		})
	}
}

func TestJWTAuthStoresCaller(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantError string
	}{
		{"user", "alice", ""},
		{"machine", "abc123@clients", ""},
		{"missing token", "", "Unauthorized"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newDeps(true, bearerAuth{})

			ctx, err := New(deps).JWTAuth(context.Background(), tt.token, nil)

			if tt.wantError != "" {
				assert.Equal(t, tt.wantError, serviceErrorName(t, err))
				return
			}
			require.NoError(t, err)
			caller, ok := ctx.Value(constants.CallerContextKey).(domain.Caller)
			require.True(t, ok)
			assert.Equal(t, tt.token, caller.Principal)
		})
	}
}

func TestTokenRoutesRefuseMachinePrincipals(t *testing.T) {
	deps, _ := newDeps(true, bearerAuth{})
	s := New(deps)
	ctx := context.WithValue(context.Background(), constants.CallerContextKey, domain.Caller{Principal: "abc123@clients"})

	_, err := s.CreateToken(ctx, &svc.CreateTokenPayload{Name: "ci", Audience: constants.AudienceInsights})
	assert.Equal(t, "Forbidden", serviceErrorName(t, err))
	_, err = s.ListTokens(ctx, &svc.ListTokensPayload{})
	assert.Equal(t, "Forbidden", serviceErrorName(t, err))
	_, err = s.GetToken(ctx, &svc.GetTokenPayload{UID: "x"})
	assert.Equal(t, "Forbidden", serviceErrorName(t, err))
	assert.Equal(t, "Forbidden", serviceErrorName(t, s.DeleteToken(ctx, &svc.DeleteTokenPayload{UID: "x"})))

	// validate-token is the machine route: the same caller reaches the credential check.
	_, err = s.ValidateToken(ctx, &svc.ValidateTokenPayload{Secret: "lfi_x"})
	var invalid *svc.InvalidTokenError
	assert.ErrorAs(t, err, &invalid)
}

func TestJWTAuthMapsAuthenticatorFailures(t *testing.T) {
	deps, _ := newDeps(true, auth.Static{Err: pkgerrors.NewUnexpected("jwks down")})

	_, err := New(deps).JWTAuth(context.Background(), "x", nil)

	assert.Equal(t, "InternalServerError", serviceErrorName(t, err))
}

func TestMethodsRequireCallerInContext(t *testing.T) {
	deps, _ := newDeps(true, bearerAuth{})
	s := New(deps)
	ctx := context.Background()

	_, err := s.CreateToken(ctx, &svc.CreateTokenPayload{Name: "ci", Audience: constants.AudienceInsights})
	assert.Equal(t, "Unauthorized", serviceErrorName(t, err))
	_, err = s.ListTokens(ctx, &svc.ListTokensPayload{})
	assert.Equal(t, "Unauthorized", serviceErrorName(t, err))
	_, err = s.GetToken(ctx, &svc.GetTokenPayload{UID: "x"})
	assert.Equal(t, "Unauthorized", serviceErrorName(t, err))
	assert.Equal(t, "Unauthorized", serviceErrorName(t, s.DeleteToken(ctx, &svc.DeleteTokenPayload{UID: "x"})))
	_, err = s.ValidateToken(ctx, &svc.ValidateTokenPayload{Secret: "x"})
	assert.Equal(t, "Unauthorized", serviceErrorName(t, err))
}

func TestWrapError(t *testing.T) {
	cause := fmt.Errorf("db exploded")
	tests := []struct {
		name    string
		err     error
		want    string
		message string
	}{
		{"not found", pkgerrors.NewNotFound("no token", cause), "NotFound", "no token"},
		{"validation", pkgerrors.NewValidation("bad name"), "BadRequest", "bad name"},
		{"unauthorized", pkgerrors.NewUnauthorized("expired"), "Unauthorized", "expired"},
		{"forbidden", pkgerrors.NewForbidden("nope"), "Forbidden", "nope"},
		{"unavailable hides cause", pkgerrors.NewServiceUnavailable("database unavailable", cause), "ServiceUnavailable", "database unavailable"},
		{"unexpected is redacted", pkgerrors.NewUnexpected("boom", cause), "InternalServerError", "internal service error"},
		{"plain error is redacted", cause, "InternalServerError", "internal service error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var serr *goa.ServiceError
			require.ErrorAs(t, wrapError(context.Background(), tt.err), &serr)
			assert.Equal(t, tt.want, serr.Name)
			assert.Equal(t, tt.message, serr.Message)
			assert.NotContains(t, serr.Message, "exploded")
		})
	}
}

func TestWrapErrorConflictKeepsCode(t *testing.T) {
	err := wrapError(context.Background(), pkgerrors.NewConflict(constants.ErrCodeTokenLimitReached, "too many"))

	var conflict *svc.ConflictError
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, constants.ErrCodeTokenLimitReached, conflict.Code)
	assert.Equal(t, "too many", conflict.Message)
	assert.Equal(t, "Conflict", conflict.GoaErrorName())
}
