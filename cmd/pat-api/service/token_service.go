// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package service is the Goa adapter: it implements the generated Service and Auther interfaces and maps
// between transport payloads and the use-cases.
package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"goa.design/goa/v3/security"
)

// Deps are the collaborators the adapter needs.
type Deps struct {
	Auth      domain.Authenticator
	Manager   *service.Manager
	Validator *service.Validator
	// Ready is consulted by the readiness probe on every call.
	Ready func(context.Context) bool
}

// Service implements the generated service interface.
type Service struct {
	deps Deps
}

// Ensure Service satisfies the generated interfaces.
var (
	_ svc.Service = (*Service)(nil)
	_ svc.Auther  = (*Service)(nil)
)

// New constructs the adapter.
func New(deps Deps) *Service {
	return &Service{deps: deps}
}

// JWTAuth implements the JWT security scheme. Beyond verifying the token it applies one policy: the token
// routes are for the owner, so a machine principal is refused there. validate-token (the only method carrying the
// token:validate scope) is the one route machine principals may call; which ones is decided at the gateway by
// OpenFGA team membership (see the chart's RuleSet), so the service adds no list of its own.
func (s *Service) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	caller, err := s.deps.Auth.Authenticate(ctx, token)
	if err != nil {
		return ctx, wrapError(ctx, err)
	}

	validate := scheme != nil && slices.Contains(scheme.RequiredScopes, constants.ScopeValidate)
	if !validate && strings.HasSuffix(caller.Principal, constants.ClientPrincipalSuffix) {
		return ctx, svc.MakeForbidden(fmt.Errorf("machine principals cannot manage personal access tokens"))
	}

	return context.WithValue(ctx, constants.CallerContextKey, caller), nil
}

// CreateToken implements create-token.
func (s *Service) CreateToken(ctx context.Context, p *svc.CreateTokenPayload) (*svc.CreateTokenResult, error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	created, err := s.deps.Manager.Create(ctx, caller, p.Name, p.Audience)
	if err != nil {
		return nil, wrapError(ctx, err)
	}
	return &svc.CreateTokenResult{Secret: created.Secret, Token: toTokenResponse(created.Token)}, nil
}

// ListTokens implements list-tokens.
func (s *Service) ListTokens(ctx context.Context, p *svc.ListTokensPayload) (*svc.ListTokensResult, error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	var audience string
	if p.Audience != nil {
		audience = *p.Audience
	}
	tokens, err := s.deps.Manager.List(ctx, caller.Principal, audience)
	if err != nil {
		return nil, wrapError(ctx, err)
	}
	return &svc.ListTokensResult{Tokens: toTokenResponses(tokens)}, nil
}

// GetToken implements get-token.
func (s *Service) GetToken(ctx context.Context, p *svc.GetTokenPayload) (*svc.TokenResponse, error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	token, err := s.deps.Manager.Get(ctx, p.UID, caller.Principal)
	if err != nil {
		return nil, wrapError(ctx, err)
	}
	return toTokenResponse(token), nil
}

// DeleteToken implements delete-token.
func (s *Service) DeleteToken(ctx context.Context, p *svc.DeleteTokenPayload) error {
	caller, err := callerFrom(ctx)
	if err != nil {
		return err
	}
	if err := s.deps.Manager.Revoke(ctx, p.UID, caller.Principal); err != nil {
		return wrapError(ctx, err)
	}
	return nil
}

// ValidateToken implements validate-token. Every rejection of the secret itself is the same 404 body.
func (s *Service) ValidateToken(ctx context.Context, p *svc.ValidateTokenPayload) (*svc.TokenIdentity, error) {
	if _, err := callerFrom(ctx); err != nil {
		return nil, err
	}
	identity, err := s.deps.Validator.Validate(ctx, p.Secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, &svc.InvalidTokenError{Code: constants.ErrCodeInvalidToken, Message: "secret is invalid or revoked"}
		}
		return nil, wrapError(ctx, err)
	}
	return toIdentity(identity), nil
}

// Readyz implements the readiness probe.
func (s *Service) Readyz(ctx context.Context) ([]byte, error) {
	if !s.deps.Ready(ctx) {
		return nil, svc.MakeServiceUnavailable(fmt.Errorf("the service is unavailable"))
	}
	return []byte("OK\n"), nil
}

// Livez implements the liveness probe. It always returns OK while the process runs: as a Kubernetes liveness
// check, the service must self-detect non-recoverable errors and exit.
func (s *Service) Livez(_ context.Context) ([]byte, error) {
	return []byte("OK\n"), nil
}

// callerFrom returns the caller the security handler stored. Its absence means the method was reached without
// the scheme, which the design forbids, so it is reported as 401 rather than trusted.
func callerFrom(ctx context.Context) (domain.Caller, error) {
	caller, ok := ctx.Value(constants.CallerContextKey).(domain.Caller)
	if !ok || caller.Principal == "" {
		return domain.Caller{}, svc.MakeUnauthorized(fmt.Errorf("missing caller identity"))
	}
	return caller, nil
}
