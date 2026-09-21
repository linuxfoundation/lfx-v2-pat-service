// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package service is the Goa adapter: it implements the generated Service and Auther interfaces and maps
// between transport payloads and the use-cases.
package service

import (
	"context"
	"fmt"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"goa.design/goa/v3/security"
)

// Service implements the generated service interface.
type Service struct {
	// ready reports whether the service can accept inbound requests. Injected so readiness can follow the
	// database once one is wired, and so tests can flip it.
	ready func(context.Context) bool
}

// Ensure Service satisfies the generated interfaces.
var (
	_ svc.Service = (*Service)(nil)
	_ svc.Auther  = (*Service)(nil)
)

// New constructs the adapter. ready is consulted by the readiness probe on every call.
func New(ready func(context.Context) bool) *Service {
	return &Service{ready: ready}
}

// JWTAuth implements the JWT security scheme. Verification lands with the auth adapter; until then every
// token method answers 501, so passing the context through grants nothing.
func (s *Service) JWTAuth(ctx context.Context, _ string, _ *security.JWTScheme) (context.Context, error) {
	return ctx, nil
}

// CreateToken implements create-token.
func (s *Service) CreateToken(_ context.Context, _ *svc.CreateTokenPayload) (*svc.CreateTokenResult, error) {
	return nil, notImplemented("create-token")
}

// ListTokens implements list-tokens.
func (s *Service) ListTokens(_ context.Context, _ *svc.ListTokensPayload) (*svc.ListTokensResult, error) {
	return nil, notImplemented("list-tokens")
}

// GetToken implements get-token.
func (s *Service) GetToken(_ context.Context, _ *svc.GetTokenPayload) (*svc.TokenResponse, error) {
	return nil, notImplemented("get-token")
}

// DeleteToken implements delete-token.
func (s *Service) DeleteToken(_ context.Context, _ *svc.DeleteTokenPayload) error {
	return notImplemented("delete-token")
}

// ValidateToken implements validate-token.
func (s *Service) ValidateToken(_ context.Context, _ *svc.ValidateTokenPayload) (*svc.TokenIdentity, error) {
	return nil, notImplemented("validate-token")
}

// Readyz implements the readiness probe.
func (s *Service) Readyz(ctx context.Context) ([]byte, error) {
	if !s.ready(ctx) {
		return nil, svc.MakeServiceUnavailable(fmt.Errorf("the service is unavailable"))
	}
	return []byte("OK\n"), nil
}

// Livez implements the liveness probe. It always returns OK while the process runs: as a Kubernetes liveness
// check, the service must self-detect non-recoverable errors and exit.
func (s *Service) Livez(_ context.Context) ([]byte, error) {
	return []byte("OK\n"), nil
}

func notImplemented(method string) error {
	return svc.MakeNotImplemented(fmt.Errorf("%s is not implemented yet", method))
}
