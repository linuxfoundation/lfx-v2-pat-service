// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package container provides dependency injection for the application.
package container

import (
	"context"
	"fmt"
	"log/slog"

	patsvc "github.com/linuxfoundation/lfx-v2-pat-service/cmd/pat-api/service"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/auth"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/config"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/mock"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
)

// Container holds all application dependencies.
type Container struct {
	Config *config.Config

	Auth      domain.Authenticator
	Manager   *service.Manager
	Validator *service.Validator
	Readiness port.Readiness

	Service *patsvc.Service
}

// NewContainer creates and wires all application dependencies.
func NewContainer(cfg *config.Config) (*Container, error) {
	slog.Info("initializing dependency container")

	authenticator, err := newAuthenticator(cfg)
	if err != nil {
		return nil, err
	}

	// The Postgres adapter lands next; until then every run uses the in-memory store.
	audiences := mock.NewAudienceRepository()
	tokens := mock.NewTokenRepository(audiences)
	slog.Warn("using the in-memory token store: nothing persists across restarts")

	c := &Container{
		Config:    cfg,
		Auth:      authenticator,
		Manager:   service.NewManager(tokens, tokens, audiences, cfg.MaxActivePerAudience),
		Validator: service.NewValidator(tokens),
		Readiness: tokens,
	}
	c.Service = patsvc.New(c.Readiness.Ready)

	slog.Info("dependency container initialized")
	return c, nil
}

// Close releases any resources held by the container (e.g., database pools).
func (c *Container) Close() error {
	return nil
}

func newAuthenticator(cfg *config.Config) (domain.Authenticator, error) {
	if cfg.MockLocalPrincipal != "" {
		slog.Warn("JWT verification is disabled: every request is attributed to the mock principal",
			"principal", cfg.MockLocalPrincipal)
		return auth.Static{Caller: domain.Caller{Principal: cfg.MockLocalPrincipal}}, nil
	}
	jwtAuth, err := auth.NewJWTAuth(auth.Config{JWKSURL: cfg.JWKSUrl, Issuer: cfg.Issuer, Audience: cfg.Audience})
	if err != nil {
		return nil, fmt.Errorf("configure JWT authentication: %w", err)
	}
	return jwtAuth, nil
}

// Ready reports whether the container can serve requests.
func (c *Container) Ready(ctx context.Context) bool {
	return c.Readiness.Ready(ctx)
}
