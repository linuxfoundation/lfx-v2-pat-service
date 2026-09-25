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
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/postgres"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
)

// Container holds all application dependencies.
type Container struct {
	Config *config.Config

	Auth      domain.Authenticator
	Manager   *service.Manager
	Validator *service.Validator
	Readiness port.Readiness

	Service *patsvc.Service

	pool *postgres.Pool
}

// store groups the adapters one backend provides.
type store struct {
	tokens interface {
		port.TokenReader
		port.TokenWriter
		port.CredentialReader
	}
	audiences port.AudienceReader
	readiness port.Readiness
}

// NewContainer creates and wires all application dependencies.
func NewContainer(ctx context.Context, cfg *config.Config) (*Container, error) {
	slog.Info("initializing dependency container")

	authenticator, err := newAuthenticator(cfg)
	if err != nil {
		return nil, err
	}

	c := &Container{Config: cfg, Auth: authenticator}
	st, err := c.newStore(ctx, cfg)
	if err != nil {
		return nil, err
	}

	c.Manager = service.NewManager(st.tokens, st.tokens, st.audiences, cfg.MaxActivePerAudience)
	c.Validator = service.NewValidator(st.tokens)
	c.Readiness = st.readiness
	c.Service = patsvc.New(patsvc.Deps{
		Auth:      c.Auth,
		Manager:   c.Manager,
		Validator: c.Validator,
		Ready:     c.Readiness.Ready,
	})

	slog.Info("dependency container initialized", "store", cfg.Store)
	return c, nil
}

// Close releases the database pool.
func (c *Container) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Ready reports whether the container can serve requests.
func (c *Container) Ready(ctx context.Context) bool {
	return c.Readiness.Ready(ctx)
}

func (c *Container) newStore(ctx context.Context, cfg *config.Config) (store, error) {
	if cfg.Store == constants.StoreMemory {
		slog.Warn("using the in-memory token store: nothing persists across restarts")
		audiences := mock.NewAudienceRepository()
		tokens := mock.NewTokenRepository(audiences)
		return store{tokens: tokens, audiences: audiences, readiness: tokens}, nil
	}

	if !cfg.DatabaseConfigured() {
		return store{}, fmt.Errorf("%s=%s requires %s, %s, %s and %s", constants.EnvStore, constants.StorePostgres,
			constants.EnvPGHost, constants.EnvPGUser, constants.EnvPGPassword, constants.EnvPGDatabase)
	}
	if cfg.MigrateOnStart {
		slog.Info("applying database migrations")
		if err := postgres.Migrate(cfg.PostgresURL("pgx5")); err != nil {
			return store{}, fmt.Errorf("migrate database: %w", err)
		}
	}
	pool, err := postgres.NewPool(ctx, cfg.PostgresURL("postgres"), cfg.PGMaxConns)
	if err != nil {
		return store{}, fmt.Errorf("connect to database: %w", err)
	}
	c.pool = pool
	return store{
		tokens:    postgres.NewTokenRepository(pool),
		audiences: postgres.NewAudienceRepository(pool),
		readiness: pool,
	}, nil
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
