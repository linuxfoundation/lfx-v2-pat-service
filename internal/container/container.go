// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package container provides dependency injection for the application.
package container

import (
	"log/slog"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/config"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
)

// Container holds all application dependencies.
// Add your service implementations and infrastructure clients here.
type Container struct {
	Config  *config.Config
	Service svc.Service
}

// NewContainer creates and wires all application dependencies.
func NewContainer(cfg *config.Config) (*Container, error) {
	slog.Info("initializing dependency container")

	// TODO: initialize your infrastructure clients (auth, database, etc.)
	// and pass them to your service implementation.
	//
	// Example:
	//   authRepo, err := auth.NewAuthRepository(cfg.JWKSUrl, cfg.Issuer, cfg.Audience)
	//   if err != nil { return nil, err }
	//   if err != nil { return nil, err }
	//   svc := service.NewService(authRepo)

	slog.Info("dependency container initialized")
	return &Container{
		Config:  cfg,
		Service: service.NewService(),
	}, nil
}

// Close releases any resources held by the container (e.g., database pools).
func (c *Container) Close() error {
	// TODO: close any open connections here.
	return nil
}
