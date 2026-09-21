// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package container provides dependency injection for the application.
package container

import (
	"context"
	"log/slog"

	"github.com/linuxfoundation/lfx-v2-pat-service/cmd/pat-api/service"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/config"
)

// Container holds all application dependencies.
type Container struct {
	Config  *config.Config
	Service *service.Service
}

// NewContainer creates and wires all application dependencies.
func NewContainer(cfg *config.Config) (*Container, error) {
	slog.Info("initializing dependency container")

	// Readiness has nothing to check until the database is wired in.
	ready := func(context.Context) bool { return true }

	slog.Info("dependency container initialized")
	return &Container{
		Config:  cfg,
		Service: service.New(ready),
	}, nil
}

// Close releases any resources held by the container (e.g., database pools).
func (c *Container) Close() error {
	return nil
}
