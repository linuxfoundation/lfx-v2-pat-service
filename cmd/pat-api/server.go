// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package main wires up the HTTP server.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"sync"

	svcsvr "github.com/linuxfoundation/lfx-v2-pat-service/gen/http/lfx_v2_pat_service/server"
	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/container"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/config"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/middleware"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/log"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"goa.design/clue/debug"
	goahttp "goa.design/goa/v3/http"
)

// StartServer initializes and starts the HTTP server.
func StartServer(ctx context.Context, cfg *config.Config) error {
	cont, err := container.NewContainer(cfg)
	if err != nil {
		return err
	}

	// Payload logging stays off even in debug mode: the create response and the validate request carry
	// plaintext secrets.
	endpoints := svc.NewEndpoints(cont.Service)

	return handleHTTPServer(ctx, cfg, endpoints, cont)
}

func handleHTTPServer(ctx context.Context, cfg *config.Config, endpoints *svc.Endpoints, cont *container.Container) error {
	mux := goahttp.NewMuxer()
	if cfg.Debug {
		debug.MountPprofHandlers(debug.Adapt(mux))
		debug.MountDebugLogEnabler(debug.Adapt(mux))
	}

	eh := errorHandler(ctx)
	server := svcsvr.New(
		endpoints,
		mux,
		goahttp.RequestDecoder,
		goahttp.ResponseEncoder,
		eh,
		nil,
		http.Dir(koDataPath()),
	)
	svcsvr.Mount(mux, server)

	var handler http.Handler = mux
	handler = middleware.RequestIDMiddleware()(handler)
	if cfg.Debug {
		handler = debug.HTTP()(handler)
	}
	handler = otelhttp.NewHandler(handler, "lfx-v2-pat-service")

	srv := &http.Server{
		Addr:              cfg.ServerAddress(),
		Handler:           handler,
		ReadHeaderTimeout: constants.DefaultReadHeaderTimeout,
		WriteTimeout:      constants.DefaultWriteTimeout,
		IdleTimeout:       constants.DefaultIdleTimeout,
	}

	return runServerWithContext(ctx, srv, cont)
}

// koDataPath is the directory holding gen/http/openapi3.json. ko and the Dockerfile place it under
// KO_DATA_PATH; a local run serves it from the repository root.
func koDataPath() string {
	if p := os.Getenv(constants.EnvKoDataPath); p != "" {
		return p
	}
	return constants.DefaultKoDataPath
}

func errorHandler(logCtx context.Context) func(context.Context, http.ResponseWriter, error) {
	return func(ctx context.Context, _ http.ResponseWriter, err error) {
		slog.ErrorContext(ctx, "HTTP error occurred", log.ErrKey, err, "outer_context", logCtx)
	}
}

func runServerWithContext(ctx context.Context, srv *http.Server, cont *container.Container) error {
	serverErr := make(chan error, 1)

	go func() {
		slog.InfoContext(ctx, "LFX V2 Personal Access Token Service listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		slog.InfoContext(ctx, "shutdown initiated")
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), constants.DefaultShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.ErrorContext(ctx, "HTTP server shutdown error", log.ErrKey, err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := cont.Close(); err != nil {
			slog.ErrorContext(ctx, "container close error", log.ErrKey, err)
		}
	}()

	wg.Wait()
	return nil
}
