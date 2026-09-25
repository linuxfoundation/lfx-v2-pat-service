// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package postgres holds the pgx connection pool, the migration runner and the repositories.
package postgres

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
)

// readyTimeout bounds the readiness ping so a hung database cannot wedge the probe; startupPingTimeout bounds
// the connectivity check in NewPool so an unroutable database fails startup instead of waiting on the OS.
const (
	readyTimeout       = time.Second
	startupPingTimeout = 5 * time.Second
)

// Pool wraps a pgx pool and reports readiness.
type Pool struct {
	*pgxpool.Pool
}

var _ port.Readiness = (*Pool)(nil)

// NewPool opens an instrumented pool and verifies connectivity with a ping. url is the postgres:// form.
func NewPool(ctx context.Context, url string, maxConns int) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		// The parser error can quote the URL, and the URL carries the password.
		return nil, fmt.Errorf("parse database config: invalid connection settings (redacted)")
	}
	cfg.MaxConns = int32(maxConns) //nolint:gosec // bounded by config validation
	cfg.ConnConfig.Tracer = otelpgx.NewTracer()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, startupPingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		// Close in the background so a failed ping returns immediately rather than waiting for the pool to
		// drain; an unreachable database must not wedge startup past the liveness probe.
		go pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Pool{Pool: pool}, nil
}

// Ready implements port.Readiness.
func (p *Pool) Ready(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	return p.Ping(ctx) == nil
}

// storeErr classifies a pgx error. A server-side SQL error is a defect in this code, so it surfaces as
// Unexpected (500); anything else is the connection or the context, which is a dependency outage (503).
func storeErr(op string, err error) error {
	if stderrors.Is(err, pgx.ErrNoRows) {
		return errors.NewNotFound(op + ": no rows")
	}
	var pgErr *pgconn.PgError
	if stderrors.As(err, &pgErr) {
		return errors.NewUnexpected(op, err)
	}
	return errors.NewServiceUnavailable("database unavailable", fmt.Errorf("%s: %w", op, err))
}
