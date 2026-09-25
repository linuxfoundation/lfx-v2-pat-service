// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package constants defines application-wide constants.
package constants

import "time"

// contextKey namespaces this service's context values so they cannot collide with keys from other packages.
type contextKey int

const (
	// RequestIDContextKey carries the X-Request-ID value through a request context.
	RequestIDContextKey contextKey = iota
	// CallerContextKey carries the authenticated domain.Caller from the security handler to the methods.
	CallerContextKey
)

// HTTP header names and server timeout defaults
const (
	RequestIDHeader = "X-Request-ID"

	DefaultShutdownTimeout   = 25 * time.Second
	DefaultReadHeaderTimeout = 60 * time.Second
	DefaultWriteTimeout      = 60 * time.Second
	DefaultIdleTimeout       = 90 * time.Second

	// The largest legitimate body is a create request of a few hundred bytes; the cap stops a client from
	// making the decoder allocate freely.
	DefaultMaxRequestBodyBytes = 64 << 10
)
