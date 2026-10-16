// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package domain holds the ports the use-cases depend on and the caller identity they receive.
package domain

import "context"

// Caller is the identity resolved from a Heimdall-issued JWT. Principal is the LFID username for users and
// "<client_id>@clients" for machine tokens; Email is present only when Heimdall's contextualizer supplied a
// verified one.
type Caller struct {
	Principal string
	Email     string
}

// Authenticator verifies a bearer token and resolves the caller behind it.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Caller, error)
}
