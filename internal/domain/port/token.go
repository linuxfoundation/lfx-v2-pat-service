// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import (
	"context"
	"errors"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
)

// ErrLookupIDTaken is returned by TokenWriter.Create when the generated lookup id already exists. The caller
// mints a new secret and retries once.
var ErrLookupIDTaken = errors.New("lookup id already exists")

// TokenReader reads the owner's view of tokens. Every method is scoped to an owner; a token owned by someone
// else is reported as NotFound.
type TokenReader interface {
	// ListActiveByOwner returns the owner's active tokens, expired ones included, newest first. An empty audience
	// means all audiences.
	ListActiveByOwner(ctx context.Context, username, audience string) ([]model.Token, error)
}

// TokenWriter issues and revokes tokens.
type TokenWriter interface {
	// Create stores a new token. It returns a Conflict error with code token_name_taken when the owner already
	// has an active token with the same name (case-insensitive) for the audience, a Conflict with code
	// token_limit_reached when the owner already has maxActive active tokens for the audience, and
	// ErrLookupIDTaken on a lookup id collision. The uniqueness and limit checks are atomic with the insert.
	Create(ctx context.Context, t model.NewToken, maxActive int) (model.Token, error)
	// Revoke soft-deletes one of the owner's active tokens, or returns a NotFound error.
	Revoke(ctx context.Context, uid, username string) error
}

// CredentialReader serves the validation hot path.
type CredentialReader interface {
	// FindActiveByLookupID returns the credential for an active, unexpired token whose audience is enabled and
	// uses the given prefix, or a NotFound error.
	FindActiveByLookupID(ctx context.Context, lookupID, prefix string) (model.Credential, error)
	// TouchLastUsed records a successful validation of an active, unexpired token. It must not change UpdatedAt.
	TouchLastUsed(ctx context.Context, uid string) error
}

// Readiness reports whether the store can serve requests.
type Readiness interface {
	Ready(ctx context.Context) bool
}
