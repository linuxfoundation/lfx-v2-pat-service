// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/log"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/secret"
)

// Validator resolves a presented secret to its owner. Every rejection is the same NotFound so callers cannot
// tell an unknown secret from a revoked one.
type Validator struct {
	creds port.CredentialReader
	// apiIdentifiers maps an audience slug to the identifier of the Auth0 API its tokens are exchanged for.
	apiIdentifiers map[string]string
}

// NewValidator wires the validator.
func NewValidator(creds port.CredentialReader, apiIdentifiers map[string]string) *Validator {
	return &Validator{creds: creds, apiIdentifiers: apiIdentifiers}
}

// Validate checks the secret and records the use. A failure to record the use is logged and does not fail the
// validation: the token is valid either way.
func (v *Validator) Validate(ctx context.Context, plain string) (model.TokenIdentity, error) {
	parts, err := secret.Parse(plain)
	if err != nil {
		return model.TokenIdentity{}, invalid()
	}
	cred, err := v.creds.FindActiveByLookupID(ctx, parts.LookupID, parts.Prefix)
	if err != nil {
		if errors.IsNotFound(err) {
			return model.TokenIdentity{}, invalid()
		}
		return model.TokenIdentity{}, err
	}
	if !secret.Verify(cred.Salt, cred.SecretHash, parts.Random) {
		return model.TokenIdentity{}, invalid()
	}
	if cred.UserID == "" {
		slog.WarnContext(ctx, "token predates owner user ID capture and cannot be exchanged", "uid", cred.UID)
		return model.TokenIdentity{}, invalid()
	}
	apiIdentifier, ok := v.apiIdentifiers[cred.Audience]
	if !ok {
		return model.TokenIdentity{}, errors.NewUnexpected(fmt.Sprintf("audience %q has no API identifier configured", cred.Audience))
	}
	if err := v.creds.TouchLastUsed(ctx, cred.UID); err != nil {
		slog.WarnContext(ctx, "recording token use failed", log.ErrKey, err, "uid", cred.UID)
	}
	return model.TokenIdentity{
		UserID:   cred.UserID,
		Username: cred.Username,
		Audience: apiIdentifier,
		Email:    cred.Email,
	}, nil
}

func invalid() error {
	return errors.NewNotFound("secret is invalid or revoked")
}
