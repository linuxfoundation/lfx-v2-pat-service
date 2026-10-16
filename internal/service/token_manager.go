// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package service holds the use-cases. They depend on ports only, never on Goa or a store.
package service

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/secret"
)

// CreatedToken pairs a new token with the one-time plaintext secret.
type CreatedToken struct {
	Secret string
	Token  model.Token
}

// Manager implements the owner-facing use-cases: issue, list and revoke.
type Manager struct {
	reader    port.TokenReader
	writer    port.TokenWriter
	audiences port.AudienceReader
	maxActive int
}

// NewManager wires the manager. maxActive bounds active tokens per owner and audience.
func NewManager(reader port.TokenReader, writer port.TokenWriter, audiences port.AudienceReader, maxActive int) *Manager {
	return &Manager{reader: reader, writer: writer, audiences: audiences, maxActive: maxActive}
}

// Create issues a token for the caller. The audience must exist and be enabled; the name is trimmed and must be
// unique among the caller's active tokens for that audience.
func (m *Manager) Create(ctx context.Context, caller domain.Caller, name, audienceSlug string) (CreatedToken, error) {
	name, err := normalizeName(name)
	if err != nil {
		return CreatedToken{}, err
	}
	audience, err := m.audiences.GetEnabledBySlug(ctx, audienceSlug)
	if err != nil {
		if errors.IsNotFound(err) {
			return CreatedToken{}, errors.NewValidation(
				fmt.Sprintf("%s: audience %q is unknown or disabled", constants.ErrCodeUnknownAudience, audienceSlug))
		}
		return CreatedToken{}, err
	}

	// A lookup id collision is astronomically unlikely but cheap to survive: mint again once.
	for attempt := 0; ; attempt++ {
		created, err := m.issue(ctx, caller, name, audience)
		if err == nil {
			return created, nil
		}
		if !errors.Is(err, port.ErrLookupIDTaken) || attempt == 1 {
			return CreatedToken{}, err
		}
	}
}

func (m *Manager) issue(ctx context.Context, caller domain.Caller, name string, audience model.Audience) (CreatedToken, error) {
	parts, err := secret.Generate(audience.TokenPrefix)
	if err != nil {
		return CreatedToken{}, errors.NewUnexpected("generate secret", err)
	}
	salt, err := secret.NewSalt()
	if err != nil {
		return CreatedToken{}, errors.NewUnexpected("generate salt", err)
	}
	token, err := m.writer.Create(ctx, model.NewToken{
		Username:   caller.Principal,
		Email:      caller.Email,
		Audience:   audience.Slug,
		Name:       name,
		LookupID:   parts.LookupID,
		Salt:       salt,
		SecretHash: secret.Hash(salt, parts.Random),
	}, m.maxActive)
	if err != nil {
		return CreatedToken{}, err
	}
	return CreatedToken{Secret: parts.String(), Token: token}, nil
}

// List returns the caller's active tokens, newest first, optionally limited to one audience.
func (m *Manager) List(ctx context.Context, username, audience string) ([]model.Token, error) {
	return m.reader.ListActiveByOwner(ctx, username, audience)
}

// Revoke soft-deletes one of the caller's active tokens.
func (m *Manager) Revoke(ctx context.Context, uid, username string) error {
	return m.writer.Revoke(ctx, uid, username)
}

func normalizeName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.NewValidation("name is required")
	}
	if utf8.RuneCountInString(name) > constants.TokenNameMaxLength {
		return "", errors.NewValidation(fmt.Sprintf("name must be at most %d characters", constants.TokenNameMaxLength))
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", errors.NewValidation("name must not contain control characters")
		}
	}
	return name, nil
}
