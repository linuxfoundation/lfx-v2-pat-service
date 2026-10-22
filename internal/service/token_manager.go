// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package service holds the use-cases. They depend on ports only, never on Goa or a store.
package service

import (
	"context"
	"fmt"
	"strings"
	"time"
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
	now       func() time.Time
}

// NewManager wires the manager. maxActive bounds active tokens per owner and audience.
func NewManager(reader port.TokenReader, writer port.TokenWriter, audiences port.AudienceReader, maxActive int) *Manager {
	return &Manager{reader: reader, writer: writer, audiences: audiences, maxActive: maxActive, now: time.Now}
}

// SetClock replaces the clock expirations are counted from, for tests that move time.
func (m *Manager) SetClock(now func() time.Time) {
	m.now = now
}

// Create issues a token for the caller in an enabled audience; the trimmed name must be unique among the caller's
// active tokens there. An empty expiration means none (see constants.Expiration*).
func (m *Manager) Create(ctx context.Context, caller domain.Caller, name, audienceSlug, expiration string) (CreatedToken, error) {
	name, err := normalizeName(name)
	if err != nil {
		return CreatedToken{}, err
	}
	expiresAt, err := expiresAt(m.now(), expiration)
	if err != nil {
		return CreatedToken{}, err
	}
	audience, err := m.audiences.GetEnabledBySlug(ctx, audienceSlug)
	if err != nil {
		if errors.IsNotFound(err) {
			return CreatedToken{}, errors.NewValidation(constants.ErrCodeUnknownAudience,
				fmt.Sprintf("audience %q is unknown or disabled", audienceSlug))
		}
		return CreatedToken{}, err
	}

	// A lookup id collision is astronomically unlikely but cheap to survive: mint again once.
	for attempt := 0; ; attempt++ {
		created, err := m.issue(ctx, caller, name, audience, expiresAt)
		if err == nil {
			return created, nil
		}
		if !errors.Is(err, port.ErrLookupIDTaken) || attempt == 1 {
			return CreatedToken{}, err
		}
	}
}

func (m *Manager) issue(ctx context.Context, caller domain.Caller, name string, audience model.Audience, expiresAt *time.Time) (CreatedToken, error) {
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
		ExpiresAt:  expiresAt,
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

// expiresAt returns when a token created at now expires, or nil when it never does. A year is a calendar year,
// so a token created on 7 September expires on 7 September.
func expiresAt(now time.Time, expiration string) (*time.Time, error) {
	var at time.Time
	switch expiration {
	case "", constants.ExpirationNone:
		return nil, nil
	case constants.Expiration30Days:
		at = now.AddDate(0, 0, 30)
	case constants.Expiration60Days:
		at = now.AddDate(0, 0, 60)
	case constants.Expiration90Days:
		at = now.AddDate(0, 0, 90)
	case constants.Expiration1Year:
		at = now.AddDate(1, 0, 0)
	default:
		return nil, errors.NewValidation(constants.ErrCodeInvalidExpiration, fmt.Sprintf("expiration %q is not supported", expiration))
	}
	// Responses render RFC3339 whole seconds, so the enforced deadline carries none either.
	at = at.Truncate(time.Second).UTC()
	return &at, nil
}

func normalizeName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.NewValidation(constants.ErrCodeInvalidName, "name is required")
	}
	if utf8.RuneCountInString(name) > constants.TokenNameMaxLength {
		return "", errors.NewValidation(constants.ErrCodeInvalidName, fmt.Sprintf("name must be at most %d characters", constants.TokenNameMaxLength))
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", errors.NewValidation(constants.ErrCodeInvalidName, "name must not contain control characters")
		}
	}
	return name, nil
}
