// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service_test

import (
	"context"
	"testing"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/mock"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateResolvesOwnerAndRecordsUse(t *testing.T) {
	f := newFixture(25)
	created := f.create(t, alice, "ci", constants.AudienceInsights)
	validator := service.NewValidator(f.tokens, apiIdentifiers)

	identity, err := validator.Validate(context.Background(), created.Secret)

	require.NoError(t, err)
	assert.Equal(t, model.TokenIdentity{
		UserID:   "auth0|alice-id",
		Username: "alice",
		Audience: "https://insights-api.test/",
		Email:    "alice@example.com",
	}, identity)

	after := f.active(t, "alice", created.Token.UID)
	require.NotNil(t, after.LastUsedAt)
	assert.Equal(t, created.Token.UpdatedAt, after.UpdatedAt, "recording a use must not move UpdatedAt")
}

func TestValidateRejections(t *testing.T) {
	f := newFixture(25)
	created := f.create(t, alice, "ci", constants.AudienceInsights)
	revoked := f.create(t, alice, "old", constants.AudienceInsights)
	require.NoError(t, f.manager.Revoke(context.Background(), revoked.Token.UID, "alice"))
	unstored, err := secret.Generate("lfi_")
	require.NoError(t, err)
	wrongRandom := created.Secret[:len(created.Secret)-1] + flip(created.Secret[len(created.Secret)-1])
	validator := service.NewValidator(f.tokens, apiIdentifiers)

	tests := []struct {
		name   string
		secret string
	}{
		{"empty", ""},
		{"malformed", "lfi_short"},
		{"unknown lookup id", unstored.String()},
		{"wrong random part", wrongRandom},
		{"revoked", revoked.Secret},
		{"prefix of another audience", "lfo_" + created.Secret[4:]},
		{"prefix without audience", "zzz_" + created.Secret[4:]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.Validate(context.Background(), tt.secret)
			assert.True(t, errors.IsNotFound(err), "got %v", err)
		})
	}

	// None of the rejections recorded a use.
	still := f.active(t, "alice", created.Token.UID)
	assert.Nil(t, still.LastUsedAt)
}

func TestValidateFailsClosedWhenAudienceDisabledAfterIssuance(t *testing.T) {
	f := newFixture(25)
	created := f.create(t, alice, "ci", constants.AudienceInsights)
	disabled := mock.SeedAudience
	disabled.Enabled = false
	f.audiences.Set(disabled)

	_, err := service.NewValidator(f.tokens, apiIdentifiers).Validate(context.Background(), created.Secret)

	assert.True(t, errors.IsNotFound(err))
}

// flakyTouch fails every TouchLastUsed.
type flakyTouch struct {
	port.CredentialReader
}

func (flakyTouch) TouchLastUsed(context.Context, string) error {
	return errors.NewUnexpected("write failed")
}

func TestValidateSucceedsWhenRecordingUseFails(t *testing.T) {
	f := newFixture(25)
	created := f.create(t, alice, "ci", constants.AudienceInsights)

	identity, err := service.NewValidator(flakyTouch{CredentialReader: f.tokens}, apiIdentifiers).Validate(context.Background(), created.Secret)

	require.NoError(t, err)
	assert.Equal(t, "auth0|alice-id", identity.UserID)
}

func TestValidateRejectsATokenIssuedWithoutUserID(t *testing.T) {
	f := newFixture(25)
	parts, err := secret.Generate("lfi_")
	require.NoError(t, err)
	salt, err := secret.NewSalt()
	require.NoError(t, err)
	legacy, err := f.tokens.Create(context.Background(), model.NewToken{
		Username:   "alice",
		Audience:   constants.AudienceInsights,
		Name:       "legacy",
		LookupID:   parts.LookupID,
		Salt:       salt,
		SecretHash: secret.Hash(salt, parts.Random),
	}, 25)
	require.NoError(t, err)

	_, err = service.NewValidator(f.tokens, apiIdentifiers).Validate(context.Background(), parts.String())

	assert.True(t, errors.IsNotFound(err), "got %v", err)
	assert.Nil(t, f.active(t, "alice", legacy.UID).LastUsedAt)
}

func TestValidateFailsWithoutAnAPIIdentifierForTheAudience(t *testing.T) {
	f := newFixture(25)
	created := f.create(t, alice, "ci", "other")
	identifiers := map[string]string{constants.AudienceInsights: "https://insights-api.test/"}

	_, err := service.NewValidator(f.tokens, identifiers).Validate(context.Background(), created.Secret)

	require.Error(t, err)
	assert.False(t, errors.IsNotFound(err), "a misconfiguration must not read as an invalid secret")
	assert.Nil(t, f.active(t, "alice", created.Token.UID).LastUsedAt)
}

func flip(b byte) string {
	if b == 'a' {
		return "b"
	}
	return "a"
}
