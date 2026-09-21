// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/postgres"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests need a database they may freely modify, named by TEST_DATABASE_URL as a postgres:// URL.
// Unset, they skip on a laptop; on CI, where a database is promised, an unset variable fails instead so a
// silently skipped suite never reads as green.
const envDatabaseURL = "TEST_DATABASE_URL"

func live(t *testing.T) *postgres.Pool {
	t.Helper()
	url := strings.TrimSpace(os.Getenv(envDatabaseURL))
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s must be set on CI", envDatabaseURL)
		}
		t.Skipf("%s not set", envDatabaseURL)
	}
	ctx := context.Background()
	require.NoError(t, postgres.Migrate(strings.Replace(url, "postgres://", "pgx5://", 1)))
	pool, err := postgres.NewPool(ctx, url, 5)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	_, err = pool.Exec(ctx, `DELETE FROM tokens`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE audiences SET enabled = true`)
	require.NoError(t, err)
	return pool
}

func newToken(username, name string) model.NewToken {
	parts, err := secret.Generate("lfi_")
	if err != nil {
		panic(err)
	}
	salt, err := secret.NewSalt()
	if err != nil {
		panic(err)
	}
	return model.NewToken{
		Username:   username,
		Email:      username + "@example.com",
		Audience:   constants.AudienceInsights,
		Name:       name,
		LookupID:   parts.LookupID,
		Salt:       salt,
		SecretHash: secret.Hash(salt, parts.Random),
	}
}

func TestLiveMigrationSeedsInsights(t *testing.T) {
	pool := live(t)
	repo := postgres.NewAudienceRepository(pool)

	a, err := repo.GetEnabledBySlug(context.Background(), constants.AudienceInsights)

	require.NoError(t, err)
	assert.Equal(t, model.Audience{Slug: "insights", DisplayName: "LFX Insights", TokenPrefix: "lfi_", Enabled: true}, a)
	_, err = repo.GetEnabledBySlug(context.Background(), "nope")
	assert.True(t, errors.IsNotFound(err))
	assert.True(t, pool.Ready(context.Background()))
}

func TestLiveMigrateIsIdempotent(t *testing.T) {
	live(t)
	url := strings.Replace(os.Getenv(envDatabaseURL), "postgres://", "pgx5://", 1)

	assert.NoError(t, postgres.Migrate(url))
	assert.NoError(t, postgres.Migrate(url))
}

func TestLiveCreateGetListRevoke(t *testing.T) {
	pool := live(t)
	repo := postgres.NewTokenRepository(pool)
	ctx := context.Background()

	first, err := repo.Create(ctx, newToken("alice", "one"), 25)
	require.NoError(t, err)
	assert.Equal(t, "alice", first.Username)
	assert.Equal(t, "alice@example.com", first.Email)
	assert.Equal(t, "one", first.Name)
	assert.Len(t, first.LookupID, 12)
	assert.Nil(t, first.LastUsedAt)
	assert.Nil(t, first.RevokedAt)
	assert.Equal(t, time.UTC, first.CreatedAt.Location())

	second, err := repo.Create(ctx, newToken("alice", "two"), 25)
	require.NoError(t, err)
	_, err = repo.Create(ctx, newToken("bob", "one"), 25)
	require.NoError(t, err)

	got, err := repo.GetActiveByOwner(ctx, first.UID, "alice")
	require.NoError(t, err)
	assert.Equal(t, first, got)
	_, err = repo.GetActiveByOwner(ctx, first.UID, "bob")
	assert.True(t, errors.IsNotFound(err))
	_, err = repo.GetActiveByOwner(ctx, uuid.NewString(), "alice")
	assert.True(t, errors.IsNotFound(err))

	list, err := repo.ListActiveByOwner(ctx, "alice", "")
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, second.UID, list[0].UID, "newest first")
	assert.Equal(t, first.UID, list[1].UID)
	list, err = repo.ListActiveByOwner(ctx, "alice", "other")
	require.NoError(t, err)
	assert.Empty(t, list)

	require.NoError(t, repo.Revoke(ctx, first.UID, "alice"))
	assert.True(t, errors.IsNotFound(repo.Revoke(ctx, first.UID, "alice")), "revoke is not repeatable")
	assert.True(t, errors.IsNotFound(repo.Revoke(ctx, second.UID, "bob")), "not the owner")
	_, err = repo.GetActiveByOwner(ctx, first.UID, "alice")
	assert.True(t, errors.IsNotFound(err))
	list, err = repo.ListActiveByOwner(ctx, "alice", "")
	require.NoError(t, err)
	assert.Equal(t, []string{second.UID}, []string{list[0].UID})
}

func TestLiveNameUniquenessIsCaseInsensitiveAndPerOwnerAndAudience(t *testing.T) {
	pool := live(t)
	repo := postgres.NewTokenRepository(pool)
	ctx := context.Background()
	created, err := repo.Create(ctx, newToken("alice", "CI"), 25)
	require.NoError(t, err)

	_, err = repo.Create(ctx, newToken("alice", "ci"), 25)
	var conflict errors.Conflict
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, constants.ErrCodeTokenNameTaken, conflict.Code())

	// Revoked names are free again.
	require.NoError(t, repo.Revoke(ctx, created.UID, "alice"))
	_, err = repo.Create(ctx, newToken("alice", "ci"), 25)
	assert.NoError(t, err)
}

func TestLiveLookupIDNeverReusedEvenAfterRevoke(t *testing.T) {
	pool := live(t)
	repo := postgres.NewTokenRepository(pool)
	ctx := context.Background()
	nt := newToken("alice", "one")
	created, err := repo.Create(ctx, nt, 25)
	require.NoError(t, err)
	require.NoError(t, repo.Revoke(ctx, created.UID, "alice"))

	dup := newToken("alice", "two")
	dup.LookupID = nt.LookupID
	_, err = repo.Create(ctx, dup, 25)

	assert.ErrorIs(t, err, port.ErrLookupIDTaken)
}

func TestLiveUnknownAudienceIsRejectedByForeignKey(t *testing.T) {
	pool := live(t)
	repo := postgres.NewTokenRepository(pool)
	nt := newToken("alice", "one")
	nt.Audience = "nope"

	_, err := repo.Create(context.Background(), nt, 25)

	assert.True(t, errors.IsValidation(err), "got %v", err)
}

func TestLiveLimitHoldsUnderConcurrentCreates(t *testing.T) {
	pool := live(t)
	repo := postgres.NewTokenRepository(pool)
	ctx := context.Background()
	const limit, attempts = 3, 20

	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := repo.Create(ctx, newToken("alice", fmt.Sprintf("t%d", i)), limit)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	var ok, limited int
	for err := range results {
		if err == nil {
			ok++
			continue
		}
		var conflict errors.Conflict
		require.ErrorAs(t, err, &conflict, "unexpected error %v", err)
		assert.Equal(t, constants.ErrCodeTokenLimitReached, conflict.Code())
		limited++
	}
	assert.Equal(t, limit, ok)
	assert.Equal(t, attempts-limit, limited)
	list, err := repo.ListActiveByOwner(ctx, "alice", "")
	require.NoError(t, err)
	assert.Len(t, list, limit)
}

func TestLiveValidationPath(t *testing.T) {
	pool := live(t)
	repo := postgres.NewTokenRepository(pool)
	audiences := postgres.NewAudienceRepository(pool)
	manager := service.NewManager(repo, repo, audiences, 25)
	validator := service.NewValidator(repo)
	ctx := context.Background()
	created, err := manager.Create(ctx, domain.Caller{Principal: "alice", Email: "alice@example.com"}, "ci", constants.AudienceInsights)
	require.NoError(t, err)

	identity, err := validator.Validate(ctx, created.Secret)
	require.NoError(t, err)
	assert.Equal(t, model.TokenIdentity{UID: created.Token.UID, Username: "alice", Audience: "insights", Email: "alice@example.com"}, identity)

	after, err := repo.GetActiveByOwner(ctx, created.Token.UID, "alice")
	require.NoError(t, err)
	require.NotNil(t, after.LastUsedAt)
	assert.Equal(t, created.Token.UpdatedAt, after.UpdatedAt, "recording a use must not move updated_at")

	// Wrong random part, revoked token and a disabled audience all fail closed.
	_, err = validator.Validate(ctx, created.Secret[:len(created.Secret)-1]+"!")
	assert.True(t, errors.IsNotFound(err))
	_, err = pool.Exec(ctx, `UPDATE audiences SET enabled = false WHERE slug = 'insights'`)
	require.NoError(t, err)
	_, err = validator.Validate(ctx, created.Secret)
	assert.True(t, errors.IsNotFound(err))
	_, err = pool.Exec(ctx, `UPDATE audiences SET enabled = true WHERE slug = 'insights'`)
	require.NoError(t, err)
	require.NoError(t, manager.Revoke(ctx, created.Token.UID, "alice"))
	_, err = validator.Validate(ctx, created.Secret)
	assert.True(t, errors.IsNotFound(err))
}

func TestLiveSecretMaterialNeverLeavesTheCredentialPath(t *testing.T) {
	pool := live(t)
	repo := postgres.NewTokenRepository(pool)
	ctx := context.Background()
	nt := newToken("alice", "one")
	created, err := repo.Create(ctx, nt, 25)
	require.NoError(t, err)

	var stored []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT secret_hash FROM tokens WHERE uid = $1`, created.UID).Scan(&stored))
	assert.Equal(t, nt.SecretHash, stored)

	cred, err := repo.FindActiveByLookupID(ctx, nt.LookupID, "lfi_")
	require.NoError(t, err)
	assert.Equal(t, nt.Salt, cred.Salt)
	assert.Equal(t, nt.SecretHash, cred.SecretHash)
	_, err = repo.FindActiveByLookupID(ctx, nt.LookupID, "lfo_")
	assert.True(t, errors.IsNotFound(err))
}
