// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
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

var (
	alice = domain.Caller{Principal: "alice", Email: "alice@example.com"}
	bob   = domain.Caller{Principal: "bob"}
	other = model.Audience{Slug: "other", DisplayName: "Other", TokenPrefix: "lfo_", Enabled: true}
)

type fixture struct {
	manager   *service.Manager
	tokens    *mock.TokenRepository
	audiences *mock.AudienceRepository
}

func newFixture(maxActive int) fixture {
	audiences := mock.NewAudienceRepository(mock.SeedAudience, other)
	tokens := mock.NewTokenRepository(audiences)
	return fixture{
		manager:   service.NewManager(tokens, tokens, audiences, maxActive),
		tokens:    tokens,
		audiences: audiences,
	}
}

func (f fixture) create(t *testing.T, caller domain.Caller, name, audience string) service.CreatedToken {
	t.Helper()
	created, err := f.manager.Create(context.Background(), caller, name, audience, "")
	require.NoError(t, err)
	return created
}

// at fixes the clock the manager counts expirations from and the store checks them against.
func (f fixture) at(now time.Time) {
	f.manager.SetClock(func() time.Time { return now })
	f.tokens.SetClock(func() time.Time { return now })
}

func (f fixture) createExpiring(t *testing.T, caller domain.Caller, name, expiration string) service.CreatedToken {
	t.Helper()
	created, err := f.manager.Create(context.Background(), caller, name, constants.AudienceInsights, expiration)
	require.NoError(t, err)
	return created
}

// active returns the owner's active token with the given uid, read back through List.
func (f fixture) active(t *testing.T, username, uid string) model.Token {
	t.Helper()
	tokens, err := f.manager.List(context.Background(), username, "")
	require.NoError(t, err)
	for _, tok := range tokens {
		if tok.UID == uid {
			return tok
		}
	}
	require.FailNow(t, "token not active", uid)
	return model.Token{}
}

func conflictCode(t *testing.T, err error) string {
	t.Helper()
	var c errors.Conflict
	require.ErrorAs(t, err, &c)
	return c.Code()
}

func TestCreateIssuesSecretAndStoresOwner(t *testing.T) {
	f := newFixture(25)

	created := f.create(t, alice, "ci", constants.AudienceInsights)

	parts, err := secret.Parse(created.Secret)
	require.NoError(t, err)
	assert.Equal(t, "lfi_", parts.Prefix)
	assert.Equal(t, parts.LookupID, created.Token.LookupID)
	assert.Equal(t, "alice", created.Token.Username)
	assert.Equal(t, "alice@example.com", created.Token.Email)
	assert.Equal(t, constants.AudienceInsights, created.Token.Audience)
	assert.Equal(t, "ci", created.Token.Name)
	assert.NotEmpty(t, created.Token.UID)
	assert.False(t, created.Token.CreatedAt.IsZero())
	assert.Nil(t, created.Token.LastUsedAt)
	assert.True(t, created.Token.Active())

	assert.Equal(t, created.Token, f.active(t, "alice", created.Token.UID))
}

func TestCreateUsesTheAudiencePrefix(t *testing.T) {
	f := newFixture(25)

	created := f.create(t, alice, "ci", "other")

	assert.True(t, strings.HasPrefix(created.Secret, "lfo_"))
	assert.Equal(t, "other", created.Token.Audience)
}

func TestCreateNameValidation(t *testing.T) {
	f := newFixture(25)
	tests := []struct {
		name  string
		input string
		want  string
		valid bool
	}{
		{"trimmed", "  ci  ", "ci", true},
		{"max length", strings.Repeat("a", constants.TokenNameMaxLength), strings.Repeat("a", constants.TokenNameMaxLength), true},
		{"unicode counts runes", strings.Repeat("流", constants.TokenNameMaxLength), strings.Repeat("流", constants.TokenNameMaxLength), true},
		{"empty", "", "", false},
		{"blank", "   ", "", false},
		{"too long", strings.Repeat("a", constants.TokenNameMaxLength+1), "", false},
		{"control character", "ci\x00", "", false},
		{"tab", "ci\tprod", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created, err := f.manager.Create(context.Background(), alice, tt.input, constants.AudienceInsights, "")
			if !tt.valid {
				assertValidation(t, err, constants.ErrCodeInvalidName)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, created.Token.Name)
		})
	}
}

func assertValidation(t *testing.T, err error, code string) {
	t.Helper()
	var v errors.Validation
	require.ErrorAs(t, err, &v)
	assert.Equal(t, code, v.Code())
}

func TestCreateRejectsUnknownOrDisabledAudience(t *testing.T) {
	f := newFixture(25)

	_, err := f.manager.Create(context.Background(), alice, "ci", "nope", "")
	assertValidation(t, err, constants.ErrCodeUnknownAudience)

	disabled := mock.SeedAudience
	disabled.Enabled = false
	f.audiences.Set(disabled)
	_, err = f.manager.Create(context.Background(), alice, "ci", constants.AudienceInsights, "")
	assertValidation(t, err, constants.ErrCodeUnknownAudience)
}

func TestCreateRejectsDuplicateNameCaseInsensitively(t *testing.T) {
	f := newFixture(25)
	f.create(t, alice, "ci", constants.AudienceInsights)

	_, err := f.manager.Create(context.Background(), alice, "CI", constants.AudienceInsights, "")
	assert.Equal(t, constants.ErrCodeTokenNameTaken, conflictCode(t, err))

	// Uniqueness is per owner and per audience.
	f.create(t, bob, "ci", constants.AudienceInsights)
	f.create(t, alice, "ci", "other")
}

func TestCreateEnforcesActiveLimitPerAudience(t *testing.T) {
	f := newFixture(2)
	first := f.create(t, alice, "one", constants.AudienceInsights)
	f.create(t, alice, "two", constants.AudienceInsights)

	_, err := f.manager.Create(context.Background(), alice, "three", constants.AudienceInsights, "")
	assert.Equal(t, constants.ErrCodeTokenLimitReached, conflictCode(t, err))

	// Another audience has its own budget, and revoking frees a slot.
	f.create(t, alice, "three", "other")
	require.NoError(t, f.manager.Revoke(context.Background(), first.Token.UID, "alice"))
	f.create(t, alice, "three", constants.AudienceInsights)
}

func TestCreateCountsExpiryFromCreation(t *testing.T) {
	created := time.Date(2026, 9, 7, 10, 30, 0, 0, time.UTC)
	at := func(y int, m time.Month, d int) *time.Time {
		t := time.Date(y, m, d, 10, 30, 0, 0, time.UTC)
		return &t
	}
	tests := []struct {
		expiration string
		want       *time.Time
	}{
		{constants.Expiration30Days, at(2026, time.October, 7)},
		{constants.Expiration60Days, at(2026, time.November, 6)},
		{constants.Expiration90Days, at(2026, time.December, 6)},
		{constants.Expiration1Year, at(2027, time.September, 7)},
		{constants.ExpirationNone, nil},
		{"", nil},
	}

	for _, tt := range tests {
		t.Run("expiration "+tt.expiration, func(t *testing.T) {
			f := newFixture(25)
			f.at(created)

			token := f.createExpiring(t, alice, "ci", tt.expiration).Token

			assert.Equal(t, tt.want, token.ExpiresAt)
			assert.Equal(t, tt.want, f.active(t, "alice", token.UID).ExpiresAt)
		})
	}
}

func TestCreateRejectsUnknownExpiration(t *testing.T) {
	f := newFixture(25)

	_, err := f.manager.Create(context.Background(), alice, "ci", constants.AudienceInsights, "7d")

	assertValidation(t, err, constants.ErrCodeInvalidExpiration)
}

func TestExpiredTokenStaysListedAndHoldsItsNameAndSlotUntilRevoked(t *testing.T) {
	f := newFixture(1)
	start := time.Date(2026, 9, 7, 10, 30, 0, 0, time.UTC)
	f.at(start)
	expired := f.createExpiring(t, alice, "ci", constants.Expiration30Days)
	f.at(start.AddDate(0, 0, 31))

	listed := f.active(t, "alice", expired.Token.UID)
	assert.True(t, listed.Expired(start.AddDate(0, 0, 31)))
	_, err := f.manager.Create(context.Background(), alice, "CI", constants.AudienceInsights, "")
	assert.Equal(t, constants.ErrCodeTokenNameTaken, conflictCode(t, err))
	_, err = f.manager.Create(context.Background(), alice, "other", constants.AudienceInsights, "")
	assert.Equal(t, constants.ErrCodeTokenLimitReached, conflictCode(t, err))

	require.NoError(t, f.manager.Revoke(context.Background(), expired.Token.UID, "alice"))
	f.createExpiring(t, alice, "ci", constants.ExpirationNone)
}

func TestRevokedNameIsReusable(t *testing.T) {
	f := newFixture(25)
	created := f.create(t, alice, "ci", constants.AudienceInsights)

	require.NoError(t, f.manager.Revoke(context.Background(), created.Token.UID, "alice"))
	again := f.create(t, alice, "ci", constants.AudienceInsights)

	assert.NotEqual(t, created.Token.UID, again.Token.UID)
}

func TestListIsOwnerScopedFilteredAndNewestFirst(t *testing.T) {
	f := newFixture(25)
	clock := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	f.tokens.SetClock(func() time.Time { clock = clock.Add(time.Second); return clock })
	a := f.create(t, alice, "a", constants.AudienceInsights)
	b := f.create(t, alice, "b", "other")
	c := f.create(t, alice, "c", constants.AudienceInsights)
	f.create(t, bob, "x", constants.AudienceInsights)

	all, err := f.manager.List(context.Background(), "alice", "")
	require.NoError(t, err)
	assert.Equal(t, []string{c.Token.UID, b.Token.UID, a.Token.UID}, uids(all))

	insights, err := f.manager.List(context.Background(), "alice", constants.AudienceInsights)
	require.NoError(t, err)
	assert.Equal(t, []string{c.Token.UID, a.Token.UID}, uids(insights))

	none, err := f.manager.List(context.Background(), "carol", "")
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestRevoke(t *testing.T) {
	f := newFixture(25)
	created := f.create(t, alice, "ci", constants.AudienceInsights)

	assert.True(t, errors.IsNotFound(f.manager.Revoke(context.Background(), created.Token.UID, "bob")))
	require.NoError(t, f.manager.Revoke(context.Background(), created.Token.UID, "alice"))

	assert.True(t, errors.IsNotFound(f.manager.Revoke(context.Background(), created.Token.UID, "alice")))
	list, err := f.manager.List(context.Background(), "alice", "")
	require.NoError(t, err)
	assert.Empty(t, list)
}

// collidingWriter reports a lookup id collision for the first n creates, then delegates.
type collidingWriter struct {
	port.TokenWriter
	remaining int
	calls     int
}

func (w *collidingWriter) Create(ctx context.Context, t model.NewToken, maxActive int) (model.Token, error) {
	w.calls++
	if w.remaining > 0 {
		w.remaining--
		return model.Token{}, port.ErrLookupIDTaken
	}
	return w.TokenWriter.Create(ctx, t, maxActive)
}

func TestCreateRetriesOnceOnLookupIDCollision(t *testing.T) {
	audiences := mock.NewAudienceRepository()
	tokens := mock.NewTokenRepository(audiences)

	once := &collidingWriter{TokenWriter: tokens, remaining: 1}
	_, err := service.NewManager(tokens, once, audiences, 25).Create(context.Background(), alice, "ci", constants.AudienceInsights, "")
	require.NoError(t, err)
	assert.Equal(t, 2, once.calls)

	twice := &collidingWriter{TokenWriter: tokens, remaining: 2}
	_, err = service.NewManager(tokens, twice, audiences, 25).Create(context.Background(), alice, "ci2", constants.AudienceInsights, "")
	assert.ErrorIs(t, err, port.ErrLookupIDTaken)
	assert.Equal(t, 2, twice.calls)
}

func uids(tokens []model.Token) []string {
	out := make([]string, 0, len(tokens))
	for _, tk := range tokens {
		out = append(out, tk.UID)
	}
	return out
}
