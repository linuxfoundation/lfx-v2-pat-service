// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package mock

import (
	"context"
	"testing"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newToken(name, lookup string) model.NewToken {
	return model.NewToken{Username: "alice", Audience: SeedAudience.Slug, Name: name, LookupID: lookup, Salt: []byte("s"), SecretHash: []byte("h")}
}

func TestReadyFollowsSetReady(t *testing.T) {
	r := NewTokenRepository(NewAudienceRepository())

	assert.True(t, r.Ready(context.Background()))
	r.SetReady(false)
	assert.False(t, r.Ready(context.Background()))
}

func TestCreateRejectsLookupIDCollisionEvenWhenRevoked(t *testing.T) {
	r := NewTokenRepository(NewAudienceRepository())
	created, err := r.Create(context.Background(), newToken("a", "lookup-000001"), 25)
	require.NoError(t, err)
	require.NoError(t, r.Revoke(context.Background(), created.UID, "alice"))

	_, err = r.Create(context.Background(), newToken("b", "lookup-000001"), 25)

	assert.ErrorIs(t, err, port.ErrLookupIDTaken)
}

func TestFindActiveByLookupIDJoinsEnabledAudience(t *testing.T) {
	audiences := NewAudienceRepository()
	r := NewTokenRepository(audiences)
	created, err := r.Create(context.Background(), newToken("a", "lookup-000001"), 25)
	require.NoError(t, err)

	cred, err := r.FindActiveByLookupID(context.Background(), "lookup-000001", "lfi_")
	require.NoError(t, err)
	assert.Equal(t, created.UID, cred.UID)
	assert.Equal(t, []byte("s"), cred.Salt)
	assert.Equal(t, []byte("h"), cred.SecretHash)

	_, err = r.FindActiveByLookupID(context.Background(), "lookup-000001", "lfo_")
	assert.True(t, errors.IsNotFound(err))

	disabled := SeedAudience
	disabled.Enabled = false
	audiences.Set(disabled)
	_, err = r.FindActiveByLookupID(context.Background(), "lookup-000001", "lfi_")
	assert.True(t, errors.IsNotFound(err))
}

func TestGetEnabledBySlug(t *testing.T) {
	audiences := NewAudienceRepository()

	a, err := audiences.GetEnabledBySlug(context.Background(), SeedAudience.Slug)
	require.NoError(t, err)
	assert.Equal(t, SeedAudience, a)

	_, err = audiences.GetEnabledBySlug(context.Background(), "nope")
	assert.True(t, errors.IsNotFound(err))
}
