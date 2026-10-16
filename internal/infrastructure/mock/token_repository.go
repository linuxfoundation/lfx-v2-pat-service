// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package mock

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
)

type storedToken struct {
	model.Token
	salt []byte
	hash []byte
	// seq orders tokens created within the same clock tick so ListActiveByOwner is deterministic.
	seq int
}

// TokenRepository is an in-memory TokenReader, TokenWriter, CredentialReader and Readiness.
type TokenRepository struct {
	mu        sync.Mutex
	audiences *AudienceRepository
	byUID     map[string]*storedToken
	seq       int
	ready     bool
	now       func() time.Time
}

var (
	_ port.TokenReader      = (*TokenRepository)(nil)
	_ port.TokenWriter      = (*TokenRepository)(nil)
	_ port.CredentialReader = (*TokenRepository)(nil)
	_ port.Readiness        = (*TokenRepository)(nil)
)

// NewTokenRepository returns an empty, ready repository whose validation path joins the given audiences.
func NewTokenRepository(audiences *AudienceRepository) *TokenRepository {
	return &TokenRepository{
		audiences: audiences,
		byUID:     make(map[string]*storedToken),
		ready:     true,
		now:       time.Now,
	}
}

// SetReady controls what Ready reports.
func (r *TokenRepository) SetReady(ready bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = ready
}

// SetClock replaces the clock, for tests that assert on timestamps.
func (r *TokenRepository) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

// Ready implements port.Readiness.
func (r *TokenRepository) Ready(context.Context) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ready
}

// Create implements port.TokenWriter with the same checks the Postgres adapter performs inside its transaction.
func (r *TokenRepository) Create(_ context.Context, t model.NewToken, maxActive int) (model.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	active := 0
	for _, s := range r.byUID {
		if s.LookupID == t.LookupID {
			return model.Token{}, port.ErrLookupIDTaken
		}
		if !s.Active() || s.Username != t.Username || s.Audience != t.Audience {
			continue
		}
		active++
		if strings.EqualFold(s.Name, t.Name) {
			return model.Token{}, errors.NewConflict(constants.ErrCodeTokenNameTaken,
				fmt.Sprintf("a token named %q already exists for audience %s", t.Name, t.Audience))
		}
	}
	if active >= maxActive {
		return model.Token{}, errors.NewConflict(constants.ErrCodeTokenLimitReached,
			fmt.Sprintf("limit of %d active tokens for audience %s reached", maxActive, t.Audience))
	}

	now := r.now()
	r.seq++
	s := &storedToken{
		Token: model.Token{
			UID:       uuid.NewString(),
			Username:  t.Username,
			Email:     t.Email,
			Audience:  t.Audience,
			Name:      t.Name,
			LookupID:  t.LookupID,
			CreatedAt: now,
			UpdatedAt: now,
		},
		salt: append([]byte(nil), t.Salt...),
		hash: append([]byte(nil), t.SecretHash...),
		seq:  r.seq,
	}
	r.byUID[s.UID] = s
	return s.Token, nil
}

// ListActiveByOwner implements port.TokenReader.
func (r *TokenRepository) ListActiveByOwner(_ context.Context, username, audience string) ([]model.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var matches []*storedToken
	for _, s := range r.byUID {
		if s.Active() && s.Username == username && (audience == "" || s.Audience == audience) {
			matches = append(matches, s)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].CreatedAt.Equal(matches[j].CreatedAt) {
			return matches[i].seq > matches[j].seq
		}
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	out := make([]model.Token, 0, len(matches))
	for _, s := range matches {
		out = append(out, s.Token)
	}
	return out, nil
}

// Revoke implements port.TokenWriter.
func (r *TokenRepository) Revoke(_ context.Context, uid, username string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.byUID[uid]
	if !ok || !s.Active() || s.Username != username {
		return notFound(uid)
	}
	now := r.now()
	s.RevokedAt = &now
	s.UpdatedAt = now
	return nil
}

// FindActiveByLookupID implements port.CredentialReader, including the join on an enabled audience with the
// given prefix.
func (r *TokenRepository) FindActiveByLookupID(_ context.Context, lookupID, prefix string) (model.Credential, error) {
	audience, ok := r.audiences.enabledByPrefix(prefix)
	if !ok {
		return model.Credential{}, errors.NewNotFound("no enabled audience for prefix")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.byUID {
		if s.LookupID != lookupID {
			continue
		}
		if !s.Active() || s.Audience != audience.Slug {
			break
		}
		return model.Credential{
			UID:        s.UID,
			Username:   s.Username,
			Email:      s.Email,
			Audience:   s.Audience,
			Salt:       append([]byte(nil), s.salt...),
			SecretHash: append([]byte(nil), s.hash...),
		}, nil
	}
	return model.Credential{}, errors.NewNotFound("no active token for lookup id")
}

// TouchLastUsed implements port.CredentialReader. It leaves UpdatedAt alone.
func (r *TokenRepository) TouchLastUsed(_ context.Context, uid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.byUID[uid]
	if !ok || !s.Active() {
		return notFound(uid)
	}
	now := r.now()
	s.LastUsedAt = &now
	return nil
}

func notFound(uid string) error {
	return errors.NewNotFound(fmt.Sprintf("no active token %s owned by the caller", uid))
}
