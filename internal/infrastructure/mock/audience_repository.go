// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package mock provides in-memory adapters with the same semantics as the Postgres ones, for unit tests and
// local runs without a database.
package mock

import (
	"context"
	"fmt"
	"sync"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
)

// SeedAudience mirrors the row the first migration inserts.
var SeedAudience = model.Audience{
	Slug:        constants.AudienceInsights,
	DisplayName: "LFX Insights",
	TokenPrefix: "lfi_",
	Enabled:     true,
}

// AudienceRepository is an in-memory AudienceReader.
type AudienceRepository struct {
	mu     sync.RWMutex
	bySlug map[string]model.Audience
}

var _ port.AudienceReader = (*AudienceRepository)(nil)

// NewAudienceRepository returns a repository holding the given audiences, or the seed audience when none are
// given.
func NewAudienceRepository(audiences ...model.Audience) *AudienceRepository {
	if len(audiences) == 0 {
		audiences = []model.Audience{SeedAudience}
	}
	r := &AudienceRepository{bySlug: make(map[string]model.Audience, len(audiences))}
	for _, a := range audiences {
		r.bySlug[a.Slug] = a
	}
	return r
}

// Set inserts or replaces an audience.
func (r *AudienceRepository) Set(a model.Audience) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bySlug[a.Slug] = a
}

// GetEnabledBySlug implements port.AudienceReader.
func (r *AudienceRepository) GetEnabledBySlug(_ context.Context, slug string) (model.Audience, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.bySlug[slug]
	if !ok || !a.Enabled {
		return model.Audience{}, errors.NewNotFound(fmt.Sprintf("audience %q is unknown or disabled", slug))
	}
	return a, nil
}

// enabledByPrefix returns the enabled audience using prefix, if any.
func (r *AudienceRepository) enabledByPrefix(prefix string) (model.Audience, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.bySlug {
		if a.Enabled && a.TokenPrefix == prefix {
			return a, true
		}
	}
	return model.Audience{}, false
}
