// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package postgres

import (
	"context"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
)

// AudienceRepository reads the audiences table.
type AudienceRepository struct {
	pool *Pool
}

var _ port.AudienceReader = (*AudienceRepository)(nil)

// NewAudienceRepository wires the repository.
func NewAudienceRepository(pool *Pool) *AudienceRepository {
	return &AudienceRepository{pool: pool}
}

// GetEnabledBySlug implements port.AudienceReader.
func (r *AudienceRepository) GetEnabledBySlug(ctx context.Context, slug string) (model.Audience, error) {
	const q = `SELECT slug, display_name, token_prefix, enabled FROM audiences WHERE slug = $1 AND enabled`
	var a model.Audience
	if err := r.pool.QueryRow(ctx, q, slug).Scan(&a.Slug, &a.DisplayName, &a.TokenPrefix, &a.Enabled); err != nil {
		return model.Audience{}, storeErr("get audience", err)
	}
	return a, nil
}
