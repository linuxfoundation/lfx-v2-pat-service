// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package port declares the interfaces the use-cases depend on, one small interface per capability.
package port

import (
	"context"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
)

// AudienceReader resolves audiences by slug.
type AudienceReader interface {
	// GetEnabledBySlug returns the audience, or a NotFound error when the slug is unknown or disabled.
	GetEnabledBySlug(ctx context.Context, slug string) (model.Audience, error)
}
