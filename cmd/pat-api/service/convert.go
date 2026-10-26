// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"time"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
)

// toTokenResponse names every exposed field, so secret material can never reach a response by struct copy.
func toTokenResponse(t model.Token) *svc.TokenResponse {
	return &svc.TokenResponse{
		UID:        t.UID,
		Name:       t.Name,
		Audience:   t.Audience,
		LookupID:   t.LookupID,
		Username:   t.Username,
		CreatedAt:  formatTime(t.CreatedAt),
		LastUsedAt: formatOptionalTime(t.LastUsedAt),
		ExpiresAt:  formatOptionalTime(t.ExpiresAt),
	}
}

// toTokenResponses always returns a non-nil slice so an empty list encodes as [] rather than null.
func toTokenResponses(tokens []model.Token) []*svc.TokenResponse {
	out := make([]*svc.TokenResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, toTokenResponse(t))
	}
	return out
}

func toIdentity(id model.TokenIdentity) *svc.TokenIdentity {
	out := &svc.TokenIdentity{UID: id.UID, Username: id.Username, Audience: id.Audience}
	if id.Email != "" {
		out.Email = &id.Email
	}
	return out
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func formatOptionalTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := formatTime(*t)
	return &s
}
