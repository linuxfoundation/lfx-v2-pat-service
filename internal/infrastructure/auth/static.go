// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
)

// Static resolves every token to a fixed caller. It backs local development when JWT verification is disabled
// through JWT_AUTH_DISABLED_MOCK_LOCAL_PRINCIPAL, and tests.
type Static struct {
	Caller domain.Caller
	Err    error
}

var _ domain.Authenticator = Static{}

// Authenticate implements domain.Authenticator.
func (s Static) Authenticate(context.Context, string) (domain.Caller, error) {
	if s.Err != nil {
		return domain.Caller{}, s.Err
	}
	return s.Caller, nil
}
