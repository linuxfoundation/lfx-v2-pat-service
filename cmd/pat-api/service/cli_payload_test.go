// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"testing"

	svccli "github.com/linuxfoundation/lfx-v2-pat-service/gen/http/lfx_v2_pat_service/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratedCLIAcceptsOmittedExpiration(t *testing.T) {
	payload, err := svccli.BuildCreateTokenPayload(`{"name":"ci","audience":"insights"}`, "", "")
	require.NoError(t, err)
	assert.Nil(t, payload.Expiration)

	_, err = svccli.BuildCreateTokenPayload(`{"name":"ci","audience":"insights","expiration":"7d"}`, "", "")
	assert.Error(t, err)
}
