// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateKeepsThePasswordOutOfParseErrors(t *testing.T) {
	err := Migrate("pgx5://pat:S3cr3t%25PW@bad host/pat?sslmode=disable")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "S3cr3t")
}
