// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package migrations embeds the SQL migration files so golang-migrate's iofs source can run them from the
// compiled binary.
package migrations

import "embed"

// FS holds every *.sql migration file at the root of this package.
//
//go:embed *.sql
var FS embed.FS
