// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package model holds the domain entities.
package model

// Audience is a service tokens can be minted for. Rows live in the audiences table; the seed is "insights" with
// prefix "lfi_".
type Audience struct {
	Slug        string
	DisplayName string
	// TokenPrefix starts every secret minted for this audience, for example "lfi_".
	TokenPrefix string
	// Enabled gates both issuance and validation; a disabled audience fails closed.
	Enabled bool
}
