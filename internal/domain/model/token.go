// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import "time"

// Token is a personal access token as the owner sees it. It carries no secret material.
type Token struct {
	UID      string
	Username string
	// Email is the owner's email captured at issuance, or empty when the user JWT carried none.
	Email    string
	Audience string
	Name     string
	// LookupID is the public locator embedded in the secret.
	LookupID   string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	// ExpiresAt is when the token stops validating, or nil when it never expires.
	ExpiresAt *time.Time
}

// Active reports whether the token has not been revoked. An expired token stays active, so it is still listed
// and keeps its name until the owner revokes it.
func (t Token) Active() bool {
	return t.RevokedAt == nil
}

// Expired reports whether the token no longer validates at now.
func (t Token) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
}

// NewToken is the write model for issuing a token: everything the store needs, with the secret already reduced
// to its salted hash.
type NewToken struct {
	Username   string
	Email      string
	Audience   string
	Name       string
	LookupID   string
	Salt       []byte
	SecretHash []byte
	ExpiresAt  *time.Time
}

// Credential is the verification material of one active token. Only the validator reads it.
type Credential struct {
	UID        string
	Username   string
	Email      string
	Audience   string
	Salt       []byte
	SecretHash []byte
}

// TokenIdentity is what a successful validation resolves to.
type TokenIdentity struct {
	UID      string
	Username string
	Audience string
	Email    string
}
