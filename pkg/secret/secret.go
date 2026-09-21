// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package secret generates, parses and verifies the plaintext credential handed to a user.
//
// A secret is <prefix><lookup id><random part>: the prefix names the audience (for example "lfi_"), the lookup
// id is a public locator that makes validation one indexed query, and the random part is the only confidential
// piece. The store keeps a per-row salt and SHA-256(salt || random part). SHA-256 without a slow KDF is enough
// because the random part carries about 190 bits of entropy; slow hashes compensate for guessable passwords,
// not for random secrets.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"regexp"
	"strings"
)

const (
	// LookupIDLength is the length of the public locator embedded in every secret.
	LookupIDLength = 12
	// RandomLength is the length of the confidential part.
	RandomLength = 32
	// SaltLength is the number of random bytes stored next to each hash.
	SaltLength = 16

	alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	// acceptBelow is the largest multiple of len(alphabet) that fits in a byte; bytes at or above it are
	// rejected so every alphabet character is equally likely.
	acceptBelow = 248
)

// PrefixPattern is the shape of an audience prefix. It ends with the only underscore in a secret, which is what
// Parse splits on, and it mirrors the audiences_prefix_fmt check constraint.
var PrefixPattern = regexp.MustCompile(`^[a-z0-9]{2,8}_$`)

// ErrMalformed is returned by Parse for anything that is not a well-formed secret. Callers report it exactly
// like an unknown secret so the two are indistinguishable.
var ErrMalformed = errors.New("malformed secret")

// Parts is a secret split into its three components.
type Parts struct {
	Prefix   string
	LookupID string
	Random   string
}

// String reassembles the plaintext secret.
func (p Parts) String() string {
	return p.Prefix + p.LookupID + p.Random
}

// ValidPrefix reports whether prefix can start a secret.
func ValidPrefix(prefix string) bool {
	return PrefixPattern.MatchString(prefix)
}

// Generate mints a new secret for the given audience prefix.
func Generate(prefix string) (Parts, error) {
	if !ValidPrefix(prefix) {
		return Parts{}, errors.New("invalid audience prefix")
	}
	lookup, err := randomString(LookupIDLength)
	if err != nil {
		return Parts{}, err
	}
	random, err := randomString(RandomLength)
	if err != nil {
		return Parts{}, err
	}
	return Parts{Prefix: prefix, LookupID: lookup, Random: random}, nil
}

// Parse splits a plaintext secret. It accepts only the exact shape Generate produces.
func Parse(plain string) (Parts, error) {
	i := strings.IndexByte(plain, '_')
	if i < 0 {
		return Parts{}, ErrMalformed
	}
	prefix, rest := plain[:i+1], plain[i+1:]
	if !ValidPrefix(prefix) || len(rest) != LookupIDLength+RandomLength || !isBase62(rest) {
		return Parts{}, ErrMalformed
	}
	return Parts{Prefix: prefix, LookupID: rest[:LookupIDLength], Random: rest[LookupIDLength:]}, nil
}

// NewSalt returns SaltLength random bytes.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Hash returns SHA-256(salt || random).
func Hash(salt []byte, random string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(random))
	return h.Sum(nil)
}

// Verify reports whether random hashes to hash under salt, in constant time.
func Verify(salt, hash []byte, random string) bool {
	return subtle.ConstantTimeCompare(Hash(salt, random), hash) == 1
}

func randomString(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= acceptBelow {
				continue
			}
			out = append(out, alphabet[int(b)%len(alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(alphabet, rune(s[i])) {
			return false
		}
	}
	return true
}
