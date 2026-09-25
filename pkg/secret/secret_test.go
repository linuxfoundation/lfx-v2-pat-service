// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package secret

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateShape(t *testing.T) {
	p, err := Generate("lfi_")
	require.NoError(t, err)

	assert.Equal(t, "lfi_", p.Prefix)
	assert.Len(t, p.LookupID, LookupIDLength)
	assert.Len(t, p.Random, RandomLength)
	assert.True(t, isBase62(p.LookupID+p.Random))
	assert.Equal(t, "lfi_"+p.LookupID+p.Random, p.String())
	assert.Len(t, p.String(), 4+LookupIDLength+RandomLength)
}

func TestGenerateRejectsBadPrefix(t *testing.T) {
	for _, prefix := range []string{"", "lfi", "LFI_", "l_", "toolongprefix_", "lf-i_", "lfi__"} {
		_, err := Generate(prefix)
		assert.Error(t, err, prefix)
	}
}

func TestGenerateIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 10000)
	for i := 0; i < 10000; i++ {
		p, err := Generate("lfi_")
		require.NoError(t, err)
		_, dup := seen[p.LookupID]
		require.False(t, dup, "duplicate lookup id after %d secrets", i)
		seen[p.LookupID] = struct{}{}
	}
}

func TestParseRoundTrip(t *testing.T) {
	p, err := Generate("lfi_")
	require.NoError(t, err)

	got, err := Parse(p.String())

	require.NoError(t, err)
	assert.Equal(t, p, got)
}

func TestParseRejections(t *testing.T) {
	valid := "lfi_" + strings.Repeat("a", LookupIDLength) + strings.Repeat("b", RandomLength)
	tests := []struct {
		name  string
		plain string
	}{
		{"empty", ""},
		{"no underscore", strings.ReplaceAll(valid, "_", "")},
		{"uppercase prefix", "LFI_" + valid[4:]},
		{"too short", valid[:len(valid)-1]},
		{"too long", valid + "c"},
		{"underscore in body", valid[:20] + "_" + valid[21:]},
		{"dash in body", valid[:20] + "-" + valid[21:]},
		{"space in body", valid[:20] + " " + valid[21:]},
		{"prefix only", "lfi_"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.plain)
			assert.ErrorIs(t, err, ErrMalformed)
		})
	}

	_, err := Parse(valid)
	assert.NoError(t, err)
}

func TestVerify(t *testing.T) {
	salt, err := NewSalt()
	require.NoError(t, err)
	require.Len(t, salt, SaltLength)
	hash := Hash(salt, "random-part")

	assert.Len(t, hash, 32)
	assert.True(t, Verify(salt, hash, "random-part"))
	assert.False(t, Verify(salt, hash, "random-parT"))
	other, err := NewSalt()
	require.NoError(t, err)
	assert.False(t, Verify(other, hash, "random-part"))
	assert.False(t, Verify(salt, hash[:31], "random-part"))
}

func TestHashKnownVector(t *testing.T) {
	// sha256("salt" || "random") computed independently with Python's hashlib.
	got := Hash([]byte("salt"), "random")
	assert.Equal(t, "3c3703d74ce5e51533e46f2b2cff72da3e856ae88d895937e447ae6d8a166f03", hex.EncodeToString(got))
}

func TestPrefixPatternMatchesSchemaCheck(t *testing.T) {
	for _, ok := range []string{"lfi_", "ab_", "abcdefgh_", "a1b2_"} {
		assert.True(t, ValidPrefix(ok), ok)
	}
	for _, bad := range []string{"a_", "abcdefghi_", "Lfi_", "lfi", "lf_i_", "lf-i_"} {
		assert.False(t, ValidPrefix(bad), bad)
	}
}
