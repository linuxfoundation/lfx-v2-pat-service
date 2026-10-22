// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessagesKeepCauseOutOfMessage(t *testing.T) {
	cause := errors.New("db down")
	tests := []struct {
		name    string
		err     error
		message string
		full    string
	}{
		{"validation", NewValidation("invalid_name", "bad name"), "bad name", "bad name"},
		{"not found with cause", NewNotFound("no token", cause), "no token", "no token: db down"},
		{"conflict", NewConflict("token_name_taken", "name taken"), "name taken", "name taken"},
		{"unauthorized", NewUnauthorized("no token"), "no token", "no token"},
		{"forbidden", NewForbidden("not allowed"), "not allowed", "not allowed"},
		{"unexpected joins causes", NewUnexpected("boom", errors.New("a"), errors.New("b")), "boom", "boom: a\nb"},
		{"service unavailable", NewServiceUnavailable("db", cause), "db", "db: db down"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.full, tt.err.Error())
			m, ok := tt.err.(interface{ Message() string })
			if assert.True(t, ok) {
				assert.Equal(t, tt.message, m.Message())
			}
		})
	}
}

func TestPredicatesMatchThroughWrapping(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("outer: %w", err) }

	assert.True(t, IsValidation(wrap(NewValidation("invalid_name", "x"))))
	assert.True(t, IsNotFound(wrap(NewNotFound("x"))))
	assert.True(t, IsConflict(wrap(NewConflict("c", "x"))))
	assert.True(t, IsUnauthorized(wrap(NewUnauthorized("x"))))
	assert.True(t, IsForbidden(wrap(NewForbidden("x"))))
	assert.True(t, IsServiceUnavailable(wrap(NewServiceUnavailable("x"))))

	assert.False(t, IsNotFound(NewValidation("invalid_name", "x")))
	assert.False(t, IsValidation(nil))
	assert.False(t, IsConflict(errors.New("plain")))
}

func TestConflictCodeAndUnwrap(t *testing.T) {
	cause := errors.New("unique violation")
	err := NewConflict("token_limit_reached", "too many", cause)

	var c Conflict
	if assert.ErrorAs(t, err, &c) {
		assert.Equal(t, "token_limit_reached", c.Code())
	}
	assert.ErrorIs(t, err, cause)
}
