// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package errors defines the typed errors the use-cases return, so the Goa adapter can map each to one HTTP
// status without inspecting message text.
package errors

import (
	stderrors "errors"
	"fmt"
)

// Is re-exports errors.Is so callers need only this package.
func Is(err, target error) bool {
	return stderrors.Is(err, target)
}

// As re-exports errors.As so callers need only this package.
func As(err error, target any) bool {
	return stderrors.As(err, target)
}

// base holds the common fields for error types.
type base struct {
	message string
	err     error
}

// Message returns the curated message without any wrapped cause, so callers can surface stable text to
// clients while the full cause stays in server logs.
func (b base) Message() string {
	return b.message
}

func (b base) error() string {
	if b.err == nil {
		return b.message
	}
	return fmt.Sprintf("%s: %v", b.message, b.err)
}

// Unwrap exposes the wrapped cause to errors.Is and errors.As.
func (b base) Unwrap() error {
	return b.err
}
