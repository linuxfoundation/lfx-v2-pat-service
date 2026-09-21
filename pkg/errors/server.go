// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package errors

import "errors"

// Unexpected represents a failure the service cannot attribute to the caller (HTTP 500).
type Unexpected struct {
	base
}

// Error returns the error message for Unexpected.
func (u Unexpected) Error() string {
	return u.error()
}

// NewUnexpected creates a new Unexpected error with the provided message.
func NewUnexpected(message string, err ...error) Unexpected {
	return Unexpected{base: base{message: message, err: errors.Join(err...)}}
}

// ServiceUnavailable represents a dependency outage (HTTP 503).
type ServiceUnavailable struct {
	base
}

// Error returns the error message for ServiceUnavailable.
func (s ServiceUnavailable) Error() string {
	return s.error()
}

// NewServiceUnavailable creates a new ServiceUnavailable error with the provided message.
func NewServiceUnavailable(message string, err ...error) ServiceUnavailable {
	return ServiceUnavailable{base: base{message: message, err: errors.Join(err...)}}
}

// IsServiceUnavailable reports whether err is a ServiceUnavailable error.
func IsServiceUnavailable(err error) bool {
	var s ServiceUnavailable
	return errors.As(err, &s)
}
