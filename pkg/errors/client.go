// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package errors

import "errors"

// Validation represents invalid input (HTTP 400).
type Validation struct {
	base
	code string
}

// Error returns the error message for Validation.
func (v Validation) Error() string {
	return v.error()
}

// Code returns the stable machine-readable code.
func (v Validation) Code() string {
	return v.code
}

// NewValidation creates a new Validation error with the provided code and message.
func NewValidation(code, message string, err ...error) Validation {
	return Validation{base: base{message: message, err: errors.Join(err...)}, code: code}
}

// IsValidation reports whether err is a Validation error.
func IsValidation(err error) bool {
	var v Validation
	return errors.As(err, &v)
}

// NotFound represents a missing resource (HTTP 404). A resource the caller does not own is reported the same
// way, so existence never leaks.
type NotFound struct {
	base
}

// Error returns the error message for NotFound.
func (n NotFound) Error() string {
	return n.error()
}

// NewNotFound creates a new NotFound error with the provided message.
func NewNotFound(message string, err ...error) NotFound {
	return NotFound{base: base{message: message, err: errors.Join(err...)}}
}

// IsNotFound reports whether err is a NotFound error.
func IsNotFound(err error) bool {
	var n NotFound
	return errors.As(err, &n)
}

// Conflict represents a state conflict (HTTP 409). It carries a stable code because lfx-one can only tell
// conflict causes apart through the "error" field of the response body.
type Conflict struct {
	base
	code string
}

// Error returns the error message for Conflict.
func (c Conflict) Error() string {
	return c.error()
}

// Code returns the stable machine-readable code.
func (c Conflict) Code() string {
	return c.code
}

// NewConflict creates a new Conflict error with the provided code and message.
func NewConflict(code, message string, err ...error) Conflict {
	return Conflict{base: base{message: message, err: errors.Join(err...)}, code: code}
}

// IsConflict reports whether err is a Conflict error.
func IsConflict(err error) bool {
	var c Conflict
	return errors.As(err, &c)
}

// Unauthorized represents a missing or invalid credential (HTTP 401).
type Unauthorized struct {
	base
}

// Error returns the error message for Unauthorized.
func (u Unauthorized) Error() string {
	return u.error()
}

// NewUnauthorized creates a new Unauthorized error with the provided message.
func NewUnauthorized(message string, err ...error) Unauthorized {
	return Unauthorized{base: base{message: message, err: errors.Join(err...)}}
}

// IsUnauthorized reports whether err is an Unauthorized error.
func IsUnauthorized(err error) bool {
	var u Unauthorized
	return errors.As(err, &u)
}

// Forbidden represents a valid credential that is not allowed to perform the call (HTTP 403).
type Forbidden struct {
	base
}

// Error returns the error message for Forbidden.
func (f Forbidden) Error() string {
	return f.error()
}

// NewForbidden creates a new Forbidden error with the provided message.
func NewForbidden(message string, err ...error) Forbidden {
	return Forbidden{base: base{message: message, err: errors.Join(err...)}}
}

// IsForbidden reports whether err is a Forbidden error.
func IsForbidden(err error) bool {
	var f Forbidden
	return errors.As(err, &f)
}
