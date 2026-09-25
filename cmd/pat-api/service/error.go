// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"fmt"
	"log/slog"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	pkgerrors "github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/log"
)

// wrapError maps a use-case error to the generated Goa error for its status. Client errors carry the curated
// message only; the wrapped cause, when any, stays in the server log. Anything unrecognised is a 500 with a
// fixed message.
func wrapError(ctx context.Context, err error) error {
	var notFound pkgerrors.NotFound
	if pkgerrors.As(err, &notFound) {
		slog.InfoContext(ctx, "resource not found", log.ErrKey, err)
		return svc.MakeNotFound(fmt.Errorf("%s", notFound.Message()))
	}

	var validation pkgerrors.Validation
	if pkgerrors.As(err, &validation) {
		slog.InfoContext(ctx, "request validation failed", log.ErrKey, err)
		return svc.MakeBadRequest(fmt.Errorf("%s", validation.Message()))
	}

	var conflict pkgerrors.Conflict
	if pkgerrors.As(err, &conflict) {
		slog.WarnContext(ctx, "request rejected due to conflict", log.ErrKey, err)
		return &svc.ConflictError{Code: conflict.Code(), Message: conflict.Message()}
	}

	var unauthorized pkgerrors.Unauthorized
	if pkgerrors.As(err, &unauthorized) {
		slog.InfoContext(ctx, "request not authenticated", log.ErrKey, err)
		return svc.MakeUnauthorized(fmt.Errorf("%s", unauthorized.Message()))
	}

	var forbidden pkgerrors.Forbidden
	if pkgerrors.As(err, &forbidden) {
		slog.WarnContext(ctx, "request forbidden", log.ErrKey, err)
		return svc.MakeForbidden(fmt.Errorf("%s", forbidden.Message()))
	}

	var unavailable pkgerrors.ServiceUnavailable
	if pkgerrors.As(err, &unavailable) {
		slog.ErrorContext(ctx, "dependency unavailable", log.ErrKey, err)
		return svc.MakeServiceUnavailable(fmt.Errorf("%s", unavailable.Message()))
	}

	slog.ErrorContext(ctx, "request failed", log.ErrKey, err)
	return svc.MakeInternalServerError(fmt.Errorf("internal service error"))
}
