// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/log"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// errorBody is the {error, message} shape every error response uses.
type errorBody struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	status  int
}

// StatusCode is read only for undeclared errors; declared ones get the status from the design.
func (b *errorBody) StatusCode() int { return b.status }

// FormatError renders every error the generated server encodes. Goa runs declared errors through it as well, so
// those pass through unchanged, while its own payload validation and decoding errors become 400s with a code.
func FormatError(ctx context.Context, err error) goahttp.Statuser {
	switch e := err.(type) {
	case *svc.BadRequestError:
		return &errorBody{Code: e.Code, Message: e.Message}
	case *svc.UnauthorizedError:
		return &errorBody{Code: e.Code, Message: e.Message}
	case *svc.ForbiddenError:
		return &errorBody{Code: e.Code, Message: e.Message}
	case *svc.NotFoundError:
		return &errorBody{Code: e.Code, Message: e.Message}
	case *svc.InvalidTokenError:
		return &errorBody{Code: e.Code, Message: e.Message}
	case *svc.ConflictError:
		return &errorBody{Code: e.Code, Message: e.Message}
	case *svc.InternalError:
		return &errorBody{Code: e.Code, Message: e.Message}
	case *svc.ServiceUnavailableError:
		return &errorBody{Code: e.Code, Message: e.Message}
	}

	var serr *goa.ServiceError
	if errors.As(err, &serr) && !serr.Fault {
		return &errorBody{Code: badRequestCode(serr), Message: serr.Message, status: http.StatusBadRequest}
	}
	slog.ErrorContext(ctx, "unhandled request error", log.ErrKey, err)
	return &errorBody{Code: constants.ErrCodeInternal, Message: "internal service error", status: http.StatusInternalServerError}
}

// badRequestCode maps the field Goa names in a validation error to its code. Merged errors keep the first
// field, and body fields are prefixed with "body.".
func badRequestCode(serr *goa.ServiceError) string {
	if serr.Field == nil {
		return constants.ErrCodeInvalidRequest
	}
	switch strings.TrimPrefix(*serr.Field, "body.") {
	case "name":
		return constants.ErrCodeInvalidName
	case "expiration":
		return constants.ErrCodeInvalidExpiration
	case "uid":
		return constants.ErrCodeInvalidUID
	case "audience":
		return constants.ErrCodeUnknownAudience
	default:
		return constants.ErrCodeInvalidRequest
	}
}
