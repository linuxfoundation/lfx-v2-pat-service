// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/stretchr/testify/assert"
)

func TestFormatErrorRedactsUndeclaredErrors(t *testing.T) {
	body := FormatError(context.Background(), fmt.Errorf("db exploded")).(*errorBody)

	assert.Equal(t, http.StatusInternalServerError, body.StatusCode())
	assert.Equal(t, constants.ErrCodeInternal, body.Code)
	assert.NotContains(t, body.Message, "exploded")
}
