// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service_test

import (
	"testing"

	"github.com/linuxfoundation/lfx-v2-pat-service/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestAllowList(t *testing.T) {
	list := service.NewAllowList(" abc123@clients , def456@clients,, ,abc123@clients")

	assert.Equal(t, 2, list.Len())
	assert.True(t, list.Allowed("abc123@clients"))
	assert.True(t, list.Allowed("def456@clients"))
	assert.False(t, list.Allowed("ghi789@clients"))
	assert.False(t, list.Allowed(""))
	assert.False(t, list.Allowed("alice"))
}

func TestEmptyAllowListAllowsNobody(t *testing.T) {
	for _, raw := range []string{"", "   ", ",,"} {
		list := service.NewAllowList(raw)
		assert.Equal(t, 0, list.Len(), "%q", raw)
		assert.False(t, list.Allowed(""), "%q", raw)
		assert.False(t, list.Allowed("abc@clients"), "%q", raw)
	}
}
