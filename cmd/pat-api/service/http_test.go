// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	svcsvr "github.com/linuxfoundation/lfx-v2-pat-service/gen/http/lfx_v2_pat_service/server"
	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goahttp "goa.design/goa/v3/http"
)

// newTestServer mounts the generated HTTP server over the adapter, serving the OpenAPI file from the
// repository root the same way a local run does.
func newTestServer(t *testing.T, s *Service) *httptest.Server {
	t.Helper()
	mux := goahttp.NewMuxer()
	endpoints := svc.NewEndpoints(s)
	server := svcsvr.New(endpoints, mux, goahttp.RequestDecoder, goahttp.ResponseEncoder, nil, nil, http.Dir("../../.."))
	svcsvr.Mount(mux, server)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, ts *httptest.Server, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, raw
}

func TestHTTPServesOpenAPI(t *testing.T) {
	ts := newTestServer(t, New(always(true)))

	resp, raw := do(t, ts, http.MethodGet, "/_tokens/openapi3.json", "")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(raw, &spec))
	for _, p := range []string{"/tokens", "/tokens/{uid}", "/_tokens/validate"} {
		assert.Contains(t, spec.Paths, p)
	}
	assert.NotContains(t, spec.Paths, "/livez", "health probes are excluded from the spec")
}

func TestHTTPProbes(t *testing.T) {
	ts := newTestServer(t, New(always(false)))

	resp, raw := do(t, ts, http.MethodGet, "/livez", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "OK\n", string(raw))

	resp, _ = do(t, ts, http.MethodGet, "/readyz", "")
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHTTPStubsAndVersionParam(t *testing.T) {
	ts := newTestServer(t, New(always(true)))

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{"create is 501", http.MethodPost, "/tokens?v=1", `{"name":"ci","audience":"insights"}`, http.StatusNotImplemented},
		{"list is 501", http.MethodGet, "/tokens?v=1", "", http.StatusNotImplemented},
		{"get is 501", http.MethodGet, "/tokens/8d4c5a2e-3b1f-4c6d-9e7a-1f2b3c4d5e6f", "", http.StatusNotImplemented},
		{"delete is 501", http.MethodDelete, "/tokens/8d4c5a2e-3b1f-4c6d-9e7a-1f2b3c4d5e6f", "", http.StatusNotImplemented},
		{"validate is 501", http.MethodPost, "/_tokens/validate?v=1", `{"secret":"lfi_x"}`, http.StatusNotImplemented},
		{"unknown version is 400", http.MethodGet, "/tokens?v=2", "", http.StatusBadRequest},
		{"non-uuid uid is 400", http.MethodGet, "/tokens/not-a-uuid", "", http.StatusBadRequest},
		{"bad audience shape is 400", http.MethodPost, "/tokens", `{"name":"ci","audience":"Not Valid"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := do(t, ts, tt.method, tt.path, tt.body)
			assert.Equal(t, tt.status, resp.StatusCode)
		})
	}
}
