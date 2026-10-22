// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	svcsvr "github.com/linuxfoundation/lfx-v2-pat-service/gen/http/lfx_v2_pat_service/server"
	svc "github.com/linuxfoundation/lfx-v2-pat-service/gen/lfx_v2_pat_service"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
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
	server := svcsvr.New(endpoints, mux, goahttp.RequestDecoder, goahttp.ResponseEncoder, nil, FormatError, http.Dir("../../.."))
	svcsvr.Mount(mux, server)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// do sends a request as the given principal (see bearerAuth) and returns the status and body.
func do(t *testing.T, ts *httptest.Server, principal, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	if principal != "" {
		req.Header.Set("Authorization", "Bearer "+principal)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded map[string]any
	if len(raw) > 0 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		require.NoError(t, json.Unmarshal(raw, &decoded), string(raw))
	}
	return resp.StatusCode, decoded, string(raw)
}

func TestHTTPServesOpenAPI(t *testing.T) {
	deps, _ := newDeps(true, bearerAuth{})
	ts := newTestServer(t, New(deps))

	status, _, raw := do(t, ts, "", http.MethodGet, "/_tokens/openapi3.json", "")

	require.Equal(t, http.StatusOK, status)
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &spec))
	for _, p := range []string{"/tokens", "/tokens/{uid}", "/_tokens/validate"} {
		assert.Contains(t, spec.Paths, p)
	}
	assert.NotContains(t, spec.Paths, "/livez", "health probes are excluded from the spec")
}

func TestHTTPProbes(t *testing.T) {
	deps, _ := newDeps(false, bearerAuth{})
	ts := newTestServer(t, New(deps))

	status, _, raw := do(t, ts, "", http.MethodGet, "/livez", "")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "OK\n", raw)

	status, _, _ = do(t, ts, "", http.MethodGet, "/readyz", "")
	assert.Equal(t, http.StatusServiceUnavailable, status)
}

func TestHTTPTokenLifecycle(t *testing.T) {
	deps, _ := newDeps(true, bearerAuth{})
	ts := newTestServer(t, New(deps))
	createBody := `{"name":"ci","audience":"insights"}`

	// Create: the secret appears here and only here.
	status, body, raw := do(t, ts, "alice", http.MethodPost, "/tokens?v=1", createBody)
	require.Equal(t, http.StatusCreated, status, raw)
	secret, _ := body["secret"].(string)
	assert.True(t, strings.HasPrefix(secret, "lfi_"), raw)
	assert.Equal(t, 1, strings.Count(raw, `"secret"`))
	token, _ := body["token"].(map[string]any)
	uid, _ := token["uid"].(string)
	require.NotEmpty(t, uid)
	assert.Equal(t, "ci", token["name"])
	assert.Equal(t, "insights", token["audience"])
	assert.Equal(t, "alice", token["username"])
	assert.Len(t, token["lookup_id"], 12)
	assert.Contains(t, token, "created_at")
	assert.NotContains(t, token, "last_used_at")
	assert.NotContains(t, token, "expires_at", "omitting expiration means the token never expires")
	for _, forbidden := range []string{"salt", "secret_hash", "updated_at", "revoked_at"} {
		assert.NotContains(t, token, forbidden)
	}

	// An expiring token reports when it stops validating, counted from creation.
	status, body, raw = do(t, ts, "alice", http.MethodPost, "/tokens", `{"name":"ci-90","audience":"insights","expiration":"90d"}`)
	require.Equal(t, http.StatusCreated, status, raw)
	expiring, _ := body["token"].(map[string]any)
	expiresAt, err := time.Parse(time.RFC3339, fmt.Sprint(expiring["expires_at"]))
	require.NoError(t, err, raw)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, 90), expiresAt, time.Minute)
	status, body, _ = do(t, ts, "alice", http.MethodGet, "/tokens", "")
	require.Equal(t, http.StatusOK, status)
	listed, _ := body["tokens"].([]any)
	require.Len(t, listed, 2)
	assert.Equal(t, expiring["expires_at"], listed[0].(map[string]any)["expires_at"], "list returns the same expiry, newest first")
	status, _, _ = do(t, ts, "alice", http.MethodDelete, "/tokens/"+fmt.Sprint(expiring["uid"]), "")
	require.Equal(t, http.StatusNoContent, status)

	// List exposes the lookup id and never the secret.
	status, body, raw = do(t, ts, "alice", http.MethodGet, "/tokens?v=1", "")
	require.Equal(t, http.StatusOK, status, raw)
	tokens, _ := body["tokens"].([]any)
	require.Len(t, tokens, 1)
	assert.NotContains(t, raw, secret)
	assert.NotContains(t, raw, `"secret"`)

	// Other owners see nothing.
	status, body, _ = do(t, ts, "bob", http.MethodGet, "/tokens", "")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, []any{}, body["tokens"], "an empty list encodes as [] not null")
	status, _, _ = do(t, ts, "bob", http.MethodDelete, "/tokens/"+uid, "")
	assert.Equal(t, http.StatusNotFound, status)

	// Validate as a machine principal: identity plus recorded use.
	status, body, raw = do(t, ts, "abc123@clients", http.MethodPost, "/_tokens/validate?v=1", `{"secret":"`+secret+`"}`)
	require.Equal(t, http.StatusOK, status, raw)
	assert.Equal(t, uid, body["uid"])
	assert.Equal(t, "alice", body["username"])
	assert.Equal(t, "insights", body["audience"])
	assert.Equal(t, "alice@example.com", body["email"])
	status, body, _ = do(t, ts, "alice", http.MethodGet, "/tokens", "")
	require.Equal(t, http.StatusOK, status)
	tokens, _ = body["tokens"].([]any)
	require.Len(t, tokens, 1)
	assert.Contains(t, tokens[0], "last_used_at")

	// Revoke: 204 once, 404 after, and the secret stops validating.
	status, _, _ = do(t, ts, "alice", http.MethodDelete, "/tokens/"+uid+"?v=1", "")
	assert.Equal(t, http.StatusNoContent, status)
	status, _, _ = do(t, ts, "alice", http.MethodDelete, "/tokens/"+uid, "")
	assert.Equal(t, http.StatusNotFound, status)
	status, body, _ = do(t, ts, "alice", http.MethodGet, "/tokens", "")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, []any{}, body["tokens"])
	status, body, _ = do(t, ts, "abc123@clients", http.MethodPost, "/_tokens/validate", `{"secret":"`+secret+`"}`)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, constants.ErrCodeInvalidToken, body["error"])
}

func TestHTTPErrorBodies(t *testing.T) {
	deps, _ := newDeps(true, bearerAuth{})
	ts := newTestServer(t, New(deps))
	for _, name := range []string{"one", "two", "three"} {
		status, _, raw := do(t, ts, "alice", http.MethodPost, "/tokens", `{"name":"`+name+`","audience":"insights"}`)
		require.Equal(t, http.StatusCreated, status, raw)
	}

	tests := []struct {
		name      string
		principal string
		method    string
		path      string
		body      string
		status    int
		code      string
	}{
		{"duplicate name", "alice", http.MethodPost, "/tokens", `{"name":"ONE","audience":"insights"}`, http.StatusConflict, constants.ErrCodeTokenNameTaken},
		{"limit reached", "alice", http.MethodPost, "/tokens", `{"name":"four","audience":"insights"}`, http.StatusConflict, constants.ErrCodeTokenLimitReached},
		{"unknown audience", "alice", http.MethodPost, "/tokens", `{"name":"x","audience":"nope"}`, http.StatusBadRequest, constants.ErrCodeUnknownAudience},
		{"audience shape", "alice", http.MethodPost, "/tokens", `{"name":"x","audience":"Not Valid"}`, http.StatusBadRequest, constants.ErrCodeUnknownAudience},
		{"blank name", "alice", http.MethodPost, "/tokens", `{"name":"   ","audience":"insights"}`, http.StatusBadRequest, constants.ErrCodeInvalidName},
		{"unknown expiration", "alice", http.MethodPost, "/tokens", `{"name":"x","audience":"insights","expiration":"7d"}`, http.StatusBadRequest, constants.ErrCodeInvalidExpiration},
		{"unknown version", "alice", http.MethodGet, "/tokens?v=2", "", http.StatusBadRequest, constants.ErrCodeInvalidRequest},
		{"non-uuid uid", "alice", http.MethodDelete, "/tokens/not-a-uuid", "", http.StatusBadRequest, constants.ErrCodeInvalidUID},
		{"get by uid is not routed", "alice", http.MethodGet, "/tokens/00000000-0000-4000-8000-000000000000", "", http.StatusMethodNotAllowed, ""},
		{"no bearer", "", http.MethodGet, "/tokens", "", http.StatusUnauthorized, constants.ErrCodeUnauthorized},
		{"machine on user route", "abc123@clients", http.MethodGet, "/tokens", "", http.StatusForbidden, constants.ErrCodeForbidden},
		{"malformed secret", "abc123@clients", http.MethodPost, "/_tokens/validate", `{"secret":"lfi_x"}`, http.StatusNotFound, constants.ErrCodeInvalidToken},
		{"empty secret", "abc123@clients", http.MethodPost, "/_tokens/validate", `{"secret":""}`, http.StatusBadRequest, constants.ErrCodeInvalidRequest},
		{"malformed json", "alice", http.MethodPost, "/tokens", `{"name":`, http.StatusBadRequest, constants.ErrCodeInvalidRequest},
		{"unknown uid", "alice", http.MethodDelete, "/tokens/00000000-0000-4000-8000-000000000000", "", http.StatusNotFound, constants.ErrCodeTokenNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body, raw := do(t, ts, tt.principal, tt.method, tt.path, tt.body)
			assert.Equal(t, tt.status, status, raw)
			if tt.code != "" {
				assert.Equal(t, map[string]any{"error": tt.code, "message": body["message"]}, body, raw)
				assert.NotEmpty(t, body["message"])
			}
		})
	}
}
