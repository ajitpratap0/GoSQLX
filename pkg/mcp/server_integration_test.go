// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpserver "github.com/mark3labs/mcp-go/server"
)

func newTestHTTPServer(t *testing.T, authToken string) *httptest.Server {
	t.Helper()
	cfg := &Config{Host: "127.0.0.1", Port: 8080, AuthToken: authToken}
	srv := New(cfg)
	streamSrv := mcpserver.NewStreamableHTTPServer(srv.mcpSrv)
	wrapped := BearerAuthMiddleware(cfg, streamSrv)
	return httptest.NewServer(wrapped)
}

func TestIntegration_AuthRequired_NoToken(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestIntegration_AuthRequired_WrongToken(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestIntegration_AuthRequired_ValidToken(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("got 401 with valid token — middleware should have passed through")
	}
}

func TestIntegration_NoAuth_RequestPassesThrough(t *testing.T) {
	ts := newTestHTTPServer(t, "")
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("got 401 when auth is disabled")
	}
}

func TestIntegration_AuthRequired_GETAlsoBlocked(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for GET without token, got %d", resp.StatusCode)
	}
}
