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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	gosqlxmcp "github.com/ajitpratap0/GoSQLX/pkg/mcp"
)

func TestNewMux_Health(t *testing.T) {
	cfg := gosqlxmcp.DefaultConfig()
	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(newMux(cfg, srv))
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, ok := body["status"].(string); !ok || got != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if got, ok := body["version"].(string); !ok || got != gosqlx.Version {
		t.Errorf("version = %v, want %q", body["version"], gosqlx.Version)
	}
	tools, ok := body["tools"].(float64)
	if !ok || int(tools) != srv.ToolCount() || srv.ToolCount() == 0 {
		t.Errorf("tools = %v, want %d", body["tools"], srv.ToolCount())
	}
}

func TestNewMux_OpenAIAppsChallenge(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantBody   string
	}{
		{name: "configured", token: "abc123-token", wantStatus: http.StatusOK, wantBody: "abc123-token"},
		{name: "not configured", token: "", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := gosqlxmcp.DefaultConfig()
			cfg.OpenAIAppsChallenge = tt.token
			ts := httptest.NewServer(newMux(cfg, newTestServer(t, cfg)))
			t.Cleanup(ts.Close)

			resp, err := http.Get(ts.URL + "/.well-known/openai-apps-challenge")
			if err != nil {
				t.Fatalf("GET challenge: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if tt.wantBody == "" {
				return
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if string(b) != tt.wantBody {
				t.Errorf("body = %q, want %q", b, tt.wantBody)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("Content-Type = %q, want text/plain", ct)
			}
		})
	}
}

// newTestServer builds a Server whose session sweeper is stopped at test end.
func newTestServer(t *testing.T, cfg *gosqlxmcp.Config) *gosqlxmcp.Server {
	t.Helper()
	srv := gosqlxmcp.New(cfg)
	t.Cleanup(func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return srv
}

// mcpPost sends one JSON-RPC message to url. xff isolates the request in its
// own rate-limit bucket.
func mcpPost(t *testing.T, url, token, sessionID, xff, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-Forwarded-For", xff)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(b)
}

const initializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"main-test","version":"0"}}}`

// TestNewMux_HTTPChain exercises the production chain built by newMux:
// rate limit -> bearer auth -> MCP, on both /mcp and /mcp/.
func TestNewMux_HTTPChain(t *testing.T) {
	const token = "s3cret"
	cfg := gosqlxmcp.DefaultConfig()
	cfg.AuthToken = token
	ts := httptest.NewServer(newMux(cfg, newTestServer(t, cfg)))
	t.Cleanup(ts.Close)

	for i, path := range []string{"/mcp", "/mcp/"} {
		t.Run(path, func(t *testing.T) {
			url := ts.URL + path
			xff := fmt.Sprintf("192.0.2.%d", i+1)

			resp, _ := mcpPost(t, url, "", "", xff, initializeRequest)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("no token: status = %d, want 401", resp.StatusCode)
			}
			if resp.Header.Get("WWW-Authenticate") == "" {
				t.Error("no token: WWW-Authenticate header missing")
			}
			if resp.Header.Get("X-RateLimit-Limit") == "" {
				t.Error("no token: X-RateLimit-Limit missing; the rate limiter must run before auth")
			}

			resp, _ = mcpPost(t, url, "wrong", "", xff, initializeRequest)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("wrong token: status = %d, want 401", resp.StatusCode)
			}

			resp, body := mcpPost(t, url, token, "", xff, initializeRequest)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("valid token: status = %d, want 200 (body %s)", resp.StatusCode, body)
			}
			if !strings.Contains(body, `"serverInfo"`) {
				t.Errorf("initialize response has no serverInfo: %s", body)
			}
			if resp.Header.Get("Mcp-Session-Id") == "" {
				t.Error("initialize response has no Mcp-Session-Id")
			}
			if resp.Header.Get("X-RateLimit-Remaining") == "" {
				t.Error("X-RateLimit-Remaining missing on an allowed request")
			}
		})
	}

	t.Run("rate limit", func(t *testing.T) {
		const xff = "198.51.100.7"
		resp, _ := mcpPost(t, ts.URL+"/mcp", token, "", xff, initializeRequest)
		sid := resp.Header.Get("Mcp-Session-Id")
		call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"SELECT 1"}}}`
		limited := false
		for i := 0; i < 30 && !limited; i++ {
			resp, body := mcpPost(t, ts.URL+"/mcp", token, sid, xff, call)
			if strings.Contains(body, "Rate limit exceeded") {
				limited = true
				if !strings.Contains(body, `"code":-32000`) {
					t.Errorf("rate-limit response is not a JSON-RPC -32000 error: %s", body)
				}
				if resp.Header.Get("X-RateLimit-Remaining") != "0" {
					t.Errorf("X-RateLimit-Remaining = %q, want 0", resp.Header.Get("X-RateLimit-Remaining"))
				}
			}
		}
		if !limited {
			t.Error("30 rapid tools/call requests from one IP were never rate limited")
		}
	})

	t.Run("unknown paths", func(t *testing.T) {
		for _, p := range []string{"/", "/.well-known/oauth-authorization-server", "/.well-known/openai-apps-challenge"} {
			resp, err := http.Get(ts.URL + p)
			if err != nil {
				t.Fatalf("GET %s: %v", p, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s: status = %d, want 404", p, resp.StatusCode)
			}
		}
	})
}
