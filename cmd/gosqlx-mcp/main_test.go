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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		// X-Forwarded-For is ignored by default, so the limit keys on the
		// loopback peer; the header only proves spoofing does not help.
		const xff = "198.51.100.7"
		resp, _ := mcpPost(t, ts.URL+"/mcp", token, "", xff, initializeRequest)
		sid := resp.Header.Get("Mcp-Session-Id")
		call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"SELECT 1"}}}`
		limited := false
		for i := 0; i < 30 && !limited; i++ {
			resp, body := mcpPost(t, ts.URL+"/mcp", token, sid, xff, call)
			if strings.Contains(body, "Rate limit exceeded") {
				limited = true
				if resp.StatusCode != http.StatusTooManyRequests {
					t.Errorf("rate-limit status = %d, want 429", resp.StatusCode)
				}
				if !strings.Contains(body, `"code":-32000`) || !strings.Contains(body, `"id":2`) {
					t.Errorf("rate-limit response is not a JSON-RPC -32000 error for id 2: %s", body)
				}
				if resp.Header.Get("Retry-After") == "" {
					t.Error("rate-limit response has no Retry-After header")
				}
				if resp.Header.Get("X-RateLimit-Remaining") == "" {
					t.Error("rate-limit response has no X-RateLimit-Remaining header")
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

func TestNewHTTPServer_Limits(t *testing.T) {
	cfg := gosqlxmcp.DefaultConfig()
	s := newHTTPServer(cfg, gosqlxmcp.New(cfg))
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"ReadHeaderTimeout", s.ReadHeaderTimeout, readHeaderTimeout},
		{"IdleTimeout", s.IdleTimeout, idleTimeout},
		{"MaxHeaderBytes", s.MaxHeaderBytes, maxHeaderBytes},
		// A global ReadTimeout/WriteTimeout would cut off GET SSE streams.
		{"ReadTimeout unset", s.ReadTimeout, time.Duration(0)},
		{"WriteTimeout unset", s.WriteTimeout, time.Duration(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestNewMux_RateLimitIgnoresSpoofedXFF(t *testing.T) {
	cfg := gosqlxmcp.DefaultConfig()
	ts := httptest.NewServer(newMux(cfg, gosqlxmcp.New(cfg)))
	t.Cleanup(ts.Close)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	var last int
	for i := 0; i < 15; i++ {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("11.0.%d.1", i))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("15 rapid requests with rotating X-Forwarded-For: last status %d, want 429", last)
	}
}

func TestClientIPSource(t *testing.T) {
	tests := []struct {
		name string
		cfg  gosqlxmcp.Config
		want string
	}{
		{"default", gosqlxmcp.Config{}, "RemoteAddr"},
		{"header", gosqlxmcp.Config{TrustedProxyHeader: "Cf-Connecting-Ip"}, "Cf-Connecting-Ip"},
		{"hops", gosqlxmcp.Config{TrustedProxyHops: 2}, "X-Forwarded-For[-2]"},
		{"secret-gated header", gosqlxmcp.Config{TrustedProxyHeader: "Cf-Connecting-Ip", TrustedProxySecretHeader: "X-Origin-Secret", TrustedProxySecret: "s3cret-0123456789abcdef"},
			"Cf-Connecting-Ip when X-Origin-Secret matches, else RemoteAddr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientIPSource(&tt.cfg); got != tt.want {
				t.Errorf("clientIPSource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWithBodyDeadline_SlowBodyOutsideMCP(t *testing.T) {
	tests := []struct {
		name      string
		wrap      bool
		wantClose bool
	}{
		{"with deadline", true, true},
		// Control: without the wrapper the server keeps waiting for the body,
		// proving the test detects the slowloris case.
		{"without deadline", false, false},
	}
	for _, tt := range tests {
		for _, path := range []string{"/health", "/nope"} {
			t.Run(tt.name+path, func(t *testing.T) {
				cfg := gosqlxmcp.DefaultConfig()
				var h http.Handler = newMux(cfg, gosqlxmcp.New(cfg))
				if tt.wrap {
					h = withBodyDeadline(h, 200*time.Millisecond)
				}
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
				go func() { _ = srv.Serve(ln) }()
				t.Cleanup(func() { _ = srv.Close() })

				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				defer conn.Close()
				// Promise a body that never arrives.
				req := "POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabc"
				if _, err := conn.Write([]byte(req)); err != nil {
					t.Fatalf("write: %v", err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				// The server replies, then must close the connection once the
				// body-drain deadline passes instead of waiting for the body.
				_, err = io.ReadAll(conn)
				var ne net.Error
				timedOut := errors.As(err, &ne) && ne.Timeout()
				if closed := err == nil; closed != tt.wantClose || (!tt.wantClose && !timedOut) {
					t.Errorf("connection closed by server = %v (err %v), want %v", closed, err, tt.wantClose)
				}
			})
		}
	}
}

func TestClientIPSource_NeverLogsSecret(t *testing.T) {
	cfg := gosqlxmcp.Config{TrustedProxyHops: 1, TrustedProxySecretHeader: "X-Origin-Secret", TrustedProxySecret: "s3cret-0123456789abcdef"}
	if got := clientIPSource(&cfg); strings.Contains(got, cfg.TrustedProxySecret) {
		t.Fatalf("clientIPSource leaks the secret: %q", got)
	}
}

func TestSharedClientIPWarning(t *testing.T) {
	tests := []struct {
		name     string
		cfg      gosqlxmcp.Config
		wantWarn bool
	}{
		{"no trusted proxy warns", gosqlxmcp.Config{Host: "0.0.0.0", Port: 8080}, true},
		{"loopback still warns (local reverse proxy)", gosqlxmcp.Config{Host: "127.0.0.1", Port: 8080}, true},
		{"trusted header silences", gosqlxmcp.Config{TrustedProxyHeader: "Cf-Connecting-Ip"}, false},
		{"trusted hops silences", gosqlxmcp.Config{TrustedProxyHops: 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sharedClientIPWarning(&tt.cfg)
			if (got != "") != tt.wantWarn {
				t.Fatalf("sharedClientIPWarning() = %q, want warning=%v", got, tt.wantWarn)
			}
			if !tt.wantWarn {
				return
			}
			for _, want := range []string{"warning", "share", "rate-limit bucket", "stream cap",
				"GOSQLX_MCP_TRUSTED_PROXY_HEADER", "GOSQLX_MCP_TRUSTED_PROXY_HOPS"} {
				if !strings.Contains(got, want) {
					t.Errorf("warning %q does not mention %q", got, want)
				}
			}
			if strings.Contains(got, "\n") {
				t.Errorf("warning should be a single log line: %q", got)
			}
		})
	}
}
