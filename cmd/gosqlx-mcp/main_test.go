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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	gosqlxmcp "github.com/ajitpratap0/GoSQLX/pkg/mcp"
)

func TestNewMux_Health(t *testing.T) {
	cfg := gosqlxmcp.DefaultConfig()
	srv := gosqlxmcp.New(cfg)
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
			ts := httptest.NewServer(newMux(cfg, gosqlxmcp.New(cfg)))
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
