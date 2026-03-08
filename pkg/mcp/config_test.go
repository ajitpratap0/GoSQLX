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
	"os"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear any env vars that might be set
	os.Unsetenv("GOSQLX_MCP_HOST")
	os.Unsetenv("GOSQLX_MCP_PORT")
	os.Unsetenv("GOSQLX_MCP_AUTH_TOKEN")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want %q", cfg.Host, "127.0.0.1")
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.AuthEnabled() {
		t.Error("AuthEnabled() = true, want false")
	}
	if cfg.Addr() != "127.0.0.1:8080" {
		t.Errorf("Addr() = %q, want %q", cfg.Addr(), "127.0.0.1:8080")
	}
}

func TestLoadConfig_CustomPort(t *testing.T) {
	os.Setenv("GOSQLX_MCP_PORT", "9090")
	defer os.Unsetenv("GOSQLX_MCP_PORT")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
}

func TestLoadConfig_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		val  string
	}{
		{"non-numeric", "abc"},
		{"zero", "0"},
		{"negative", "-1"},
		{"too-large", "99999"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("GOSQLX_MCP_PORT", tc.val)
			defer os.Unsetenv("GOSQLX_MCP_PORT")
			_, err := LoadConfig()
			if err == nil {
				t.Errorf("expected error for port %q, got nil", tc.val)
			}
		})
	}
}

func TestLoadConfig_AuthToken(t *testing.T) {
	os.Setenv("GOSQLX_MCP_AUTH_TOKEN", "supersecret")
	defer os.Unsetenv("GOSQLX_MCP_AUTH_TOKEN")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.AuthEnabled() {
		t.Error("AuthEnabled() = false, want true")
	}
	if cfg.AuthToken != "supersecret" {
		t.Errorf("AuthToken = %q, want %q", cfg.AuthToken, "supersecret")
	}
}

func TestLoadConfig_CustomHost(t *testing.T) {
	os.Setenv("GOSQLX_MCP_HOST", "0.0.0.0")
	defer os.Unsetenv("GOSQLX_MCP_HOST")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %q, want %q", cfg.Host, "0.0.0.0")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.AuthEnabled() {
		t.Error("AuthEnabled() = true, want false")
	}
}
