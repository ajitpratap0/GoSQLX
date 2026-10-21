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
	"strings"
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

func TestLoadConfig_OpenAIAppsChallenge(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "unset", env: "", want: ""},
		{name: "trimmed", env: "  tok-123\n", want: "tok-123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOSQLX_MCP_OPENAI_APPS_CHALLENGE", tt.env)
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.OpenAIAppsChallenge != tt.want {
				t.Errorf("OpenAIAppsChallenge = %q, want %q", cfg.OpenAIAppsChallenge, tt.want)
			}
		})
	}
}

func TestLoadConfig_TrustedProxy(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		hops       string
		wantHeader string
		wantHops   int
		wantErr    bool
	}{
		{name: "unset", wantHeader: "", wantHops: 0},
		{name: "cloudflare header canonicalised", header: " cf-connecting-ip ", wantHeader: "Cf-Connecting-Ip"},
		{name: "hops", hops: "2", wantHops: 2},
		{name: "both", header: "True-Client-IP", hops: "1", wantHeader: "True-Client-Ip", wantHops: 1},
		{name: "invalid header name", header: "CF Connecting IP", wantErr: true},
		{name: "XFF as header rejected", header: "x-forwarded-for", wantErr: true},
		{name: "hops non-numeric", hops: "one", wantErr: true},
		{name: "hops negative", hops: "-1", wantErr: true},
		{name: "hops too large", hops: "17", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOSQLX_MCP_TRUSTED_PROXY_HEADER", tt.header)
			t.Setenv("GOSQLX_MCP_TRUSTED_PROXY_HOPS", tt.hops)
			cfg, err := LoadConfig()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got config %+v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.TrustedProxyHeader != tt.wantHeader || cfg.TrustedProxyHops != tt.wantHops {
				t.Errorf("got header=%q hops=%d, want header=%q hops=%d",
					cfg.TrustedProxyHeader, cfg.TrustedProxyHops, tt.wantHeader, tt.wantHops)
			}
		})
	}
}

func TestLoadConfig_TrustedProxySecret(t *testing.T) {
	const secret = "s3cret-0123456789abcdef"
	tests := []struct {
		name       string
		header     string
		hops       string
		secretHdr  string
		secret     string
		wantHeader string
		wantErr    string
	}{
		{name: "unset keeps default", header: "CF-Connecting-IP"},
		{name: "header and secret", header: "CF-Connecting-IP", secretHdr: " x-origin-secret ", secret: secret, wantHeader: "X-Origin-Secret"},
		{name: "with hops", hops: "1", secretHdr: "X-Origin-Secret", secret: secret, wantHeader: "X-Origin-Secret"},
		{name: "secret without header", header: "CF-Connecting-IP", secret: secret, wantErr: "must be set together"},
		{name: "header without secret", header: "CF-Connecting-IP", secretHdr: "X-Origin-Secret", wantErr: "must be set together"},
		{name: "invalid header name", header: "CF-Connecting-IP", secretHdr: "X Origin", secret: secret, wantErr: "not a valid HTTP header name"},
		{name: "XFF rejected", hops: "1", secretHdr: "X-Forwarded-For", secret: secret, wantErr: "cannot be used"},
		{name: "Authorization rejected", header: "CF-Connecting-IP", secretHdr: "authorization", secret: secret, wantErr: "cannot be used"},
		{name: "same as client IP header rejected", header: "CF-Connecting-IP", secretHdr: "cf-connecting-ip", secret: secret, wantErr: "cannot be used"},
		{name: "short secret rejected", header: "CF-Connecting-IP", secretHdr: "X-Origin-Secret", secret: "short", wantErr: "at least 16"},
		{name: "no trusted proxy rejected", secretHdr: "X-Origin-Secret", secret: secret, wantErr: "requires GOSQLX_MCP_TRUSTED_PROXY_HEADER"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOSQLX_MCP_TRUSTED_PROXY_HEADER", tt.header)
			t.Setenv("GOSQLX_MCP_TRUSTED_PROXY_HOPS", tt.hops)
			t.Setenv("GOSQLX_MCP_TRUSTED_PROXY_SECRET_HEADER", tt.secretHdr)
			t.Setenv("GOSQLX_MCP_TRUSTED_PROXY_SECRET", tt.secret)
			cfg, err := LoadConfig()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got config %+v", tt.wantErr, cfg)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
				}
				if tt.secret != "" && strings.Contains(err.Error(), tt.secret) {
					t.Errorf("error leaks the secret: %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.TrustedProxySecretHeader != tt.wantHeader {
				t.Errorf("TrustedProxySecretHeader = %q, want %q", cfg.TrustedProxySecretHeader, tt.wantHeader)
			}
			wantSecret := ""
			if tt.wantHeader != "" {
				wantSecret = tt.secret
			}
			if cfg.TrustedProxySecret != wantSecret {
				t.Errorf("TrustedProxySecret not loaded as expected (set=%v)", cfg.TrustedProxySecret != "")
			}
		})
	}
}
