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

// Package mcp provides a Model Context Protocol (MCP) server for GoSQLX.
// It exposes SQL parsing, validation, formatting, linting, and security
// scanning as MCP tools accessible over streamable HTTP transport.
//
// # Quick start
//
//	cfg, err := mcp.LoadConfig()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	srv := mcp.New(cfg)
//	srv.Start(context.Background())
//
// # Environment variables
//
//	GOSQLX_MCP_HOST        bind host (default: 127.0.0.1)
//	GOSQLX_MCP_PORT        bind port (default: 8080)
//	GOSQLX_MCP_AUTH_TOKEN  bearer token; empty disables auth
//	GOSQLX_MCP_OPENAI_APPS_CHALLENGE  ChatGPT app domain-verification token,
//	                       served at /.well-known/openai-apps-challenge
//	GOSQLX_MCP_TRUSTED_PROXY_HEADER  header set by a trusted proxy that holds
//	                       the client IP (e.g. CF-Connecting-IP); empty = unused
//	GOSQLX_MCP_TRUSTED_PROXY_HOPS    number of trusted proxies appending to
//	                       X-Forwarded-For (0-16, default 0 = ignore XFF)
package mcp

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Config holds all MCP server configuration loaded from environment variables.
// Use LoadConfig or DefaultConfig to obtain a valid Config; the zero value is not valid.
type Config struct {
	// Host is the interface to bind to.
	// Source: GOSQLX_MCP_HOST (default: "127.0.0.1")
	Host string

	// Port is the TCP port to listen on (1–65535).
	// Source: GOSQLX_MCP_PORT (default: 8080)
	Port int

	// AuthToken is the optional bearer token for request authentication.
	// When non-empty every request must carry "Authorization: Bearer <token>".
	// Source: GOSQLX_MCP_AUTH_TOKEN (default: "" - auth disabled)
	AuthToken string

	// OpenAIAppsChallenge is the domain-verification token issued by the
	// OpenAI Platform when submitting a ChatGPT app. When non-empty it is
	// served as plain text at /.well-known/openai-apps-challenge.
	// Source: GOSQLX_MCP_OPENAI_APPS_CHALLENGE (default: "" - not served)
	OpenAIAppsChallenge string

	// TrustedProxyHeader names a header, written by a trusted reverse proxy,
	// that carries the client IP used as the rate-limit key (for example
	// "CF-Connecting-IP" behind Cloudflare). Only set it when every request
	// reaches the server through that proxy, since clients can send any
	// header themselves. Invalid values fall back to RemoteAddr.
	// Source: GOSQLX_MCP_TRUSTED_PROXY_HEADER (default: "" - not used)
	TrustedProxyHeader string

	// TrustedProxyHops is the number of trusted proxies in front of the
	// server that append to X-Forwarded-For. When > 0 the client IP is the
	// entry that many positions from the right; entries further left are
	// client-supplied and ignored.
	// Source: GOSQLX_MCP_TRUSTED_PROXY_HOPS (default: 0 - X-Forwarded-For ignored)
	TrustedProxyHops int
}

// maxTrustedProxyHops bounds GOSQLX_MCP_TRUSTED_PROXY_HOPS.
const maxTrustedProxyHops = 16

// LoadConfig reads configuration from environment variables, applying defaults
// for any variables that are unset or empty.
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	if v := os.Getenv("GOSQLX_MCP_HOST"); v != "" {
		cfg.Host = v
	}

	if v := os.Getenv("GOSQLX_MCP_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("GOSQLX_MCP_PORT: expected integer, got %q", v)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("GOSQLX_MCP_PORT: %d is out of range (1–65535)", port)
		}
		cfg.Port = port
	}

	if v := strings.TrimSpace(os.Getenv("GOSQLX_MCP_AUTH_TOKEN")); v != "" {
		cfg.AuthToken = v
	}

	if v := strings.TrimSpace(os.Getenv("GOSQLX_MCP_OPENAI_APPS_CHALLENGE")); v != "" {
		cfg.OpenAIAppsChallenge = v
	}

	if v := strings.TrimSpace(os.Getenv("GOSQLX_MCP_TRUSTED_PROXY_HEADER")); v != "" {
		if !validHeaderName(v) {
			return nil, fmt.Errorf("GOSQLX_MCP_TRUSTED_PROXY_HEADER: %q is not a valid HTTP header name", v)
		}
		canonical := http.CanonicalHeaderKey(v)
		if canonical == "X-Forwarded-For" {
			return nil, fmt.Errorf("GOSQLX_MCP_TRUSTED_PROXY_HEADER: use GOSQLX_MCP_TRUSTED_PROXY_HOPS for X-Forwarded-For")
		}
		cfg.TrustedProxyHeader = canonical
	}

	if v := strings.TrimSpace(os.Getenv("GOSQLX_MCP_TRUSTED_PROXY_HOPS")); v != "" {
		hops, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("GOSQLX_MCP_TRUSTED_PROXY_HOPS: expected integer, got %q", v)
		}
		if hops < 0 || hops > maxTrustedProxyHops {
			return nil, fmt.Errorf("GOSQLX_MCP_TRUSTED_PROXY_HOPS: %d is out of range (0–%d)", hops, maxTrustedProxyHops)
		}
		cfg.TrustedProxyHops = hops
	}

	return cfg, nil
}

// validHeaderName reports whether s is a valid HTTP header field name
// (an RFC 9110 token).
func validHeaderName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return s != ""
}

// DefaultConfig returns a Config with all defaults applied (auth disabled).
func DefaultConfig() *Config {
	return &Config{
		Host: "127.0.0.1",
		Port: 8080,
	}
}

// Addr returns the "host:port" string suitable for net/http ListenAndServe.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// AuthEnabled reports whether bearer token authentication is configured.
func (c *Config) AuthEnabled() bool {
	return c.AuthToken != ""
}
