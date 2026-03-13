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
package mcp

import (
	"fmt"
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
	// Source: GOSQLX_MCP_AUTH_TOKEN (default: "" — auth disabled)
	AuthToken string
}

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

	return cfg, nil
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
