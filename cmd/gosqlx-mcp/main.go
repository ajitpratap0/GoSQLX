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

// Package main is the entry point for the gosqlx-mcp MCP server.
//
// The server exposes GoSQLX SQL processing capabilities as MCP tools
// accessible over streamable HTTP transport.
//
// # Environment variables
//
//	GOSQLX_MCP_HOST        bind host (default: 127.0.0.1)
//	GOSQLX_MCP_PORT        bind port (default: 8080)
//	GOSQLX_MCP_AUTH_TOKEN  bearer token; empty disables auth
//	GOSQLX_MCP_OPENAI_APPS_CHALLENGE  ChatGPT app domain-verification token
//
// Pass --stdio to serve MCP over stdin/stdout instead of HTTP.
//
// # Usage
//
//	gosqlx-mcp
//	GOSQLX_MCP_PORT=9090 gosqlx-mcp
//	GOSQLX_MCP_AUTH_TOKEN=secret gosqlx-mcp
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	gosqlxmcp "github.com/ajitpratap0/GoSQLX/pkg/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gosqlx-mcp: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Check for --stdio flag (used when spawned by mcp-proxy as a subprocess).
	for _, arg := range os.Args[1:] {
		if arg == "--stdio" {
			return runStdio()
		}
	}
	return runHTTP()
}

// runStdio serves the MCP protocol over stdin/stdout.
// This mode is used when the binary is spawned by mcp-proxy.
func runStdio() error {
	cfg := gosqlxmcp.DefaultConfig()
	srv := gosqlxmcp.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stdioSrv := mcpserver.NewStdioServer(srv.MCPServer())
	stdioSrv.SetErrorLogger(log.New(os.Stderr, "gosqlx-mcp: ", log.LstdFlags))
	return stdioSrv.Listen(ctx, os.Stdin, os.Stdout)
}

// runHTTP serves the MCP protocol over streamable HTTP transport.
func runHTTP() error {
	cfg, err := gosqlxmcp.LoadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := gosqlxmcp.New(cfg)

	httpSrv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           newMux(cfg, srv),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("gosqlx-mcp: listening on %s (auth=%v)\n", cfg.Addr(), cfg.AuthEnabled())
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// newMux builds the HTTP routes:
//
//	/mcp, /mcp/  MCP streamable HTTP (rate limit → auth → MCP)
//	/health      liveness probe with version and tool count
//	/.well-known/openai-apps-challenge  ChatGPT app domain verification (only when configured)
//
// Every other path (including OAuth discovery probes from connector wizards)
// returns 404, which tells clients that no OAuth is configured.
func newMux(cfg *gosqlxmcp.Config, srv *gosqlxmcp.Server) *http.ServeMux {
	handler := gosqlxmcp.RateLimitMiddleware(srv.Handler())

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)

	health, _ := json.Marshal(map[string]any{
		"status":  "ok",
		"version": gosqlx.Version,
		"tools":   srv.ToolCount(),
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(health)
	})

	if token := cfg.OpenAIAppsChallenge; token != "" {
		mux.HandleFunc("/.well-known/openai-apps-challenge", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(token))
		})
	}
	return mux
}
