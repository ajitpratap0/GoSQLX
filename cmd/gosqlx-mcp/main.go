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
//
// # Usage
//
//	gosqlx-mcp
//	GOSQLX_MCP_PORT=9090 gosqlx-mcp
//	GOSQLX_MCP_AUTH_TOKEN=secret gosqlx-mcp
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	gosqlxmcp "github.com/ajitpratap0/GoSQLX/pkg/mcp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gosqlx-mcp: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := gosqlxmcp.LoadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := gosqlxmcp.New(cfg)

	// Build handler chain: MCP → auth → rate limiter
	handler := gosqlxmcp.RateLimitMiddleware(srv.Handler())

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":"%s","tools":7}`, "1.11.1")
	})

	httpSrv := &http.Server{
		Addr:    cfg.Addr(),
		Handler: mux,
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
