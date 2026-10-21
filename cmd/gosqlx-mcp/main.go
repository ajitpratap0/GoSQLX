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
//	GOSQLX_MCP_TRUSTED_PROXY_HEADER   trusted client-IP header (e.g. CF-Connecting-IP)
//	GOSQLX_MCP_TRUSTED_PROXY_HOPS     trusted proxies appending to X-Forwarded-For
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
	"strings"
	"syscall"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	gosqlxmcp "github.com/ajitpratap0/GoSQLX/pkg/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// HTTP server limits. See runHTTP for why there is no Read/WriteTimeout.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 32 << 10 // 32KB
	// otherBodyTimeout bounds request-body reads on routes other than /mcp,
	// which never read a body. net/http drains an unread body (up to 256KB)
	// before replying, so without a deadline a trickled body holds the
	// connection open forever. /mcp sets its own deadline in the rate limiter.
	otherBodyTimeout = 30 * time.Second
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

	httpSrv := newHTTPServer(cfg, srv)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("gosqlx-mcp: listening on %s (auth=%v, client-ip=%s)\n", cfg.Addr(), cfg.AuthEnabled(), clientIPSource(cfg))
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// newHTTPServer builds the http.Server for runHTTP.
//
// No ReadTimeout/WriteTimeout: they would cut off long-lived GET (SSE)
// streams. POST bodies get their own read deadline in the rate-limit
// middleware; IdleTimeout closes idle keep-alive connections.
func newHTTPServer(cfg *gosqlxmcp.Config, srv *gosqlxmcp.Server) *http.Server {
	return &http.Server{
		Addr:              cfg.Addr(),
		Handler:           withBodyDeadline(newMux(cfg, srv), otherBodyTimeout),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// withBodyDeadline sets a read deadline of timeout on every request outside
// /mcp, so slow or stalled bodies sent to /health, the challenge route or an
// unknown path cannot keep connections open. /mcp is left alone: its POST
// bodies get a deadline in the rate limiter and its GET (SSE) streams must
// not be cut off.
func withBodyDeadline(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" && !strings.HasPrefix(r.URL.Path, "/mcp/") {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(timeout))
		}
		next.ServeHTTP(w, r)
	})
}

// clientIPSource describes where rate limiting takes the client IP from.
func clientIPSource(cfg *gosqlxmcp.Config) string {
	switch {
	case cfg.TrustedProxyHeader != "":
		return cfg.TrustedProxyHeader
	case cfg.TrustedProxyHops > 0:
		return fmt.Sprintf("X-Forwarded-For[-%d]", cfg.TrustedProxyHops)
	default:
		return "RemoteAddr"
	}
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
	handler := gosqlxmcp.NewRateLimitMiddleware(cfg, srv.Handler())

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
