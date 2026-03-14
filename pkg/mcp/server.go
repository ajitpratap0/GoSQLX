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
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// Server wraps the MCP server with all GoSQLX tools registered.
type Server struct {
	cfg    *Config
	mcpSrv *mcpserver.MCPServer
}

// New creates a Server with all 7 GoSQLX tools registered.
func New(cfg *Config) *Server {
	s := &Server{cfg: cfg}
	s.mcpSrv = mcpserver.NewMCPServer(
		"gosqlx-mcp",
		"1.11.1",
		mcpserver.WithToolCapabilities(false),
	)
	s.registerTools()
	return s
}

// Start binds to cfg.Addr() and serves using streamable HTTP transport.
// It blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Start(ctx context.Context) error {
	streamSrv := mcpserver.NewStreamableHTTPServer(s.mcpSrv)
	wrapped := BearerAuthMiddleware(s.cfg, streamSrv)

	httpSrv := &http.Server{
		Addr:    s.cfg.Addr(),
		Handler: wrapped,
	}

	go func() {
		<-ctx.Done()
		_ = httpSrv.Shutdown(context.Background())
	}()

	log.Printf("gosqlx-mcp: listening on %s (auth=%v)\n", s.cfg.Addr(), s.cfg.AuthEnabled())
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// registerTools adds all 7 GoSQLX tools with their JSON Schema definitions.
func (s *Server) registerTools() {
	// validate_sql
	s.mcpSrv.AddTool(
		mcp.NewTool("validate_sql",
			mcp.WithDescription("Validate SQL syntax. Returns {valid: bool, error?: string, dialect?: string}."),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to validate"),
			),
			mcp.WithString("dialect",
				mcp.Description("SQL dialect: generic, mysql, postgresql, sqlite, sqlserver, oracle, snowflake"),
				mcp.Enum("generic", "mysql", "postgresql", "sqlite", "sqlserver", "oracle", "snowflake"),
			),
		),
		handleValidateSQL,
	)

	// format_sql
	s.mcpSrv.AddTool(
		mcp.NewTool("format_sql",
			mcp.WithDescription("Format SQL with configurable indentation and keyword casing."),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to format"),
			),
			mcp.WithNumber("indent_size",
				mcp.Description("Spaces per indent level (default: 2)"),
			),
			mcp.WithBoolean("uppercase_keywords",
				mcp.Description("Uppercase SQL keywords (default: false)"),
			),
			mcp.WithBoolean("add_semicolon",
				mcp.Description("Append a trailing semicolon (default: false)"),
			),
		),
		handleFormatSQL,
	)

	// parse_sql
	s.mcpSrv.AddTool(
		mcp.NewTool("parse_sql",
			mcp.WithDescription("Parse SQL and return an AST summary: statement count and types."),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to parse"),
			),
		),
		handleParseSQL,
	)

	// extract_metadata
	s.mcpSrv.AddTool(
		mcp.NewTool("extract_metadata",
			mcp.WithDescription("Extract tables, columns, and functions referenced in SQL."),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to analyze"),
			),
		),
		handleExtractMetadata,
	)

	// security_scan
	s.mcpSrv.AddTool(
		mcp.NewTool("security_scan",
			mcp.WithDescription("Scan SQL for injection patterns: tautologies, UNION attacks, stacked queries, comment bypasses, and more."),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to scan"),
			),
		),
		handleSecurityScan,
	)

	// lint_sql
	s.mcpSrv.AddTool(
		mcp.NewTool("lint_sql",
			mcp.WithDescription("Lint SQL against all 10 GoSQLX style rules (L001–L010)."),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to lint"),
			),
		),
		handleLintSQL,
	)

	// analyze_sql
	s.mcpSrv.AddTool(
		mcp.NewTool("analyze_sql",
			mcp.WithDescription("Run all 6 analysis tools concurrently and return a composite report (validate, parse, metadata, security, lint, format)."),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to analyze"),
			),
		),
		handleAnalyzeSQL,
	)
}
