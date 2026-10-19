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
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// Server wraps the MCP server with all GoSQLX tools and UI resources registered.
type Server struct {
	cfg    *Config
	mcpSrv *mcpserver.MCPServer
}

// serverInstructions is returned in the initialize result so the client
// model knows when to reach for each tool.
const serverInstructions = `GoSQLX parses, validates, formats, lints, and security-scans SQL locally. ` +
	`All tools are read-only, deterministic, and never connect to a database or execute SQL.

Pick the narrowest tool for the request:
- analyze_sql: one-shot review of a query (validity, statement types, tables/columns/functions, security findings, lint violations, formatted SQL). Prefer it when the user asks to "review", "check", or "analyze" SQL; hosts that support MCP Apps render it as an interactive report.
- validate_sql: is the SQL syntactically valid, optionally for a specific dialect (postgresql, mysql, mariadb, sqlserver, oracle, sqlite, snowflake, clickhouse).
- format_sql: pretty-print SQL (indent size, keyword casing, trailing semicolon).
- parse_sql: statement count and AST statement types.
- extract_metadata: tables, columns, and functions referenced.
- security_scan: SQL-injection pattern detection (tautologies, UNION-based, stacked queries, comment bypass, ...), with severities.
- lint_sql: style rules L001-L010 (whitespace, indentation, line length, alignment, keyword case, comma placement, aliasing).

Pass the SQL text exactly as the user wrote it. Results are JSON; summarise them for the user rather than repeating them verbatim.`

// New creates a Server with all GoSQLX tools and the analysis widget resource registered.
func New(cfg *Config) *Server {
	s := &Server{cfg: cfg}
	s.mcpSrv = mcpserver.NewMCPServer(
		"gosqlx-mcp",
		gosqlx.Version,
		mcpserver.WithToolCapabilities(false),
		mcpserver.WithResourceCapabilities(false, false),
		mcpserver.WithInstructions(serverInstructions),
	)
	s.registerTools()
	s.registerResources()
	return s
}

// ToolCount reports how many tools are registered.
func (s *Server) ToolCount() int {
	return len(s.mcpSrv.ListTools())
}

// Handler returns the HTTP handler chain (MCP server + auth middleware)
// without starting an HTTP server. Use this when you need to wrap
// the handler with additional middleware (e.g., rate limiting).
func (s *Server) Handler() http.Handler {
	streamSrv := s.newStreamableHTTPServer()
	return BearerAuthMiddleware(s.cfg, streamSrv)
}

// SessionIdleTTL is how long an idle MCP session's transport state is kept.
// Clients that disconnect without sending DELETE (the common case for hosted
// assistants) would otherwise leave their session state in memory until the
// process restarts. The privacy policy on gosqlx.dev cites this value.
const SessionIdleTTL = 30 * time.Minute

// newStreamableHTTPServer builds the streamable HTTP transport with idle
// session sweeping enabled.
func (s *Server) newStreamableHTTPServer() *mcpserver.StreamableHTTPServer {
	return mcpserver.NewStreamableHTTPServer(s.mcpSrv,
		mcpserver.WithSessionIdleTTL(SessionIdleTTL),
	)
}

// Cfg returns the server configuration.
func (s *Server) Cfg() *Config {
	return s.cfg
}

// MCPServer returns the underlying MCPServer for use with alternative transports
// such as stdio (mcpserver.NewStdioServer).
func (s *Server) MCPServer() *mcpserver.MCPServer {
	return s.mcpSrv
}

// Start binds to cfg.Addr() and serves using streamable HTTP transport.
// It blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Start(ctx context.Context) error {
	streamSrv := s.newStreamableHTTPServer()
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

// readOnlyAnnotations are shared by every GoSQLX tool: pure local computation
// on the SQL text, no side effects, no network or database access. ChatGPT
// requires readOnly/destructive/openWorld to be set explicitly.
func readOnlyAnnotations(title string) []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithTitleAnnotation(title),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	}
}

// newTool assembles a tool from shared annotations, _meta and its own options.
func newTool(name, title, description string, meta *mcp.Meta, opts ...mcp.ToolOption) mcp.Tool {
	all := make([]mcp.ToolOption, 0, len(opts)+7)
	all = append(all, mcp.WithDescription(description))
	all = append(all, readOnlyAnnotations(title)...)
	all = append(all, withToolMeta(meta))
	all = append(all, opts...)
	return mcp.NewTool(name, all...)
}

// supportedDialects lists the dialect values accepted by validate_sql. Each
// one is accepted by gosqlx.ParseWithDialect.
var supportedDialects = []string{
	"generic", "postgresql", "mysql", "mariadb", "sqlserver",
	"oracle", "sqlite", "snowflake", "clickhouse",
}

// registerTools adds all 7 GoSQLX tools with their JSON Schema definitions.
func (s *Server) registerTools() {
	cfg := s.cfg

	s.mcpSrv.AddTool(
		newTool("validate_sql", "Validate SQL",
			"Use this when the user wants to know whether a SQL statement is syntactically valid, "+
				"optionally for a specific dialect. Returns {valid: bool, error?: string, dialect?: string}.",
			toolMeta(cfg, "Validating SQL…", "Validated SQL", false),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to validate"),
			),
			mcp.WithString("dialect",
				mcp.Description("SQL dialect: generic, postgresql, mysql, mariadb, sqlserver, oracle, sqlite, snowflake, clickhouse"),
				mcp.Enum(supportedDialects...),
			),
		),
		handleValidateSQL,
	)

	s.mcpSrv.AddTool(
		newTool("format_sql", "Format SQL",
			"Use this when the user wants SQL pretty-printed or reformatted, with configurable "+
				"indentation, keyword casing, and trailing semicolon. Returns {formatted_sql, options}.",
			toolMeta(cfg, "Formatting SQL…", "Formatted SQL", false),
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

	s.mcpSrv.AddTool(
		newTool("parse_sql", "Parse SQL",
			"Use this when the user wants to know how SQL parses: returns an AST summary with "+
				"the statement count and the type of each statement.",
			toolMeta(cfg, "Parsing SQL…", "Parsed SQL", false),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to parse"),
			),
		),
		handleParseSQL,
	)

	s.mcpSrv.AddTool(
		newTool("extract_metadata", "Extract SQL metadata",
			"Use this when the user wants the tables, columns, and functions a SQL query references "+
				"(e.g. for lineage or impact analysis). Returns {tables, columns, functions}.",
			toolMeta(cfg, "Extracting tables and columns…", "Extracted SQL metadata", false),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to analyze"),
			),
		),
		handleExtractMetadata,
	)

	s.mcpSrv.AddTool(
		newTool("security_scan", "Scan SQL for injection",
			"Use this when the user wants SQL checked for injection patterns: tautologies, UNION attacks, "+
				"stacked queries, comment bypasses, and more. Returns findings with severity counts.",
			toolMeta(cfg, "Scanning SQL for injection patterns…", "Scanned SQL", false),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to scan"),
			),
		),
		handleSecurityScan,
	)

	s.mcpSrv.AddTool(
		newTool("lint_sql", "Lint SQL",
			"Use this when the user wants SQL style feedback. Applies the same 10 rules as `gosqlx lint`: "+
				"L001 trailing whitespace, L002 mixed indentation, L003 consecutive blank lines, "+
				"L004 indentation depth, L005 line length (>100), L006 column alignment, L007 keyword case (upper), "+
				"L008 comma placement (trailing), L009 aliasing consistency, L010 redundant whitespace. "+
				"Returns {violation_count, violations}.",
			toolMeta(cfg, "Linting SQL…", "Linted SQL", false),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to lint"),
			),
		),
		handleLintSQL,
	)

	s.mcpSrv.AddTool(
		newTool("analyze_sql", "Analyze SQL",
			"Use this when the user wants a complete review of a SQL query. Runs validate, parse, metadata, "+
				"security, lint, and format concurrently and returns one composite report; "+
				"hosts that support MCP Apps render it as an interactive report.",
			toolMeta(cfg, "Analyzing SQL…", "Analyzed SQL", true),
			mcp.WithString("sql",
				mcp.Required(),
				mcp.Description("The SQL string to analyze"),
			),
		),
		handleAnalyzeSQL,
	)
}
