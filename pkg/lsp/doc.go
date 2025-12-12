/*
Package lsp implements a production-ready Language Server Protocol (LSP) server for GoSQLX.

The LSP server provides comprehensive SQL code intelligence features for IDEs and text editors,
enabling real-time syntax validation, intelligent auto-completion, code formatting, and
interactive documentation for SQL development.

# Overview

The GoSQLX LSP server transforms any LSP-compatible editor into a powerful SQL development
environment. It leverages the GoSQLX SQL parser to provide accurate, real-time feedback on
SQL syntax and offers intelligent code assistance through the Language Server Protocol.

Version: 1.0.0 (GoSQLX v1.6.0+)

# Features

The server implements the following LSP capabilities:

Diagnostics (textDocument/publishDiagnostics):
  - Real-time SQL syntax validation
  - Precise error location with line and column information
  - Structured error codes from GoSQLX parser
  - Immediate feedback as you type

Formatting (textDocument/formatting):
  - Intelligent SQL code formatting
  - Keyword capitalization
  - Consistent indentation (configurable tab/space)
  - Clause alignment for readability

Hover (textDocument/hover):
  - Interactive documentation for 60+ SQL keywords
  - Markdown-formatted help with syntax examples
  - Context-sensitive keyword information
  - Coverage: DML, DDL, JOINs, CTEs, Window Functions, Set Operations

Completion (textDocument/completion):
  - Auto-complete for 100+ SQL keywords
  - 22 pre-built code snippets for common patterns
  - Trigger characters: space, dot, opening parenthesis
  - Smart filtering based on current input

Document Symbol (textDocument/documentSymbol):
  - Outline view of SQL statements
  - Navigate between SELECT, INSERT, UPDATE, DELETE statements
  - Hierarchical structure for complex queries
  - Quick jump to specific statements

Signature Help (textDocument/signatureHelp):
  - Parameter hints for 20+ SQL functions
  - Active parameter highlighting
  - Documentation for each parameter
  - Coverage: Aggregates, Window Functions, String Functions, Type Conversions

Code Actions (textDocument/codeAction):
  - Quick fixes for common syntax errors
  - Automatic semicolon insertion
  - Keyword case correction suggestions
  - Context-aware refactoring hints

# Architecture

The LSP server consists of three main components:

Server (server.go):
  - Main server loop and JSON-RPC 2.0 message handling
  - Rate limiting (100 requests/second) to prevent abuse
  - Message size limits (10MB per message, 5MB per document)
  - Graceful error handling and recovery
  - Thread-safe write operations

Handler (handler.go):
  - Implementation of all LSP protocol methods
  - Request routing and response generation
  - Integration with GoSQLX parser for validation
  - Error position extraction and diagnostic creation

DocumentManager (documents.go):
  - Thread-safe document state management
  - Support for incremental document synchronization
  - Version tracking for stale diagnostic detection
  - Efficient position-to-offset conversions

Protocol (protocol.go):
  - Complete LSP protocol type definitions
  - JSON-RPC 2.0 message structures
  - Standard and LSP-specific error codes
  - All LSP 3.17 data structures

# Quick Start

Starting the LSP server from command line:

	./gosqlx lsp
	./gosqlx lsp --log /tmp/gosqlx-lsp.log  # With debug logging

Programmatic usage:

	package main

	import (
	    "log"
	    "os"
	    "github.com/ajitpratap0/GoSQLX/pkg/lsp"
	)

	func main() {
	    // Create logger that writes to file (not stdout!)
	    logFile, err := os.Create("/tmp/gosqlx-lsp.log")
	    if err != nil {
	        log.Fatal(err)
	    }
	    defer logFile.Close()

	    logger := log.New(logFile, "[GoSQLX LSP] ", log.LstdFlags)

	    // Create and run server
	    server := lsp.NewStdioServer(logger)
	    if err := server.Run(); err != nil {
	        logger.Fatalf("Server error: %v", err)
	    }
	}

# IDE Integration

The LSP server integrates with popular editors and IDEs:

VSCode:

Add to your settings.json or create a VSCode extension:

	{
	  "gosqlx-lsp": {
	    "command": "gosqlx",
	    "args": ["lsp"],
	    "filetypes": ["sql"],
	    "settings": {}
	  }
	}

Or create .vscode/settings.json:

	{
	  "sql.lsp.path": "gosqlx",
	  "sql.lsp.args": ["lsp"],
	  "sql.lsp.logLevel": "info"
	}

Neovim (nvim-lspconfig):

Add to your init.lua:

	local lspconfig = require('lspconfig')
	local configs = require('lspconfig.configs')

	if not configs.gosqlx then
	  configs.gosqlx = {
	    default_config = {
	      cmd = {'gosqlx', 'lsp'},
	      filetypes = {'sql'},
	      root_dir = lspconfig.util.root_pattern('.git', '.gosqlx.yml'),
	      settings = {},
	    },
	  }
	end

	lspconfig.gosqlx.setup{}

Or using vim.lsp.start directly:

	vim.api.nvim_create_autocmd("FileType", {
	  pattern = "sql",
	  callback = function()
	    vim.lsp.start({
	      name = "gosqlx-lsp",
	      cmd = {"gosqlx", "lsp"},
	      root_dir = vim.fn.getcwd(),
	    })
	  end,
	})

Emacs (lsp-mode):

Add to your init.el:

	(require 'lsp-mode)

	(add-to-list 'lsp-language-id-configuration '(sql-mode . "sql"))

	(lsp-register-client
	 (make-lsp-client
	  :new-connection (lsp-stdio-connection '("gosqlx" "lsp"))
	  :activation-fn (lsp-activate-on "sql")
	  :major-modes '(sql-mode)
	  :server-id 'gosqlx-lsp))

	(add-hook 'sql-mode-hook #'lsp)

Helix Editor:

Add to ~/.config/helix/languages.toml:

	[[language]]
	name = "sql"
	language-server = { command = "gosqlx", args = ["lsp"] }

Sublime Text (LSP package):

Add to LSP.sublime-settings:

	{
	  "clients": {
	    "gosqlx": {
	      "enabled": true,
	      "command": ["gosqlx", "lsp"],
	      "selector": "source.sql"
	    }
	  }
	}

# Configuration

The LSP server can be configured via .gosqlx.yml in your project root:

	# SQL dialect (postgresql, mysql, sqlite, sqlserver, oracle, generic)
	dialect: postgresql

	# Linting rules (see docs/LINTING_RULES.md)
	linter:
	  enabled: true
	  rules:
	    L001: error  # Keyword capitalization
	    L002: warn   # Indentation style
	    L003: error  # Trailing whitespace

	# Formatting options
	formatter:
	  indent_size: 2
	  indent_style: space
	  keyword_case: upper
	  max_line_length: 100

See docs/CONFIGURATION.md for complete configuration reference.

# Keyword Documentation

The LSP server provides hover documentation for these SQL keyword categories:

Core DML (Data Manipulation):

	SELECT, INSERT, UPDATE, DELETE, MERGE
	FROM, WHERE, SET, VALUES

JOINs:

	JOIN, INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL OUTER JOIN
	CROSS JOIN, NATURAL JOIN, LATERAL JOIN (PostgreSQL)
	ON, USING

Filtering and Grouping:

	WHERE, GROUP BY, HAVING, ORDER BY, LIMIT, OFFSET
	DISTINCT, DISTINCT ON (PostgreSQL)
	FETCH FIRST (SQL standard)

CTEs (Common Table Expressions):

	WITH, RECURSIVE
	Support for multiple CTEs and recursive queries

Set Operations:

	UNION, UNION ALL, EXCEPT, INTERSECT
	Proper precedence and parenthesization

Window Functions (SQL-99):

	ROW_NUMBER, RANK, DENSE_RANK, NTILE
	LAG, LEAD, FIRST_VALUE, LAST_VALUE
	OVER, PARTITION BY, ORDER BY
	ROWS BETWEEN, RANGE BETWEEN
	UNBOUNDED PRECEDING, CURRENT ROW, UNBOUNDED FOLLOWING

Aggregate Functions:

	COUNT, SUM, AVG, MIN, MAX
	FILTER clause (SQL:2003)
	ORDER BY in aggregates (PostgreSQL)

Advanced Grouping (SQL-99):

	ROLLUP, CUBE, GROUPING SETS
	Hierarchical and cross-tabulated aggregations

DDL (Data Definition):

	CREATE TABLE, CREATE INDEX, CREATE VIEW, CREATE MATERIALIZED VIEW
	ALTER TABLE, DROP TABLE, DROP INDEX
	TRUNCATE TABLE

Constraints:

	PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK
	NOT NULL, DEFAULT
	REFERENCES, CASCADE, RESTRICT

PostgreSQL Extensions:

	JSON/JSONB operators (-> ->> #> #>> @> <@ ? ?| ?& #-)
	RETURNING clause
	FILTER clause
	Array operators

Operators and Expressions:

	AND, OR, NOT
	IN, BETWEEN, LIKE, IS NULL, IS NOT NULL
	CASE WHEN THEN ELSE END
	NULLS FIRST, NULLS LAST

Functions:

	String: SUBSTRING, TRIM, UPPER, LOWER, LENGTH, CONCAT
	Conversion: CAST, CONVERT, COALESCE, NULLIF
	Date/Time: NOW, CURRENT_DATE, CURRENT_TIME, CURRENT_TIMESTAMP

# Code Snippets

The completion system includes 22 code snippets for rapid development:

Query Patterns:

	sel       - Basic SELECT statement
	selall    - SELECT * FROM table
	selcount  - SELECT COUNT(*) with WHERE
	seljoin   - SELECT with JOIN
	selleft   - SELECT with LEFT JOIN
	selgroup  - SELECT with GROUP BY and HAVING

DML Operations:

	ins       - INSERT INTO with VALUES
	inssel    - INSERT INTO with SELECT
	upd       - UPDATE with SET and WHERE
	del       - DELETE FROM with WHERE

DDL Operations:

	cretbl    - CREATE TABLE with columns
	creidx    - CREATE INDEX
	altertbl  - ALTER TABLE ADD COLUMN
	droptbl   - DROP TABLE IF EXISTS
	trunc     - TRUNCATE TABLE

Advanced Features:

	cte       - Common Table Expression (WITH)
	cterec    - Recursive CTE
	case      - CASE expression
	casecol   - CASE on column value
	window    - Window function with PARTITION BY
	merge     - MERGE statement with MATCHED clauses
	union     - UNION query
	exists    - EXISTS subquery
	subq      - Subquery template

Each snippet uses placeholder variables (${1}, ${2}, etc.) for easy tab navigation.

# Function Signatures

Signature help is provided for these SQL function categories:

Aggregate Functions:

	COUNT(expression)           - Count rows matching criteria
	SUM(expression)             - Sum numeric values
	AVG(expression)             - Calculate average
	MIN(expression)             - Find minimum value
	MAX(expression)             - Find maximum value

Window Functions:

	ROW_NUMBER() OVER (...)     - Sequential row numbers
	RANK() OVER (...)           - Ranks with gaps for ties
	DENSE_RANK() OVER (...)     - Ranks without gaps
	NTILE(buckets) OVER (...)   - Divide into N groups
	LAG(expr, offset, default)  - Access previous row
	LEAD(expr, offset, default) - Access next row
	FIRST_VALUE(expr) OVER(...) - First value in window
	LAST_VALUE(expr) OVER(...)  - Last value in window

String Functions:

	SUBSTRING(string, start, length) - Extract substring
	TRIM([spec] chars FROM string)   - Remove leading/trailing chars
	UPPER(string)                    - Convert to uppercase
	LOWER(string)                    - Convert to lowercase
	LENGTH(string)                   - String length
	CONCAT(str1, str2, ...)         - Concatenate strings

Null Handling:

	COALESCE(val1, val2, ...)       - First non-null value
	NULLIF(expr1, expr2)             - NULL if equal, else expr1

Type Conversion:

	CAST(expression AS type)         - Type conversion

# Performance and Limits

The LSP server includes built-in safeguards for stability:

Rate Limiting:
  - 100 requests per second maximum (RateLimitRequests)
  - 1-second rolling window (RateLimitWindow)
  - Automatic recovery after window expires
  - Client receives RequestCancelled (-32800) when exceeded

Message Size Limits:
  - MaxContentLength: 10MB per JSON-RPC message
  - MaxDocumentSize: 5MB per SQL document
  - Oversized documents skip validation with warning
  - Documents remain open but diagnostics disabled

Request Timeout:
  - 30 seconds per request (RequestTimeout)
  - Prevents hanging on malformed SQL
  - Long-running parses automatically cancelled

Memory Management:
  - GoSQLX object pooling for parser efficiency
  - Document content copied to prevent races
  - Automatic cleanup on document close

Performance Characteristics:
  - Parsing: <1ms for typical queries, <10ms for complex CTEs
  - Completion: <5ms for 100+ items with filtering
  - Formatting: <10ms for documents up to 1000 lines
  - Hover: <1ms for keyword lookup
  - Validation: <50ms for complex multi-statement documents

# Error Handling

The server provides robust error handling throughout:

Position Extraction:
  - Structured errors from GoSQLX with line/column info
  - Regex fallback for unstructured error messages
  - Multiple patterns: "line X, column Y", "[X:Y]", "position N"
  - Conversion from absolute position to line/column

Error Codes:
  - JSON-RPC standard codes (-32700 to -32603)
  - LSP-specific codes (-32002, -32800 to -32803)
  - GoSQLX error codes propagated to diagnostics
  - Categorized by severity (Error, Warning, Info, Hint)

Diagnostic Features:
  - Precise error ranges for IDE underlining
  - Error code display in hover
  - Related information for multi-location errors
  - Automatic clearing on document close

Graceful Degradation:
  - Parse errors don't crash server
  - Malformed requests handled with error responses
  - Unknown methods return MethodNotFound
  - Oversized documents skip validation

# Thread Safety

All components are designed for safe concurrent operation:

Server Level:
  - Write mutex for JSON-RPC output serialization
  - Rate limiting mutex for request counting
  - Atomic operations for rate limit counter

Document Manager:
  - Read/write mutex for document map
  - Read locks for Get/GetContent (concurrent reads)
  - Write locks for Open/Update/Close (exclusive writes)
  - Document copies returned to prevent races

Handler:
  - Stateless request processing
  - No shared mutable state
  - Keywords instance is read-only after construction
  - Safe for concurrent request handling

# Logging and Debugging

The server supports comprehensive logging for debugging:

Log Levels:
  - Startup/Shutdown events
  - Received requests with method names
  - Sent responses with byte counts
  - Parse errors with content snippets
  - Rate limit violations
  - Document lifecycle events
  - Validation results (diagnostic counts)

Log Configuration:
  - Logger must write to file or stderr (never stdout)
  - Stdout is reserved for LSP protocol communication
  - Use --log flag with gosqlx CLI for file logging
  - Nil logger disables all logging (production use)

Example logging setup:

	logFile, _ := os.Create("/tmp/gosqlx-lsp.log")
	logger := log.New(logFile, "[LSP] ", log.LstdFlags|log.Lshortfile)
	server := lsp.NewStdioServer(logger)

# Protocol Compliance

The implementation conforms to LSP 3.17 specification:

Lifecycle:
  - initialize → initialize result with capabilities
  - initialized notification
  - shutdown request
  - exit notification

Text Synchronization:
  - Full and incremental sync modes
  - Version tracking
  - Open/Change/Close/Save notifications

Diagnostics:
  - publishDiagnostics notification
  - Version-tagged diagnostics
  - Multiple diagnostics per document
  - Automatic clearing on close

Code Intelligence:
  - hover request/response
  - completion request/response
  - formatting request/response
  - documentSymbol request/response
  - signatureHelp request/response
  - codeAction request/response

Error Handling:
  - Standard JSON-RPC 2.0 error responses
  - Error codes per specification
  - Detailed error messages
  - Error data field for additional context

# Testing

The LSP implementation includes comprehensive tests:

Unit Tests:
  - Protocol message parsing
  - Document state management
  - Position/offset conversions
  - Error extraction patterns

Integration Tests:
  - Full request/response cycles
  - Multi-document scenarios
  - Concurrent request handling
  - Rate limiting behavior

Benchmark Tests:
  - Handler performance under load
  - Document update performance
  - Completion latency
  - Parse and validation speed

See pkg/lsp/*_test.go for test suite details.

# Related Documentation

For more information about the LSP server and GoSQLX features:

  - docs/LSP_GUIDE.md - Complete LSP server setup and IDE integration guide
  - docs/LINTING_RULES.md - All linting rules (L001-L010) reference
  - docs/CONFIGURATION.md - Configuration file (.gosqlx.yml) documentation
  - docs/USAGE_GUIDE.md - Comprehensive GoSQLX usage guide
  - docs/SQL_COMPATIBILITY.md - SQL dialect compatibility matrix

# Standards and References

Language Server Protocol:

	https://microsoft.github.io/language-server-protocol/

JSON-RPC 2.0 Specification:

	https://www.jsonrpc.org/specification

SQL Standards:
  - SQL-92 (ISO/IEC 9075:1992)
  - SQL-99 (ISO/IEC 9075:1999) - Window functions, CTEs
  - SQL:2003 (ISO/IEC 9075:2003) - MERGE, XML
  - SQL:2011 (ISO/IEC 9075:2011) - Temporal features

GoSQLX Project:

	https://github.com/ajitpratap0/GoSQLX
*/
package lsp
