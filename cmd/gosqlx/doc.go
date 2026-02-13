// Package main provides the gosqlx command-line interface for high-performance SQL parsing,
// validation, formatting, and analysis.
//
// # Overview
//
// GoSQLX CLI is a production-ready, ultra-fast SQL toolkit that provides comprehensive SQL
// processing capabilities with performance that is 100-1000x faster than traditional tools
// like SQLFluff. Built on the GoSQLX SDK, it offers enterprise-grade features for SQL
// development, code quality enforcement, and CI/CD integration.
//
// # Version
//
// Current version: 1.7.0
//
// # Architecture
//
// The CLI is built using the Cobra framework and follows a modular command structure:
//
//	gosqlx
//	├── validate    - SQL syntax validation with multi-dialect support
//	├── format      - Intelligent SQL formatting with customizable rules
//	├── parse       - AST generation and inspection
//	├── analyze     - Security and complexity analysis
//	├── lint        - Style and quality checking (L001-L010 rules)
//	├── lsp         - Language Server Protocol for IDE integration
//	├── config      - Configuration file management
//	└── completion  - Shell autocompletion setup
//
// # Core Features
//
//   - Ultra-fast SQL validation (<10ms for typical queries)
//   - Multi-dialect support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
//   - Intelligent formatting with AST-based transformations
//   - Security vulnerability detection (SQL injection patterns)
//   - Complexity scoring and performance analysis
//   - Linting with 10 built-in rules (L001-L010)
//   - LSP server for real-time IDE integration
//   - Configuration file support (.gosqlx.yml)
//   - Multiple output formats (JSON, YAML, SARIF, text)
//   - CI/CD integration with proper exit codes
//   - Batch processing with directory/glob support
//   - Stdin/stdout pipeline support
//
// # Installation
//
// Install via go install:
//
//	go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
//
// Or build from source:
//
//	git clone https://github.com/ajitpratap0/GoSQLX.git
//	cd GoSQLX
//	task build:cli
//	sudo cp build/gosqlx /usr/local/bin/
//
// # Quick Start
//
// Validate a SQL file:
//
//	gosqlx validate query.sql
//
// Format SQL with intelligent indentation:
//
//	gosqlx format -i query.sql
//
// Parse and inspect AST structure:
//
//	gosqlx parse -f json query.sql
//
// Analyze for security and performance:
//
//	gosqlx analyze --security --performance query.sql
//
// Lint SQL files for style issues:
//
//	gosqlx lint --auto-fix query.sql
//
// Start LSP server for IDE integration:
//
//	gosqlx lsp
//
// # Commands
//
// ## validate - SQL Syntax Validation
//
// Ultra-fast validation with multi-dialect support and batch processing.
//
//	gosqlx validate [file...]
//	gosqlx validate query.sql                              # Single file
//	gosqlx validate query1.sql query2.sql                  # Multiple files
//	gosqlx validate -r ./queries/                          # Recursive directory
//	gosqlx validate --dialect postgresql query.sql         # Specific dialect
//	gosqlx validate --output-format sarif -o results.sarif # SARIF for GitHub
//	echo "SELECT * FROM users" | gosqlx validate           # Stdin input
//
// Flags:
//
//	-r, --recursive           Recursively process directories
//	-p, --pattern string      File pattern for recursive processing (default "*.sql")
//	-q, --quiet               Quiet mode (exit code only)
//	-s, --stats               Show performance statistics
//	--dialect string          SQL dialect: postgresql, mysql, sqlserver, oracle, sqlite
//	--strict                  Enable strict validation mode
//	--output-format string    Output format: text, json, sarif (default "text")
//	--output-file string      Output file path (default: stdout)
//
// Exit codes:
//
//	0 - All files valid
//	1 - One or more files invalid
//
// ## format - SQL Formatting
//
// High-performance formatting with intelligent indentation and AST-based transformations.
//
//	gosqlx format [file...]
//	gosqlx format query.sql                    # Format to stdout
//	gosqlx format -i query.sql                 # Format in-place
//	gosqlx format --indent 4 query.sql         # Custom indentation
//	gosqlx format --no-uppercase query.sql     # Keep original keyword case
//	gosqlx format --compact query.sql          # Minimal whitespace
//	gosqlx format --check query.sql            # Check if formatting needed (CI)
//	cat query.sql | gosqlx format              # Stdin input
//
// Flags:
//
//	-i, --in-place            Edit files in place
//	--indent int              Indentation size in spaces (default 2)
//	--uppercase               Uppercase SQL keywords (default true)
//	--no-uppercase            Keep original keyword case
//	--compact                 Compact format (minimal whitespace)
//	--check                   Check if files need formatting (CI mode)
//	--max-line int            Maximum line length (default 80)
//
// ## parse - AST Inspection
//
// Parse SQL and display Abstract Syntax Tree structure in various formats.
//
//	gosqlx parse [file|query]
//	gosqlx parse query.sql                     # Show AST structure
//	gosqlx parse --ast query.sql               # Detailed AST
//	gosqlx parse --tokens query.sql            # Tokenization output
//	gosqlx parse --tree query.sql              # Tree visualization
//	gosqlx parse -f json query.sql             # JSON format
//	gosqlx parse "SELECT * FROM users"         # Direct SQL
//	echo "SELECT 1" | gosqlx parse             # Stdin input
//
// Flags:
//
//	--ast             Show detailed AST structure
//	--tokens          Show tokenization output
//	--tree            Show tree visualization
//	-f, --format      Output format: json, yaml, table, tree (default "auto")
//
// ## analyze - SQL Analysis
//
// Advanced analysis for security vulnerabilities, performance issues, and complexity metrics.
//
//	gosqlx analyze [file|query]
//	gosqlx analyze query.sql                   # Basic analysis
//	gosqlx analyze --security query.sql        # Security scan
//	gosqlx analyze --performance query.sql     # Performance analysis
//	gosqlx analyze --complexity query.sql      # Complexity metrics
//	gosqlx analyze --all query.sql             # Comprehensive analysis
//	gosqlx analyze -f json query.sql           # JSON output
//	cat query.sql | gosqlx analyze             # Stdin input
//
// Flags:
//
//	--security        Focus on security vulnerability analysis
//	--performance     Focus on performance optimization analysis
//	--complexity      Focus on complexity metrics
//	--all             Comprehensive analysis
//	-f, --format      Output format: json, yaml, table (default "auto")
//
// Analysis includes:
//   - SQL injection pattern detection
//   - Performance anti-patterns (N+1 queries, missing indexes, SELECT *)
//   - Complexity scoring (JOINs, nesting depth, function calls)
//   - Best practices validation
//   - Security grading (A-F scale)
//
// ## lint - Style and Quality Checking
//
// Check SQL code for style and quality issues with auto-fix support.
//
//	gosqlx lint [file...]
//	gosqlx lint query.sql                      # Lint single file
//	gosqlx lint -r ./queries/                  # Recursive directory
//	gosqlx lint --auto-fix query.sql           # Auto-fix violations
//	gosqlx lint --max-length 120 query.sql     # Custom line length
//	gosqlx lint --fail-on-warn query.sql       # Fail on warnings
//	cat query.sql | gosqlx lint                # Stdin input
//
// Linting rules (L001-L010):
//
//	L001 - Trailing whitespace at end of lines
//	L002 - Mixed tabs and spaces for indentation
//	L003 - Consecutive blank lines
//	L004 - Indentation depth (excessive nesting)
//	L005 - Lines exceeding maximum length
//	L006 - SELECT column alignment
//	L007 - Keyword case consistency (uppercase/lowercase)
//	L008 - Comma placement (trailing vs leading)
//	L009 - Aliasing consistency (table aliases)
//	L010 - Redundant whitespace (multiple spaces)
//
// Flags:
//
//	-r, --recursive           Recursively process directories
//	-p, --pattern string      File pattern for recursive processing (default "*.sql")
//	--auto-fix                Automatically fix violations where possible
//	--max-length int          Maximum line length for L005 rule (default 100)
//	--fail-on-warn            Exit with error code on warnings
//
// Exit codes:
//
//	0 - No violations found
//	1 - Errors or warnings found (warnings only if --fail-on-warn)
//
// ## lsp - Language Server Protocol
//
// Start the LSP server for real-time IDE integration with diagnostics, hover, completion, and formatting.
//
//	gosqlx lsp
//	gosqlx lsp --log /tmp/lsp.log              # Enable debug logging
//
// Features:
//   - Real-time syntax error detection with diagnostics
//   - SQL keyword and function completion
//   - Hover documentation for keywords
//   - Document formatting on save
//   - Multi-file workspace support
//
// IDE Integration examples:
//
// VSCode (.vscode/settings.json):
//
//	{
//	  "gosqlx.lsp.enable": true,
//	  "gosqlx.lsp.path": "gosqlx"
//	}
//
// Neovim (lua config):
//
//	require('lspconfig.configs').gosqlx = {
//	  default_config = {
//	    cmd = { 'gosqlx', 'lsp' },
//	    filetypes = { 'sql' },
//	    root_dir = function() return vim.fn.getcwd() end,
//	  },
//	}
//	require('lspconfig').gosqlx.setup{}
//
// Emacs (lsp-mode):
//
//	(lsp-register-client
//	  (make-lsp-client
//	    :new-connection (lsp-stdio-connection '("gosqlx" "lsp"))
//	    :major-modes '(sql-mode)
//	    :server-id 'gosqlx))
//
// Flags:
//
//	--log string      Log file path for debugging (default: no logging)
//
// ## config - Configuration Management
//
// Manage GoSQLX configuration files (.gosqlx.yml) with validation and display.
//
//	gosqlx config init                         # Create default config
//	gosqlx config init --path ~/.gosqlx.yml    # Create in home directory
//	gosqlx config validate                     # Validate current config
//	gosqlx config validate --file config.yml   # Validate specific file
//	gosqlx config show                         # Show current config
//	gosqlx config show --format json           # Show as JSON
//
// Configuration file locations (searched in order):
//  1. Current directory: .gosqlx.yml
//  2. Home directory: ~/.gosqlx.yml
//  3. System: /etc/gosqlx.yml
//
// Configuration file format (.gosqlx.yml):
//
//	format:
//	  indent: 2
//	  uppercase_keywords: true
//	  max_line_length: 80
//	  compact: false
//
//	validate:
//	  dialect: postgresql
//	  strict_mode: false
//	  recursive: false
//	  pattern: "*.sql"
//	  security:
//	    max_file_size: 10485760  # 10MB
//
//	output:
//	  format: auto
//	  verbose: false
//
//	analyze:
//	  security: true
//	  performance: true
//	  complexity: true
//	  all: false
//
// CLI flags always override configuration file settings.
//
// # Input Handling
//
// The CLI supports multiple input methods with automatic detection:
//
// ## File Input
//
// Direct file paths:
//
//	gosqlx validate query.sql
//	gosqlx format /path/to/queries/complex.sql
//
// ## Directory Input
//
// Recursive directory processing with pattern matching:
//
//	gosqlx validate -r ./queries/
//	gosqlx validate -r ./queries/ --pattern "*.sql"
//	gosqlx lint -r . --pattern "migration_*.sql"
//
// ## Glob Patterns
//
// Shell glob patterns for batch processing:
//
//	gosqlx validate "queries/*.sql"
//	gosqlx format "tests/**/*.sql"
//
// ## Direct SQL Input
//
// SQL queries as command arguments:
//
//	gosqlx validate "SELECT * FROM users WHERE id = 1"
//	gosqlx parse "SELECT COUNT(*) FROM orders"
//
// ## Stdin Input
//
// Pipeline input with automatic detection:
//
//	echo "SELECT * FROM users" | gosqlx validate
//	cat query.sql | gosqlx format
//	gosqlx validate -                          # Explicit stdin marker
//	gosqlx format < query.sql                  # Input redirection
//
// Stdin input is automatically detected when:
//   - No arguments provided and stdin is piped
//   - Explicit "-" argument is used
//   - Input redirection is used
//
// # Output Formats
//
// The CLI supports multiple output formats for different use cases:
//
// ## Text Format (default)
//
// Human-readable output with emojis and color (when supported):
//
//	✅ query.sql: Valid SQL
//	❌ broken.sql: parsing failed: unexpected token
//
// ## JSON Format
//
// Structured output for programmatic consumption:
//
//	gosqlx validate --output-format json query.sql
//	gosqlx parse -f json query.sql
//	gosqlx analyze -f json query.sql
//
// ## YAML Format
//
// YAML output for configuration-style consumption:
//
//	gosqlx parse -f yaml query.sql
//	gosqlx config show --format yaml
//
// ## SARIF Format
//
// Static Analysis Results Interchange Format (SARIF 2.1.0) for GitHub Code Scanning:
//
//	gosqlx validate --output-format sarif --output-file results.sarif ./queries/
//
// GitHub Actions integration:
//
//   - name: Validate SQL
//     run: gosqlx validate --output-format sarif --output-file results.sarif ./sql/
//   - name: Upload SARIF
//     uses: github/codeql-action/upload-sarif@v2
//     with:
//     sarif_file: results.sarif
//
// ## Table Format
//
// Tabular output for structured data:
//
//	gosqlx parse --tokens -f table query.sql
//
// ## Tree Format
//
// Tree visualization for AST structure:
//
//	gosqlx parse --tree query.sql
//
// # Security Features
//
// The CLI implements comprehensive security measures:
//
// ## Input Validation
//
//   - File path validation with path traversal prevention
//   - Symlink resolution and validation
//   - File size limits (default: 10MB, configurable)
//   - Binary data detection in stdin input
//   - SQL injection pattern detection in queries
//
// ## File System Security
//
//   - Restricted file permissions (0600 for output files)
//   - No arbitrary file write outside working directory
//   - Safe temp file handling with cleanup
//
// ## DoS Prevention
//
//   - Maximum file size enforcement
//   - Stdin size limits (10MB default)
//   - Timeout handling for long operations
//   - Resource cleanup with defer patterns
//
// ## Vulnerability Scanning
//
// The analyze command detects common SQL vulnerabilities:
//
//   - SQL injection patterns (UNION attacks, comment injections)
//   - Unsafe dynamic SQL construction
//   - Missing parameterization
//   - Exposed error messages
//   - Privilege escalation risks
//
// # CI/CD Integration
//
// The CLI is designed for CI/CD workflows with proper exit codes and formats.
//
// ## Exit Codes
//
// All commands follow consistent exit code conventions:
//
//	0 - Success (all validations passed)
//	1 - Failure (validation errors, linting violations, etc.)
//
// ## GitHub Actions
//
// Example workflow for SQL validation:
//
//	name: SQL Validation
//	on: [push, pull_request]
//	jobs:
//	  validate:
//	    runs-on: ubuntu-latest
//	    steps:
//	      - uses: actions/checkout@v3
//	      - name: Install GoSQLX
//	        run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
//	      - name: Validate SQL files
//	        run: gosqlx validate -r ./sql/
//	      - name: Check SQL formatting
//	        run: gosqlx format --check ./sql/*.sql
//	      - name: Lint SQL files
//	        run: gosqlx lint -r ./sql/
//	      - name: Security scan
//	        run: gosqlx analyze --security ./sql/*.sql
//
// ## GitLab CI
//
// Example .gitlab-ci.yml:
//
//	sql-validation:
//	  image: golang:1.24
//	  script:
//	    - go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
//	    - gosqlx validate -r ./sql/
//	    - gosqlx format --check ./sql/*.sql
//	    - gosqlx lint -r ./sql/
//
// ## Pre-commit Hooks
//
// Example .pre-commit-config.yaml:
//
//	repos:
//	  - repo: local
//	    hooks:
//	      - id: gosqlx-validate
//	        name: Validate SQL
//	        entry: gosqlx validate
//	        language: system
//	        files: \.sql$
//	      - id: gosqlx-format
//	        name: Format SQL
//	        entry: gosqlx format --check
//	        language: system
//	        files: \.sql$
//	      - id: gosqlx-lint
//	        name: Lint SQL
//	        entry: gosqlx lint
//	        language: system
//	        files: \.sql$
//
// # Performance
//
// GoSQLX CLI delivers exceptional performance:
//
//   - Validation: <10ms for typical queries (50-500 characters)
//   - Throughput: 100+ files/second in batch mode
//   - Memory: Efficient with object pooling (60-80% reduction)
//   - Concurrency: Race-free design validated with 20,000+ concurrent operations
//
// Performance comparison vs SQLFluff:
//   - Validation: 100x faster
//   - Formatting: 100x faster
//   - Batch processing: 1000x faster (large codebases)
//
// # Global Flags
//
// These flags are available for all commands:
//
//	-v, --verbose        Enable verbose output
//	-o, --output string  Output file path (default: stdout)
//	-f, --format string  Output format: json, yaml, table, tree, auto (default "auto")
//
// # Examples
//
// ## Basic Validation
//
//	# Validate a single file
//	gosqlx validate query.sql
//
//	# Validate multiple files
//	gosqlx validate query1.sql query2.sql query3.sql
//
//	# Validate all SQL files in directory
//	gosqlx validate -r ./queries/
//
//	# Validate with specific dialect
//	gosqlx validate --dialect postgresql migrations/*.sql
//
// ## Formatting
//
//	# Format to stdout
//	gosqlx format query.sql
//
//	# Format in-place
//	gosqlx format -i query.sql
//
//	# Format with custom indentation
//	gosqlx format --indent 4 -i query.sql
//
//	# Check if formatting is needed (CI)
//	gosqlx format --check query.sql
//
// ## Analysis
//
//	# Comprehensive analysis
//	gosqlx analyze --all query.sql
//
//	# Security-focused analysis
//	gosqlx analyze --security ./queries/*.sql
//
//	# JSON output for tooling
//	gosqlx analyze --all -f json query.sql > analysis.json
//
// ## Linting
//
//	# Lint and auto-fix
//	gosqlx lint --auto-fix query.sql
//
//	# Lint entire project
//	gosqlx lint -r ./sql/
//
//	# Custom line length limit
//	gosqlx lint --max-length 120 query.sql
//
// ## Pipeline Usage
//
//	# Validate from stdin
//	cat query.sql | gosqlx validate
//
//	# Format pipeline
//	cat ugly.sql | gosqlx format > pretty.sql
//
//	# Complex pipeline
//	find ./queries -name "*.sql" -exec cat {} \; | gosqlx validate
//
// # Troubleshooting
//
// ## Common Issues
//
// Problem: "file access validation failed"
// Solution: Check file permissions and path traversal restrictions
//
// Problem: "stdin input too large"
// Solution: Input exceeds 10MB limit - use file input instead
//
// Problem: "parsing failed: unexpected token"
// Solution: SQL may use dialect-specific syntax - specify --dialect flag
//
// ## Debug Mode
//
// Enable verbose output for debugging:
//
//	gosqlx validate -v query.sql
//	gosqlx lsp --log /tmp/lsp-debug.log
//
// ## Getting Help
//
// Display help for any command:
//
//	gosqlx --help
//	gosqlx validate --help
//	gosqlx format --help
//
// # Documentation
//
// Full documentation available at:
//   - Getting Started: docs/GETTING_STARTED.md
//   - Usage Guide: docs/USAGE_GUIDE.md
//   - LSP Integration: docs/LSP_GUIDE.md
//   - Linting Rules: docs/LINTING_RULES.md
//   - Configuration: docs/CONFIGURATION.md
//   - SQL Compatibility: docs/SQL_COMPATIBILITY.md
//
// # License
//
// GoSQLX is released under the Apache License, Version 2.0.
// See LICENSE file for details.
//
// # Contributing
//
// Contributions are welcome! Please see CONTRIBUTING.md for guidelines.
//
// # Support
//
// For issues and feature requests:
//   - GitHub: https://github.com/ajitpratap0/GoSQLX/issues
//   - Documentation: https://github.com/ajitpratap0/GoSQLX/tree/main/docs
package main
