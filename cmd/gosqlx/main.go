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

package main

import (
	"fmt"
	"os"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/cmd"
)

// main is the entry point for the gosqlx CLI application.
//
// The CLI provides high-performance SQL processing capabilities including:
//   - Ultra-fast validation (<10ms for typical queries)
//   - Intelligent formatting with AST-based transformations
//   - AST structure inspection and analysis
//   - Security vulnerability detection
//   - Style and quality linting (30 rules: L001-L030)
//   - LSP server for IDE integration
//   - Configuration management
//
// Usage:
//
//	gosqlx [command] [flags] [arguments]
//
// Available commands:
//
//	validate    - Validate SQL syntax with multi-dialect support
//	format      - Format SQL with intelligent indentation
//	parse       - Parse SQL and display AST structure
//	analyze     - Analyze SQL for security and performance issues
//	lint        - Check SQL for style and quality violations
//	lsp         - Start Language Server Protocol server
//	config      - Manage configuration files
//	completion  - Generate shell autocompletion scripts
//
// Global flags:
//
//	-v, --verbose        Enable verbose output
//	-o, --output string  Output file path (default: stdout)
//	-f, --format string  Output format: json, yaml, table, tree, auto
//	--help               Display help information
//	--version            Display version information
//
// Examples:
//
//	# Validate SQL file
//	gosqlx validate query.sql
//
//	# Format SQL in-place
//	gosqlx format -i query.sql
//
//	# Analyze for security issues
//	gosqlx analyze --security query.sql
//
//	# Start LSP server
//	gosqlx lsp
//
// For detailed command help:
//
//	gosqlx [command] --help
//
// Exit codes:
//
//	0 - Success
//	1 - Error occurred (validation failed, parsing error, etc.)
//
// See package documentation for comprehensive usage information.
func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
