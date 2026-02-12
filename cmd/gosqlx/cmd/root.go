package cmd

import (
	"github.com/spf13/cobra"
)

// Version is the current version of gosqlx CLI.
//
// This version tracks feature releases and compatibility.
// Format: MAJOR.MINOR.PATCH (Semantic Versioning 2.0.0)
//
// Version 1.7.0 includes:
//   - Schema-qualified table names (schema.table, db.schema.table)
//   - PostgreSQL :: type casting operator
//   - ARRAY constructor expressions
//   - WITHIN GROUP clause for ordered-set aggregates
//   - JSONB operators (@?, @@)
//   - Regex operators (~, ~*, !~, !~*)
//   - INTERVAL expressions
//   - FETCH FIRST/NEXT with OFFSET
//   - FOR UPDATE/SHARE locking clauses
//   - Multi-row INSERT VALUES
//   - PostgreSQL UPSERT (ON CONFLICT)
//   - Positional parameters ($1, $2)
//   - Array subscript and slice operations
var Version = "1.7.0"

var (
	// verbose enables detailed output for debugging and troubleshooting.
	// When enabled, commands display additional information about processing,
	// including file paths, intermediate steps, and performance metrics.
	//
	// Usage:
	//   gosqlx validate -v query.sql
	//   gosqlx format --verbose -i query.sql
	verbose bool

	// outputFile specifies the destination for command output.
	// When not specified (empty string), output is written to stdout.
	// File output uses 0600 permissions (owner read/write only) for security.
	//
	// Usage:
	//   gosqlx validate -o results.txt query.sql
	//   gosqlx analyze --output analysis.json query.sql
	outputFile string

	// format specifies the output format for commands that support multiple formats.
	// Supported formats:
	//   - auto: Automatic format selection based on context (default)
	//   - json: JSON format for programmatic consumption
	//   - yaml: YAML format for configuration-style output
	//   - table: Tabular format for structured data display
	//   - tree: Tree visualization for hierarchical data
	//   - text: Human-readable text format
	//
	// Usage:
	//   gosqlx parse -f json query.sql
	//   gosqlx analyze --format yaml query.sql
	format string
)

// rootCmd represents the base command when called without any subcommands.
//
// The root command provides the entry point to all gosqlx functionality.
// When called without subcommands, it displays help information.
//
// Subcommands:
//   - validate: Ultra-fast SQL validation (<10ms for typical queries)
//   - format: Intelligent SQL formatting with AST-based transformations
//   - parse: AST structure inspection with multiple output formats
//   - analyze: Security and complexity analysis with grading
//   - lint: Style and quality checking with L001-L010 rules
//   - lsp: Language Server Protocol server for IDE integration
//   - config: Configuration file management
//   - completion: Shell autocompletion setup
//
// Global flags apply to all subcommands:
//
//	-v, --verbose        Enable verbose output
//	-o, --output string  Output file path (default: stdout)
//	-f, --format string  Output format: json, yaml, table, tree, auto
//
// Examples:
//
//	# Display help
//	gosqlx --help
//
//	# Display version
//	gosqlx --version
//
//	# Run command with verbose output
//	gosqlx validate -v query.sql
//
//	# Run command with JSON output to file
//	gosqlx analyze -f json -o report.json query.sql
var rootCmd = &cobra.Command{
	Use:   "gosqlx",
	Short: "High-performance SQL parsing and analysis tool",
	Long: `GoSQLX CLI - The fastest SQL parser and analyzer

GoSQLX provides ultra-fast SQL parsing, validation, formatting, and analysis
with 100x better performance than existing tools like SQLFluff.

Key features:
• Ultra-fast validation (<10ms for typical queries)
• High-performance formatting with intelligent indentation
• AST structure inspection and analysis
• Security vulnerability detection
• Multi-dialect SQL support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
• Batch processing with directory/glob patterns
• CI/CD integration with proper exit codes

Performance: 1.38M+ operations/second, 100-1000x faster than competitors.`,
	Version: "1.7.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
//
// This function is called by main.main() and only needs to be called once.
// It executes the root command, which will dispatch to the appropriate subcommand
// based on the provided arguments.
//
// The function handles:
//   - Command-line argument parsing
//   - Flag validation and processing
//   - Command dispatch and execution
//   - Error propagation to main
//
// Returns:
//   - nil on successful command execution
//   - error if command execution fails or arguments are invalid
//
// Example:
//
//	func main() {
//	    if err := cmd.Execute(); err != nil {
//	        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
//	        os.Exit(1)
//	    }
//	}
func Execute() error {
	return rootCmd.Execute()
}

// init initializes the root command and registers global flags.
//
// This function is called automatically during package initialization.
// It sets up persistent flags that are inherited by all subcommands.
//
// Global flags:
//   - verbose (-v, --verbose): Enable detailed output for debugging
//   - outputFile (-o, --output): Specify output file path
//   - format (-f, --format): Set output format (json, yaml, table, tree, auto)
//
// Persistent flags are available to the command and all its children,
// enabling consistent behavior across all subcommands.
func init() {
	// Global flags available to all subcommands
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "auto", "output format: json, yaml, table, tree, auto")
}
