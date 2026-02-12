// Package cmd implements the CLI command structure for gosqlx using the Cobra framework.
//
// # Overview
//
// This package provides the implementation of all gosqlx CLI commands, including:
//   - validate: SQL syntax validation with multi-dialect support
//   - format: Intelligent SQL formatting with AST-based transformations
//   - parse: AST generation and inspection with multiple output formats
//   - analyze: Security and complexity analysis with grading
//   - lint: Style and quality checking with L001-L010 rules
//   - lsp: Language Server Protocol server for IDE integration
//   - config: Configuration file management
//   - completion: Shell autocompletion setup
//
// # Architecture
//
// The package follows a modular design with separation of concerns:
//
//	cmd/
//	├── root.go              - Root command and global flags
//	├── validate.go          - Validate command definition
//	├── validator.go         - Validation logic implementation
//	├── format.go            - Format command definition
//	├── formatter.go         - Formatting logic implementation
//	├── sql_formatter.go     - AST-based SQL formatter
//	├── parse.go             - Parse command definition
//	├── parser_cmd.go        - Parsing logic implementation
//	├── analyze.go           - Analyze command definition
//	├── analyzer.go          - Analysis orchestration
//	├── sql_analyzer.go      - AST-based analysis engine
//	├── analysis_types.go    - Analysis data structures
//	├── lint.go              - Lint command definition
//	├── lsp.go               - LSP server command
//	├── config.go            - Config management commands
//	├── config_manager.go    - Config management logic
//	├── input_utils.go       - Input detection and validation
//	├── stdin_utils.go       - Stdin handling utilities
//	└── watch.go             - File watching (future)
//
// # Command Implementation Pattern
//
// Each command follows a consistent implementation pattern:
//
//  1. Command Definition (e.g., validate.go)
//     - Cobra command structure with Use, Short, Long, RunE
//     - Flag definitions with defaults
//     - Command registration in init()
//
//  2. Logic Implementation (e.g., validator.go)
//     - Struct with options and injectable I/O writers
//     - Core logic separated from CLI concerns
//     - Proper error handling and resource cleanup
//
//  3. Configuration Integration
//     - Load from .gosqlx.yml with defaults
//     - CLI flags override config file settings
//     - Flag change tracking for proper precedence
//
// Example implementation:
//
//	// Command definition
//	var validateCmd = &cobra.Command{
//	    Use:   "validate [file...]",
//	    Short: "Ultra-fast SQL validation",
//	    RunE:  validateRun,
//	}
//
//	// Logic implementation
//	type Validator struct {
//	    Out  io.Writer
//	    Err  io.Writer
//	    Opts ValidatorOptions
//	}
//
//	func (v *Validator) Validate(args []string) (*ValidationResult, error) {
//	    // Implementation
//	}
//
// # Input Handling
//
// All commands support multiple input methods through centralized utilities:
//
//	DetectAndReadInput(input string) - Detect file vs SQL and read content
//	ShouldReadFromStdin(args) - Check if stdin should be used
//	ReadFromStdin() - Read from stdin with size limits
//	ValidateFileAccess(path) - Security validation for file paths
//
// Input security features:
//   - Path traversal prevention
//   - Symlink resolution and validation
//   - File size limits (10MB default)
//   - Binary data detection
//   - SQL injection pattern scanning
//
// # Output Handling
//
// Commands support multiple output formats through standardized interfaces:
//
//	Text Format   - Human-readable with emojis (default)
//	JSON Format   - Structured data for programmatic use
//	YAML Format   - Configuration-style output
//	SARIF Format  - Static analysis for GitHub Code Scanning
//	Table Format  - Tabular data display
//	Tree Format   - Hierarchical visualization
//
// Output utilities:
//
//	WriteOutput(content, file, writer) - Write to file or stdout
//	FormatValidationJSON() - JSON validation results
//	FormatSARIF() - SARIF 2.1.0 format
//	FormatParseJSON() - AST to JSON conversion
//
// # Configuration System
//
// Configuration is loaded from .gosqlx.yml with precedence:
//
//  1. Current directory: .gosqlx.yml
//  2. Home directory: ~/.gosqlx.yml
//  3. System: /etc/gosqlx.yml
//  4. Built-in defaults
//
// CLI flags always override configuration file settings.
//
// Flag tracking pattern:
//
//	flagsChanged := make(map[string]bool)
//	cmd.Flags().Visit(func(f *pflag.Flag) {
//	    flagsChanged[f.Name] = true
//	})
//
// This enables proper precedence between config files and CLI flags.
//
// # Error Handling
//
// Commands follow consistent error handling patterns:
//
//  1. Input validation errors - Return early with descriptive message
//  2. Processing errors - Include context and original error
//  3. Exit codes - 0 for success, 1 for failures
//  4. Resource cleanup - Always use defer for pooled objects
//
// Example:
//
//	result, err := validator.Validate(args)
//	if err != nil {
//	    return fmt.Errorf("validation failed: %w", err)
//	}
//	if result.InvalidFiles > 0 {
//	    os.Exit(1)
//	}
//
// # Memory Management
//
// All commands implement proper memory management:
//
//	// Use pooled tokenizer
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//
//	// Use pooled AST
//	astObj := ast.NewAST()
//	defer ast.ReleaseAST(astObj)
//
// Critical rules:
//   - Always defer pool returns immediately after acquisition
//   - Never return pooled objects to callers without transfer of ownership
//   - Release AST even on errors (defer handles this)
//
// # Testing
//
// Commands are designed for testability:
//
//  1. Injectable I/O writers (Out, Err) for capturing output
//  2. Separated logic (Validator, Formatter) from command definitions
//  3. Options structs for configuration
//  4. Mock-friendly interfaces
//
// Test examples:
//
//	func TestValidator(t *testing.T) {
//	    var out, errOut bytes.Buffer
//	    opts := ValidatorOptions{Quiet: true}
//	    validator := NewValidator(&out, &errOut, opts)
//	    result, err := validator.Validate([]string{"test.sql"})
//	    // Assertions
//	}
//
// # Security Considerations
//
// All commands implement defense-in-depth security:
//
//  1. Input Validation
//     - File path validation with path traversal checks
//     - Symlink resolution and validation
//     - File size limits to prevent DoS
//     - Binary data detection
//
//  2. File System Security
//     - Restricted file permissions (0600)
//     - No arbitrary file write
//     - Safe temp file handling
//     - Cleanup on errors
//
//  3. Resource Limits
//     - Maximum file size (10MB default)
//     - Stdin size limits
//     - Timeout handling
//     - Memory pooling for efficiency
//
//  4. SQL Security
//     - SQL injection pattern detection
//     - Dynamic SQL safety checks
//     - Parameterization validation
//
// # CI/CD Integration
//
// Commands are optimized for CI/CD workflows:
//
//  1. Proper Exit Codes
//     - 0: Success
//     - 1: Validation/linting failures
//
//  2. Machine-Readable Output
//     - JSON format for parsing
//     - SARIF format for GitHub Code Scanning
//     - Quiet modes for clean logs
//
//  3. Batch Processing
//     - Directory recursion with glob patterns
//     - Fast throughput (100+ files/sec)
//     - Progress reporting in verbose mode
//
//  4. Check Modes
//     - Format --check for CI validation
//     - Lint --fail-on-warn for strict checking
//     - Stats output for metrics
//
// # Performance Optimization
//
// Commands leverage the SDK's performance features:
//
//  1. Object Pooling
//     - Tokenizer pool for reuse
//     - AST pool for memory efficiency
//     - Buffer pools for I/O
//
//  2. Zero-Copy Operations
//     - Direct byte slice processing
//     - Minimal string allocations
//     - Efficient token handling
//
//  3. Concurrent Processing
//     - Race-free design
//     - Parallel file processing (future)
//     - Batch optimization
//
// Performance targets:
//   - Validation: <10ms per query
//   - Throughput: 100+ files/second
//   - Memory: 60-80% reduction with pooling
//
// # Command Reference
//
// ## validate Command
//
// Validates SQL syntax with multi-dialect support.
//
// Implementation: validator.go
// Key types: Validator, ValidatorOptions, ValidationResult
// Key functions: Validate(), validateFile(), expandFileArgs()
//
// ## format Command
//
// Formats SQL with intelligent indentation.
//
// Implementation: formatter.go, sql_formatter.go
// Key types: Formatter, CLIFormatterOptions, SQLFormatter
// Key functions: Format(), formatFile(), formatSQL()
//
// ## parse Command
//
// Generates and displays AST structure.
//
// Implementation: parser_cmd.go
// Key types: Parser, CLIParserOptions, ParserResult
// Key functions: Parse(), Display(), displayAST()
//
// ## analyze Command
//
// Analyzes SQL for security and performance.
//
// Implementation: analyzer.go, sql_analyzer.go, analysis_types.go
// Key types: Analyzer, SQLAnalyzer, AnalysisReport
// Key functions: Analyze(), DisplayReport(), scoreQuery()
//
// ## lint Command
//
// Checks SQL for style violations.
//
// Implementation: lint.go
// Key functions: lintRun(), createLinter()
// Rules: L001-L010 (see pkg/linter)
//
// ## lsp Command
//
// Starts LSP server for IDE integration.
//
// Implementation: lsp.go
// Key functions: lspRun()
// Protocol: Language Server Protocol 3.16
//
// ## config Command
//
// Manages configuration files.
//
// Implementation: config.go, config_manager.go
// Key types: ConfigManager, ConfigManagerOptions
// Key functions: Init(), Validate(), Show()
//
// # Global Variables
//
// Global flags available to all commands:
//
//	verbose    bool   - Enable verbose output
//	outputFile string - Output file path
//	format     string - Output format
//
// Version information:
//
//	Version = "1.7.0" - Current CLI version
//
// # Dependencies
//
// External dependencies:
//   - github.com/spf13/cobra - CLI framework
//   - github.com/spf13/pflag - Flag parsing
//   - gopkg.in/yaml.v3 - YAML support
//   - golang.org/x/term - Terminal detection
//
// Internal dependencies:
//   - pkg/sql/tokenizer - SQL tokenization
//   - pkg/sql/parser - SQL parsing
//   - pkg/sql/ast - AST data structures
//   - pkg/linter - SQL linting engine
//   - pkg/lsp - LSP server implementation
//   - cmd/gosqlx/internal/config - Configuration management
//   - cmd/gosqlx/internal/output - Output formatting
//   - cmd/gosqlx/internal/validate - Security validation
//
// # Examples
//
// See individual command files for detailed examples:
//   - validate.go - Validation examples
//   - format.go - Formatting examples
//   - parse.go - Parsing examples
//   - analyze.go - Analysis examples
//   - lint.go - Linting examples
//   - lsp.go - LSP integration examples
//   - config.go - Configuration examples
package cmd
