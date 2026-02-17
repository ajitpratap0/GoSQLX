package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/output"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// ValidatorOptions contains configuration for the SQL validator.
//
// Controls validation behavior including recursion, output modes, and dialect.
//
// Fields:
//   - Recursive: Process directories recursively
//   - Pattern: File pattern for recursive processing (default: "*.sql")
//   - Quiet: Suppress output (exit code only)
//   - ShowStats: Display performance statistics
//   - Dialect: SQL dialect for validation (postgresql, mysql, etc.)
//   - StrictMode: Enable strict validation rules
//   - Verbose: Enable verbose output with debugging information
type ValidatorOptions struct {
	Recursive  bool
	Pattern    string
	Quiet      bool
	ShowStats  bool
	Dialect    string
	StrictMode bool
	Verbose    bool
}

// Validator provides SQL validation functionality with injectable output.
//
// The Validator is designed for testability with injectable I/O writers
// and separated validation logic from command-line concerns.
//
// Fields:
//   - Out: Output writer for success messages (default: os.Stdout)
//   - Err: Error writer for error messages (default: os.Stderr)
//   - Opts: Validation options and configuration
//
// Thread Safety:
//
//	Validator instances are not thread-safe. Create separate instances
//	for concurrent validation or use appropriate synchronization.
//
// Example:
//
//	validator := NewValidator(os.Stdout, os.Stderr, ValidatorOptions{
//	    Recursive: true,
//	    Pattern:   "*.sql",
//	    ShowStats: true,
//	})
//	result, err := validator.Validate([]string{"./queries"})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.InvalidFiles > 0 {
//	    os.Exit(1)
//	}
type Validator struct {
	Out  io.Writer
	Err  io.Writer
	Opts ValidatorOptions
}

// NewValidator creates a new Validator with the given options.
//
// Constructs a Validator instance with specified I/O writers and options.
// This is the primary way to create a Validator for both CLI and programmatic use.
//
// Parameters:
//   - out: Output writer for success messages and results
//   - err: Error writer for error messages and diagnostics
//   - opts: Validation options controlling behavior
//
// Returns:
//   - *Validator ready for validation operations
//
// Example:
//
//	// CLI usage
//	validator := NewValidator(os.Stdout, os.Stderr, opts)
//
//	// Testing usage with buffers
//	var outBuf, errBuf bytes.Buffer
//	validator := NewValidator(&outBuf, &errBuf, ValidatorOptions{Quiet: true})
//	result, _ := validator.Validate([]string{"test.sql"})
//	assert.Equal(t, 1, result.ValidFiles)
//
// NewValidator creates a new Validator with the given options
func NewValidator(out, err io.Writer, opts ValidatorOptions) *Validator {
	return &Validator{
		Out:  out,
		Err:  err,
		Opts: opts,
	}
}

// Validate validates the given SQL files or patterns.
//
// This is the main validation entry point that processes file arguments,
// expands patterns, and validates each file using the GoSQLX parser.
//
// The method:
//  1. Expands file arguments (globs, directories, individual files)
//  2. Validates each file using tokenizer and parser
//  3. Collects results and statistics
//  4. Outputs progress and errors (unless quiet mode)
//  5. Returns comprehensive validation results
//
// Parameters:
//   - args: Array of file paths, glob patterns, or directory paths
//
// Returns:
//   - *ValidationResult: Comprehensive validation results
//   - error: If argument expansion fails or no files found
//
// The returned ValidationResult contains:
//   - TotalFiles, ValidFiles, InvalidFiles counts
//   - Individual file results with errors
//   - Performance statistics (duration, throughput)
//
// Exit code handling (caller responsibility):
//   - 0 if all files valid (InvalidFiles == 0)
//   - 1 if any files invalid (InvalidFiles > 0)
//
// Example:
//
//	validator := NewValidator(os.Stdout, os.Stderr, ValidatorOptions{
//	    ShowStats: true,
//	})
//	result, err := validator.Validate([]string{"queries/*.sql", "migrations/"})
//	if err != nil {
//	    log.Fatalf("Validation failed: %v", err)
//	}
//	if result.InvalidFiles > 0 {
//	    fmt.Fprintf(os.Stderr, "Found %d invalid files\n", result.InvalidFiles)
//	    os.Exit(1)
//	}
//
// Validate validates the given SQL files or patterns
func (v *Validator) Validate(args []string) (*output.ValidationResult, error) {
	startTime := time.Now()

	// Expand file arguments (glob patterns, directories, etc.)
	files, err := v.expandFileArgs(args)
	if err != nil {
		return nil, fmt.Errorf("failed to expand file arguments: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no SQL files found matching the specified patterns")
	}

	result := &output.ValidationResult{
		Files: make([]output.FileValidationResult, 0, len(files)),
	}

	// Validate each file
	for _, file := range files {
		fileResult := v.validateFile(file)
		result.Files = append(result.Files, fileResult)
		result.TotalFiles++
		result.TotalBytes += fileResult.Size

		if fileResult.Error != nil {
			if !v.Opts.Quiet {
				fmt.Fprintf(v.Err, "❌ %s: %v\n", file, fileResult.Error) // #nosec G705
			}
			result.InvalidFiles++
			continue
		}

		if fileResult.Valid {
			if !v.Opts.Quiet {
				fmt.Fprintf(v.Out, "✅ %s: Valid SQL\n", file) // #nosec G705
			}
			result.ValidFiles++
		} else {
			if !v.Opts.Quiet {
				fmt.Fprintf(v.Out, "❌ %s: Invalid SQL\n", file) // #nosec G705
			}
			result.InvalidFiles++
		}
	}

	result.Duration = time.Since(startTime)

	// Display statistics if requested
	if v.Opts.ShowStats {
		v.displayStats(result)
	}

	return result, nil
}

// validateFile validates a single SQL file or direct SQL input
func (v *Validator) validateFile(filename string) output.FileValidationResult {
	result := output.FileValidationResult{
		Path: filename,
	}

	// Use robust input detection with security checks
	inputResult, err := DetectAndReadInput(filename)
	if err != nil {
		// Special handling for empty files - they're considered valid
		if strings.Contains(err.Error(), "file is empty") {
			result.Valid = true
			result.Size = 0
			return result
		}
		// Map file path errors to "file access validation failed" for consistency
		if strings.Contains(err.Error(), "invalid file path") || strings.Contains(err.Error(), "security validation failed") {
			result.Error = fmt.Errorf("file access validation failed: %w", err)
		} else {
			result.Error = fmt.Errorf("input processing failed: %w", err)
		}
		return result
	}

	data := inputResult.Content
	result.Size = int64(len(data))

	if len(data) == 0 {
		result.Valid = true
		return result // Empty inputs are considered valid
	}

	// Use pooled tokenizer for performance with dialect support
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Configure dialect if specified
	if v.Opts.Dialect != "" {
		tkz.SetDialect(keywords.SQLDialect(v.Opts.Dialect))
	}

	// Tokenize
	tokens, err := tkz.Tokenize(data)
	if err != nil {
		result.Error = fmt.Errorf("tokenization failed: %w", err)
		return result
	}

	if len(tokens) == 0 {
		result.Valid = true
		return result
	}

	// Convert TokenWithSpan to Token using centralized converter

	// Parse to validate syntax with proper error handling for memory management
	p := parser.NewParser(parser.WithDialect(v.Opts.Dialect))
	astObj, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		result.Error = fmt.Errorf("parsing failed: %w", err)
		return result
	}

	// CRITICAL: Always release AST
	defer func() {
		ast.ReleaseAST(astObj)
	}()

	result.Valid = true
	return result
}

// expandFileArgs expands file arguments (glob patterns, directories) into a list of files
func (v *Validator) expandFileArgs(args []string) ([]string, error) {
	var files []string

	for _, arg := range args {
		// Check if it's a directory first
		if v.Opts.Recursive && v.isDirectory(arg) {
			// Recursive directory processing
			pattern := v.Opts.Pattern
			if pattern == "" {
				pattern = "*.sql"
			}

			err := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if !info.IsDir() {
					matched, err := filepath.Match(pattern, filepath.Base(path))
					if err != nil {
						return err
					}
					if matched {
						files = append(files, path)
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		} else if !looksLikeSQL(arg) && (strings.Contains(arg, "*") || strings.Contains(arg, "?") || strings.Contains(arg, "[")) {
			// Only treat as glob pattern if it doesn't look like SQL
			// This prevents "SELECT * FROM" from being treated as a glob pattern
			matches, err := filepath.Glob(arg)
			if err != nil {
				return nil, err
			}
			files = append(files, matches...)
		} else {
			// Regular file or direct SQL input
			files = append(files, arg)
		}
	}

	return files, nil
}

// isDirectory checks if the given path is a directory
func (v *Validator) isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// displayStats displays validation statistics
func (v *Validator) displayStats(result *output.ValidationResult) {
	fmt.Fprintf(v.Out, "\n📊 Validation Statistics:\n")
	fmt.Fprintf(v.Out, "   Files processed: %d\n", result.TotalFiles)
	fmt.Fprintf(v.Out, "   Valid files: %d\n", result.ValidFiles)
	fmt.Fprintf(v.Out, "   Invalid files: %d\n", result.InvalidFiles)
	fmt.Fprintf(v.Out, "   Total size: %s\n", formatBytes(result.TotalBytes))
	fmt.Fprintf(v.Out, "   Duration: %v\n", result.Duration)

	if result.TotalFiles > 0 && result.Duration.Seconds() > 0 {
		fmt.Fprintf(v.Out, "   Throughput: %.1f files/sec\n", float64(result.TotalFiles)/result.Duration.Seconds())
	}

	if result.TotalBytes > 0 && result.Duration.Seconds() > 0 {
		fmt.Fprintf(v.Out, "   Speed: %s/sec\n", formatBytes(int64(float64(result.TotalBytes)/result.Duration.Seconds())))
	}
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// CLI flags structure
type ValidatorFlags struct {
	Recursive  bool
	Pattern    string
	Quiet      bool
	ShowStats  bool
	Dialect    string
	StrictMode bool
	Verbose    bool
}

// ValidatorOptionsFromConfig creates ValidatorOptions from config and CLI flags
func ValidatorOptionsFromConfig(cfg *config.Config, flagsChanged map[string]bool, flags ValidatorFlags) ValidatorOptions {
	opts := ValidatorOptions{
		Recursive:  cfg.Validation.Recursive,
		Pattern:    cfg.Validation.Pattern,
		Dialect:    cfg.Validation.Dialect,
		StrictMode: cfg.Validation.StrictMode,
		Verbose:    cfg.Output.Verbose,
	}

	// Override with CLI flags if explicitly set
	if flagsChanged["recursive"] {
		opts.Recursive = flags.Recursive
	}
	if flagsChanged["pattern"] {
		opts.Pattern = flags.Pattern
	}
	// Always use quiet flag value (may be set programmatically for SARIF output)
	if flagsChanged["quiet"] || flags.Quiet {
		opts.Quiet = flags.Quiet
	}
	if flagsChanged["stats"] {
		opts.ShowStats = flags.ShowStats
	}
	if flagsChanged["dialect"] {
		opts.Dialect = flags.Dialect
	}
	if flagsChanged["strict"] {
		opts.StrictMode = flags.StrictMode
	}
	if flagsChanged["verbose"] {
		opts.Verbose = flags.Verbose
	}

	return opts
}
