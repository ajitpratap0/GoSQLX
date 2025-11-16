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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// ValidatorOptions contains configuration for the SQL validator
type ValidatorOptions struct {
	Recursive  bool
	Pattern    string
	Quiet      bool
	ShowStats  bool
	Dialect    string
	StrictMode bool
	Verbose    bool
}

// Validator provides SQL validation functionality with injectable output
type Validator struct {
	Out  io.Writer
	Err  io.Writer
	Opts ValidatorOptions
}

// NewValidator creates a new Validator with the given options
func NewValidator(out, err io.Writer, opts ValidatorOptions) *Validator {
	return &Validator{
		Out:  out,
		Err:  err,
		Opts: opts,
	}
}

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
				fmt.Fprintf(v.Err, "❌ %s: %v\n", file, fileResult.Error)
			}
			result.InvalidFiles++
			continue
		}

		if fileResult.Valid {
			if !v.Opts.Quiet {
				fmt.Fprintf(v.Out, "✅ %s: Valid SQL\n", file)
			}
			result.ValidFiles++
		} else {
			if !v.Opts.Quiet {
				fmt.Fprintf(v.Out, "❌ %s: Invalid SQL\n", file)
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

// validateFile validates a single SQL file
func (v *Validator) validateFile(filename string) output.FileValidationResult {
	result := output.FileValidationResult{
		Path: filename,
	}

	// Use security validation first
	if err := ValidateFileAccess(filename); err != nil {
		result.Error = fmt.Errorf("file access validation failed: %w", err)
		return result
	}

	// G304: Path is validated by ValidateFileAccess above
	data, err := os.ReadFile(filename) // #nosec G304
	if err != nil {
		result.Error = fmt.Errorf("failed to read file: %w", err)
		return result
	}

	result.Size = int64(len(data))

	if len(data) == 0 {
		result.Valid = true
		return result // Empty files are considered valid
	}

	// Use pooled tokenizer for performance
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

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
	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		result.Error = fmt.Errorf("token conversion failed: %w", err)
		return result
	}

	// Parse to validate syntax with proper error handling for memory management
	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
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
		} else if strings.Contains(arg, "*") || strings.Contains(arg, "?") || strings.Contains(arg, "[") {
			// Glob pattern
			matches, err := filepath.Glob(arg)
			if err != nil {
				return nil, err
			}
			files = append(files, matches...)
		} else {
			// Regular file
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
