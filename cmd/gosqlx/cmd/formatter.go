package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// CLIFormatterOptions contains configuration for the SQL formatter CLI
type CLIFormatterOptions struct {
	InPlace    bool
	IndentSize int
	Uppercase  bool
	Compact    bool
	Check      bool
	MaxLine    int
	Verbose    bool
	Output     string // Output file path
}

// Formatter provides SQL formatting functionality with injectable output
type Formatter struct {
	Out  io.Writer
	Err  io.Writer
	Opts CLIFormatterOptions
}

// FormatterResult contains the results of a formatting run
type FormatterResult struct {
	TotalFiles       int
	FormattedFiles   int
	AlreadyFormatted int
	FailedFiles      int
	NeedsFormatting  []string
	Duration         time.Duration
}

// FileFormatterResult contains the result for a single file
type FileFormatterResult struct {
	Path      string
	Formatted string
	Changed   bool
	Error     error
}

// NewFormatter creates a new Formatter with the given options
func NewFormatter(out, err io.Writer, opts CLIFormatterOptions) *Formatter {
	return &Formatter{
		Out:  out,
		Err:  err,
		Opts: opts,
	}
}

// Format formats the given SQL files or patterns
func (f *Formatter) Format(args []string) (*FormatterResult, error) {
	startTime := time.Now()

	// Expand file arguments
	files, err := expandFileArgs(args)
	if err != nil {
		return nil, fmt.Errorf("failed to expand file arguments: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no SQL files found matching the specified patterns")
	}

	result := &FormatterResult{
		NeedsFormatting: make([]string, 0),
	}

	// Format each file
	for _, file := range files {
		fileResult := f.formatFile(file)
		result.TotalFiles++

		if fileResult.Error != nil {
			fmt.Fprintf(f.Err, "❌ %s: %v\n", file, fileResult.Error)
			result.FailedFiles++
			continue
		}

		if f.Opts.Check {
			if fileResult.Changed {
				result.NeedsFormatting = append(result.NeedsFormatting, file)
			}
			continue
		}

		if f.Opts.InPlace {
			if fileResult.Changed {
				// G306: Use 0600 for better security (owner read/write only)
				err = os.WriteFile(file, []byte(fileResult.Formatted), 0600)
				if err != nil {
					fmt.Fprintf(f.Err, "❌ Failed to write %s: %v\n", file, err)
					result.FailedFiles++
					continue
				}
				if f.Opts.Verbose {
					fmt.Fprintf(f.Out, "✅ Formatted: %s\n", file)
				}
				result.FormattedFiles++
			} else {
				if f.Opts.Verbose {
					fmt.Fprintf(f.Out, "✓ Already formatted: %s\n", file)
				}
				result.AlreadyFormatted++
			}
		} else if f.Opts.Output != "" {
			// G306: Use 0600 for better security (owner read/write only)
			err = os.WriteFile(f.Opts.Output, []byte(fileResult.Formatted), 0600)
			if err != nil {
				fmt.Fprintf(f.Err, "❌ Failed to write output file: %v\n", err)
				result.FailedFiles++
				continue
			}
			result.FormattedFiles++
		} else {
			fmt.Fprint(f.Out, fileResult.Formatted)
			result.FormattedFiles++
		}
	}

	result.Duration = time.Since(startTime)

	// Handle check mode results
	if f.Opts.Check {
		if len(result.NeedsFormatting) > 0 {
			fmt.Fprintf(f.Err, "The following files need formatting:\n")
			for _, file := range result.NeedsFormatting {
				fmt.Fprintf(f.Err, "  %s\n", file)
			}
			return result, fmt.Errorf("%d files need formatting", len(result.NeedsFormatting))
		}
		fmt.Fprintf(f.Out, "All %d files are properly formatted (%v)\n", result.TotalFiles, result.Duration)
	}

	return result, nil
}

// formatFile formats a single SQL file
func (f *Formatter) formatFile(filename string) FileFormatterResult {
	result := FileFormatterResult{
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

	original := string(data)
	if len(data) == 0 {
		result.Formatted = original
		result.Changed = false
		return result
	}

	formatted, err := f.formatSQL(original)
	if err != nil {
		result.Error = err
		return result
	}

	result.Formatted = formatted
	result.Changed = (original != formatted)
	return result
}

// formatSQL formats a SQL string
func (f *Formatter) formatSQL(sql string) (string, error) {
	// Use pooled tokenizer for performance
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize the SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("tokenization failed: %w", err)
	}

	if len(tokens) == 0 {
		return "", nil
	}

	// Convert tokens for parser using centralized converter
	convertedTokens, err := parser.ConvertTokensForParser(tokens) //nolint:staticcheck // intentional use of deprecated type for Phase 1 bridge
	if err != nil {
		return "", fmt.Errorf("token conversion failed: %w", err)
	}

	// Parse to AST with proper error handling for memory management
	p := parser.NewParser()
	parsedAST, err := p.Parse(convertedTokens)
	if err != nil {
		// Parser failed, no AST to release
		return "", fmt.Errorf("parsing failed: %w", err)
	}

	// CRITICAL: Always release AST, even on formatting errors
	defer func() {
		ast.ReleaseAST(parsedAST)
	}()

	// Configure formatter options
	indentStr := strings.Repeat(" ", f.Opts.IndentSize)
	formatterOpts := FormatterOptions{
		Indent:       indentStr,
		Compact:      f.Opts.Compact,
		UppercaseKw:  f.Opts.Uppercase,
		AlignColumns: !f.Opts.Compact, // Align columns unless in compact mode
	}

	// Create formatter and format the AST
	formatter := NewSQLFormatter(formatterOpts)
	formatted, err := formatter.Format(parsedAST)
	if err != nil {
		return "", fmt.Errorf("formatting failed: %w", err)
	}

	return formatted, nil
}

// FormatterFlags represents CLI flags for formatter command
type FormatterFlags struct {
	InPlace    bool
	IndentSize int
	Uppercase  bool
	Compact    bool
	Check      bool
	MaxLine    int
	Verbose    bool
	Output     string
}

// FormatterOptionsFromConfig creates CLIFormatterOptions from config and CLI flags
func FormatterOptionsFromConfig(cfg *config.Config, flagsChanged map[string]bool, flags FormatterFlags) CLIFormatterOptions {
	opts := CLIFormatterOptions{
		IndentSize: cfg.Format.Indent,
		Uppercase:  cfg.Format.UppercaseKeywords,
		Compact:    cfg.Format.Compact,
		MaxLine:    cfg.Format.MaxLineLength,
		Verbose:    cfg.Output.Verbose,
	}

	// Override with CLI flags if explicitly set
	if flagsChanged["in-place"] {
		opts.InPlace = flags.InPlace
	}
	if flagsChanged["indent"] {
		opts.IndentSize = flags.IndentSize
	}
	if flagsChanged["uppercase"] || flagsChanged["no-uppercase"] {
		opts.Uppercase = flags.Uppercase
	}
	if flagsChanged["compact"] {
		opts.Compact = flags.Compact
	}
	if flagsChanged["check"] {
		opts.Check = flags.Check
	}
	if flagsChanged["max-line"] {
		opts.MaxLine = flags.MaxLine
	}
	if flagsChanged["verbose"] {
		opts.Verbose = flags.Verbose
	}
	if flagsChanged["output"] {
		opts.Output = flags.Output
	}

	return opts
}
