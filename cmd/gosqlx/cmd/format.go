package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
)

var (
	formatInPlace    bool
	formatIndentSize int
	formatUppercase  bool
	formatCompact    bool
	formatCheck      bool
	formatMaxLine    int
)

// formatCmd represents the format command
var formatCmd = &cobra.Command{
	Use:   "format [file...]",
	Short: "High-performance SQL formatting",
	Long: `Format SQL queries with high-performance processing.

Examples:
  gosqlx format query.sql                    # Format to stdout
  gosqlx format -i query.sql                 # Format in-place
  gosqlx format --indent 4 query.sql         # Use 4-space indentation
  gosqlx format --no-uppercase query.sql     # Keep original keyword case
  gosqlx format --compact query.sql          # Compact format (minimal whitespace)
  gosqlx format --check query.sql            # Check if formatting is needed (CI mode)
  gosqlx format "*.sql"                      # Format all SQL files
  gosqlx format -o formatted.sql query.sql   # Save to specific file

Pipeline/Stdin Examples:
  echo "SELECT * FROM users" | gosqlx format    # Format from stdin (auto-detect)
  cat query.sql | gosqlx format                 # Pipe file contents
  gosqlx format -                               # Explicit stdin marker
  gosqlx format < query.sql                     # Input redirection
  cat query.sql | gosqlx format > formatted.sql # Full pipeline

Performance: 100x faster than SQLFluff for equivalent operations`,
	Args: cobra.MinimumNArgs(0), // Changed to allow stdin with no args
	RunE: formatRun,
}

func formatRun(cmd *cobra.Command, args []string) error {
	// Handle stdin input
	if ShouldReadFromStdin(args) {
		return formatFromStdin(cmd)
	}

	// Validate that we have file arguments if not using stdin
	if len(args) == 0 {
		return fmt.Errorf("no input provided: specify file paths or pipe SQL via stdin")
	}

	// If single argument that looks like inline SQL (not a file), format it directly
	if len(args) == 1 {
		if _, err := os.Stat(args[0]); err != nil && looksLikeSQL(args[0]) {
			return formatInlineSQL(cmd, args[0])
		}
	}

	// Load configuration with CLI flag overrides
	cfg, err := config.LoadDefault()
	if err != nil {
		// If config load fails, use defaults
		cfg = config.DefaultConfig()
	}

	// Track which flags were explicitly set
	flagsChanged := trackChangedFlags(cmd)

	// Create formatter options from config and flags
	opts := FormatterOptionsFromConfig(cfg, flagsChanged, FormatterFlags{
		InPlace:    formatInPlace,
		IndentSize: formatIndentSize,
		Uppercase:  formatUppercase,
		Compact:    formatCompact,
		Check:      formatCheck,
		MaxLine:    formatMaxLine,
		Verbose:    verbose,
		Output:     outputFile,
	})

	// Create formatter with injectable output writers
	formatter := NewFormatter(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Run formatting
	result, err := formatter.Format(args)
	if err != nil {
		return err
	}

	// Exit with error code if files need formatting in check mode
	if len(result.NeedsFormatting) > 0 {
		os.Exit(1)
	}

	// Exit with error code if any files failed to format
	if result.FailedFiles > 0 {
		return fmt.Errorf("%d file(s) failed to format", result.FailedFiles)
	}

	return nil
}

// formatFromStdin handles formatting from stdin input
func formatFromStdin(cmd *cobra.Command) error {
	// Read from stdin
	content, err := ReadFromStdin()
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	// Validate stdin content
	if err := ValidateStdinInput(content); err != nil {
		return fmt.Errorf("stdin validation failed: %w", err)
	}

	// Note: in-place mode is not supported for stdin (would be no-op)
	if formatInPlace {
		return fmt.Errorf("in-place mode (-i) is not supported with stdin input")
	}

	// Load configuration
	cfg, err := config.LoadDefault()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Track which flags were explicitly set
	flagsChanged := trackChangedFlags(cmd)

	// Create formatter options
	opts := FormatterOptionsFromConfig(cfg, flagsChanged, FormatterFlags{
		InPlace:    false, // always false for stdin
		IndentSize: formatIndentSize,
		Uppercase:  formatUppercase,
		Compact:    formatCompact,
		Check:      formatCheck,
		MaxLine:    formatMaxLine,
		Verbose:    verbose,
		Output:     outputFile,
	})

	// Create formatter
	formatter := NewFormatter(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Format the SQL content using the internal formatSQL method
	formattedSQL, err := formatter.formatSQL(string(content))
	if err != nil {
		return fmt.Errorf("formatting failed: %w", err)
	}

	// In check mode, compare original and formatted
	if formatCheck {
		if string(content) != formattedSQL {
			fmt.Fprintf(cmd.ErrOrStderr(), "stdin needs formatting\n")
			os.Exit(1)
		}

		if verbose {
			fmt.Fprintf(cmd.OutOrStdout(), "stdin is properly formatted\n")
		}
		return nil
	}

	// Write formatted output with trailing newline
	if !strings.HasSuffix(formattedSQL, "\n") {
		formattedSQL += "\n"
	}
	if err := WriteOutput([]byte(formattedSQL), outputFile, cmd.OutOrStdout()); err != nil {
		return err
	}

	return nil
}

// formatInlineSQL formats inline SQL passed as a command argument
func formatInlineSQL(cmd *cobra.Command, sql string) error {
	// Load configuration
	cfg, err := config.LoadDefault()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Track which flags were explicitly set
	flagsChanged := trackChangedFlags(cmd)

	opts := FormatterOptionsFromConfig(cfg, flagsChanged, FormatterFlags{
		InPlace:    false,
		IndentSize: formatIndentSize,
		Uppercase:  formatUppercase,
		Compact:    formatCompact,
		Check:      formatCheck,
		MaxLine:    formatMaxLine,
		Verbose:    verbose,
		Output:     outputFile,
	})

	formatter := NewFormatter(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
	formattedSQL, err := formatter.formatSQL(sql)
	if err != nil {
		return fmt.Errorf("formatting failed: %w", err)
	}

	// Ensure trailing newline
	if !strings.HasSuffix(formattedSQL, "\n") {
		formattedSQL += "\n"
	}

	return WriteOutput([]byte(formattedSQL), outputFile, cmd.OutOrStdout())
}

func init() {
	rootCmd.AddCommand(formatCmd)

	formatCmd.Flags().BoolVarP(&formatInPlace, "in-place", "i", false, "edit files in place")
	formatCmd.Flags().IntVar(&formatIndentSize, "indent", 2, "indentation size in spaces (config: format.indent)")
	formatCmd.Flags().BoolVar(&formatUppercase, "uppercase", true, "uppercase SQL keywords (config: format.uppercase_keywords)")
	formatCmd.Flags().BoolVar(&formatCompact, "compact", false, "compact format (config: format.compact)")
	formatCmd.Flags().BoolVar(&formatCheck, "check", false, "check if files need formatting (CI mode)")
	formatCmd.Flags().IntVar(&formatMaxLine, "max-line", 80, "maximum line length (config: format.max_line_length)")

	// Add negation flags
	formatCmd.Flags().BoolVar(&formatUppercase, "no-uppercase", false, "keep original keyword case")
}
