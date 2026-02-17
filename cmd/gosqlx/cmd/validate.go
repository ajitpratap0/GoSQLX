package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/output"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

var (
	validateRecursive    bool
	validatePattern      string
	validateQuiet        bool
	validateStats        bool
	validateDialect      string
	validateStrict       bool
	validateOutputFormat string
	validateOutputFile   string
)

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate [file...]",
	Short: "Ultra-fast SQL validation (<10ms typical)",
	Long: `Validate SQL queries with ultra-fast performance.

Examples:
  gosqlx validate query.sql              # Validate single file
  gosqlx validate query1.sql query2.sql  # Validate multiple files
  gosqlx validate "*.sql"                # Validate all SQL files (with quotes)
  gosqlx validate -r ./queries/          # Recursively validate directory
  gosqlx validate --quiet query.sql      # Quiet mode (exit code only)
  gosqlx validate --stats ./queries/     # Show performance statistics
  gosqlx validate --output-format sarif --output-file results.sarif queries/  # SARIF output for GitHub Code Scanning

Pipeline/Stdin Examples:
  echo "SELECT * FROM users" | gosqlx validate    # Validate from stdin (auto-detect)
  cat query.sql | gosqlx validate                 # Pipe file contents
  gosqlx validate -                               # Explicit stdin marker
  gosqlx validate < query.sql                     # Input redirection

Output Formats:
  text  - Human-readable output (default)
  json  - JSON format for programmatic consumption
  sarif - SARIF 2.1.0 format for GitHub Code Scanning integration

Performance Target: <10ms for typical queries (50-500 characters)
Throughput: 100+ files/second in batch mode`,
	Args: cobra.MinimumNArgs(0), // Changed to allow stdin with no args
	RunE: validateRun,
}

func validateRun(cmd *cobra.Command, args []string) error {
	// In quiet/check mode, silence all cobra output — only exit code matters
	if validateQuiet {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
	}

	// Handle stdin input
	if ShouldReadFromStdin(args) {
		return validateFromStdin(cmd)
	}

	// Validate that we have file arguments if not using stdin
	if len(args) == 0 {
		return fmt.Errorf("no input provided: specify file paths or pipe SQL via stdin")
	}

	// If single argument that looks like inline SQL (not a file), validate it directly
	if len(args) == 1 {
		if _, err := os.Stat(args[0]); err != nil && looksLikeSQL(args[0]) {
			return validateInlineSQL(cmd, args[0])
		}
	}

	// Load configuration with CLI flag overrides
	cfg, err := config.LoadDefault()
	if err != nil {
		// If config load fails, use defaults
		cfg = config.DefaultConfig()
	}

	// Validate output format
	if validateOutputFormat != "" && validateOutputFormat != OutputFormatText && validateOutputFormat != OutputFormatJSON && validateOutputFormat != OutputFormatSARIF {
		return fmt.Errorf("invalid output format: %s (valid options: %s, %s, %s)", validateOutputFormat, OutputFormatText, OutputFormatJSON, OutputFormatSARIF)
	}

	// Track which flags were explicitly set
	flagsChanged := trackChangedFlags(cmd)

	// Create validator options from config and flags
	// When outputting SARIF or JSON, automatically enable quiet mode to avoid mixing output
	quietMode := validateQuiet || validateOutputFormat == OutputFormatSARIF || validateOutputFormat == OutputFormatJSON

	opts := ValidatorOptionsFromConfig(cfg, flagsChanged, ValidatorFlags{
		Recursive:  validateRecursive,
		Pattern:    validatePattern,
		Quiet:      quietMode,
		ShowStats:  validateStats && validateOutputFormat == OutputFormatText, // Only show text stats for text output
		Dialect:    validateDialect,
		StrictMode: validateStrict,
		Verbose:    verbose,
	})

	// Create validator with injectable output writers
	validator := NewValidator(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Run validation
	result, err := validator.Validate(args)
	if err != nil {
		return err
	}

	// Handle different output formats
	switch validateOutputFormat {
	case OutputFormatSARIF:
		// Generate SARIF output
		sarifData, err := output.FormatSARIF(result, Version)
		if err != nil {
			return fmt.Errorf("failed to generate SARIF output: %w", err)
		}

		// Write SARIF output to file or stdout
		if validateOutputFile != "" {
			if err := os.WriteFile(validateOutputFile, sarifData, 0600); err != nil {
				return fmt.Errorf("failed to write SARIF output: %w", err)
			}
			if !opts.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "SARIF output written to %s\n", validateOutputFile)
			}
		} else {
			fmt.Fprint(cmd.OutOrStdout(), string(sarifData))
		}
	case OutputFormatJSON:
		// Generate JSON output
		jsonData, err := output.FormatValidationJSON(result, args, validateStats)
		if err != nil {
			return fmt.Errorf("failed to generate JSON output: %w", err)
		}

		// Write JSON output to file or stdout
		if validateOutputFile != "" {
			if err := os.WriteFile(validateOutputFile, jsonData, 0600); err != nil {
				return fmt.Errorf("failed to write JSON output: %w", err)
			}
			if !opts.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "JSON output written to %s\n", validateOutputFile)
			}
		} else {
			fmt.Fprint(cmd.OutOrStdout(), string(jsonData))
		}
	}
	// Default text output is already handled by the validator (no case needed)

	// Return error if there were invalid files
	if result.InvalidFiles > 0 {
		return fmt.Errorf("validation failed: %d invalid file(s)", result.InvalidFiles)
	}

	return nil
}

// validateFromStdin handles validation from stdin input
func validateFromStdin(cmd *cobra.Command) error {
	// Read from stdin
	content, err := ReadFromStdin()
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	// Validate stdin content
	if err := ValidateStdinInput(content); err != nil {
		return fmt.Errorf("stdin validation failed: %w", err)
	}

	// Create a temporary file to leverage existing validation logic
	tmpFile, err := os.CreateTemp("", "gosqlx-stdin-*.sql")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()

	// Write stdin content to temp file
	if _, err := tmpFile.Write(content); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Load configuration
	cfg, err := config.LoadDefault()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Track which flags were explicitly set
	flagsChanged := trackChangedFlags(cmd)

	// Create validator options
	quietMode := validateQuiet || validateOutputFormat == OutputFormatSARIF || validateOutputFormat == OutputFormatJSON
	opts := ValidatorOptionsFromConfig(cfg, flagsChanged, ValidatorFlags{
		Recursive:  false, // stdin is always single input
		Pattern:    "",
		Quiet:      quietMode,
		ShowStats:  validateStats && validateOutputFormat == OutputFormatText, // Only show text stats for text output
		Dialect:    validateDialect,
		StrictMode: validateStrict,
		Verbose:    verbose,
	})

	// Create validator
	validator := NewValidator(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Validate the temporary file
	result, err := validator.Validate([]string{tmpFile.Name()})
	if err != nil {
		return err
	}

	// Update result to show "stdin" instead of temp file path
	// The validation has already output results with temp file path
	// Different output formats are handled below

	// Handle different output formats
	switch validateOutputFormat {
	case OutputFormatSARIF:
		sarifData, err := output.FormatSARIF(result, Version)
		if err != nil {
			return fmt.Errorf("failed to generate SARIF output: %w", err)
		}

		if err := WriteOutput(sarifData, validateOutputFile, cmd.OutOrStdout()); err != nil {
			return err
		}

		if validateOutputFile != "" && !opts.Quiet {
			fmt.Fprintf(cmd.OutOrStdout(), "SARIF output written to %s\n", validateOutputFile)
		}
	case OutputFormatJSON:
		jsonData, err := output.FormatValidationJSON(result, []string{"stdin"}, validateStats)
		if err != nil {
			return fmt.Errorf("failed to generate JSON output: %w", err)
		}

		if err := WriteOutput(jsonData, validateOutputFile, cmd.OutOrStdout()); err != nil {
			return err
		}

		if validateOutputFile != "" && !opts.Quiet {
			fmt.Fprintf(cmd.OutOrStdout(), "JSON output written to %s\n", validateOutputFile)
		}
	}

	// Return error if validation failed
	if result.InvalidFiles > 0 {
		return fmt.Errorf("validation failed: %d invalid file(s)", result.InvalidFiles)
	}

	return nil
}

// validateInlineSQL validates inline SQL passed as a command argument.
// Uses the fast-path Validate() which skips full AST construction (#274).
func validateInlineSQL(cmd *cobra.Command, sql string) error {
	var err error
	if validateDialect != "" {
		err = parser.ValidateWithDialect(sql, keywords.SQLDialect(validateDialect))
	} else {
		err = parser.Validate(sql)
	}
	if err != nil {
		if !validateQuiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "✗ Invalid SQL: %v\n", err)
		}
		return fmt.Errorf("validation failed: %w", err)
	}

	if sql == "" {
		if !validateQuiet {
			fmt.Fprintln(cmd.OutOrStdout(), "✓ Empty input (no statements)")
		}
		return nil
	}

	if !validateQuiet {
		fmt.Fprintln(cmd.OutOrStdout(), "✓ Valid SQL")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.Flags().BoolVarP(&validateRecursive, "recursive", "r", false, "recursively process directories (config: validate.recursive)")
	validateCmd.Flags().StringVarP(&validatePattern, "pattern", "p", "*.sql", "file pattern for recursive processing (config: validate.pattern)")
	validateCmd.Flags().BoolVarP(&validateQuiet, "quiet", "q", false, "quiet mode (exit code only)")
	validateCmd.Flags().BoolVar(&validateQuiet, "check", false, "check mode (alias for --quiet): exit code only, no output")
	validateCmd.Flags().BoolVarP(&validateStats, "stats", "s", false, "show performance statistics")
	validateCmd.Flags().StringVar(&validateDialect, "dialect", "", "SQL dialect: postgresql, mysql, sqlserver, oracle, sqlite (config: validate.dialect)")
	validateCmd.Flags().BoolVar(&validateStrict, "strict", false, "enable strict validation mode (config: validate.strict_mode)")
	validateCmd.Flags().StringVar(&validateOutputFormat, "output-format", "text", "output format: text, json, sarif")
	validateCmd.Flags().StringVar(&validateOutputFile, "output-file", "", "output file path (default: stdout)")
}
