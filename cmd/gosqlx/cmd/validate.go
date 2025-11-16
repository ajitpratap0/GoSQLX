package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/output"
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
	// Handle stdin input
	if ShouldReadFromStdin(args) {
		return validateFromStdin(cmd)
	}

	// Validate that we have file arguments if not using stdin
	if len(args) == 0 {
		return fmt.Errorf("no input provided: specify file paths or pipe SQL via stdin")
	}

	// Load configuration with CLI flag overrides
	cfg, err := config.LoadDefault()
	if err != nil {
		// If config load fails, use defaults
		cfg = config.DefaultConfig()
	}

	// Validate output format
	if validateOutputFormat != "" && validateOutputFormat != "text" && validateOutputFormat != "json" && validateOutputFormat != "sarif" {
		return fmt.Errorf("invalid output format: %s (valid options: text, json, sarif)", validateOutputFormat)
	}

	// Track which flags were explicitly set
	flagsChanged := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		flagsChanged[f.Name] = true
	})
	if cmd.Parent() != nil && cmd.Parent().PersistentFlags() != nil {
		cmd.Parent().PersistentFlags().Visit(func(f *pflag.Flag) {
			flagsChanged[f.Name] = true
		})
	}

	// Create validator options from config and flags
	// When outputting SARIF, automatically enable quiet mode to avoid mixing output
	quietMode := validateQuiet || validateOutputFormat == "sarif"

	opts := ValidatorOptionsFromConfig(cfg, flagsChanged, ValidatorFlags{
		Recursive:  validateRecursive,
		Pattern:    validatePattern,
		Quiet:      quietMode,
		ShowStats:  validateStats,
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
	if validateOutputFormat == "sarif" {
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
	} else if validateOutputFormat == "json" {
		// JSON output format will be implemented later
		return fmt.Errorf("JSON output format not yet implemented")
	}
	// Default text output is already handled by the validator

	// Exit with error code if there were invalid files
	if result.InvalidFiles > 0 {
		os.Exit(1)
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
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write stdin content to temp file
	if _, err := tmpFile.Write(content); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}
	tmpFile.Close()

	// Load configuration
	cfg, err := config.LoadDefault()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Track which flags were explicitly set
	flagsChanged := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		flagsChanged[f.Name] = true
	})
	if cmd.Parent() != nil && cmd.Parent().PersistentFlags() != nil {
		cmd.Parent().PersistentFlags().Visit(func(f *pflag.Flag) {
			flagsChanged[f.Name] = true
		})
	}

	// Create validator options
	quietMode := validateQuiet || validateOutputFormat == "sarif"
	opts := ValidatorOptionsFromConfig(cfg, flagsChanged, ValidatorFlags{
		Recursive:  false, // stdin is always single input
		Pattern:    "",
		Quiet:      quietMode,
		ShowStats:  validateStats,
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
	if !opts.Quiet {
		// Replace temp file path with "stdin" in output (already printed)
		// The validation has already output results, so we just handle formats
	}

	// Handle different output formats
	if validateOutputFormat == "sarif" {
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
	} else if validateOutputFormat == "json" {
		return fmt.Errorf("JSON output format not yet implemented")
	}

	// Exit with error code if validation failed
	if result.InvalidFiles > 0 {
		os.Exit(1)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.Flags().BoolVarP(&validateRecursive, "recursive", "r", false, "recursively process directories (config: validate.recursive)")
	validateCmd.Flags().StringVarP(&validatePattern, "pattern", "p", "*.sql", "file pattern for recursive processing (config: validate.pattern)")
	validateCmd.Flags().BoolVarP(&validateQuiet, "quiet", "q", false, "quiet mode (exit code only)")
	validateCmd.Flags().BoolVarP(&validateStats, "stats", "s", false, "show performance statistics")
	validateCmd.Flags().StringVar(&validateDialect, "dialect", "", "SQL dialect: postgresql, mysql, sqlserver, oracle, sqlite (config: validate.dialect)")
	validateCmd.Flags().BoolVar(&validateStrict, "strict", false, "enable strict validation mode (config: validate.strict_mode)")
	validateCmd.Flags().StringVar(&validateOutputFormat, "output-format", "text", "output format: text, json, sarif")
	validateCmd.Flags().StringVar(&validateOutputFile, "output-file", "", "output file path (default: stdout)")
}
