package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

var (
	lintRecursive  bool
	lintPattern    string
	lintAutoFix    bool
	lintMaxLength  int
	lintFailOnWarn bool
)

// lintCmd represents the lint command
var lintCmd = &cobra.Command{
	Use:   "lint [file...]",
	Short: "Check SQL code for style and quality issues",
	Long: `Lint SQL files to detect style and quality issues.

The linter checks for common issues like:
  • L001: Trailing whitespace at end of lines
  • L002: Mixed tabs and spaces for indentation
  • L005: Lines exceeding maximum length

Examples:
  gosqlx lint query.sql                # Lint single file
  gosqlx lint query1.sql query2.sql    # Lint multiple files
  gosqlx lint "*.sql"                  # Lint all SQL files (with quotes)
  gosqlx lint -r ./queries/            # Recursively lint directory
  gosqlx lint --auto-fix query.sql     # Auto-fix violations where possible
  gosqlx lint --max-length 120 query.sql  # Set maximum line length

Pipeline/Stdin Examples:
  echo "SELECT * FROM users" | gosqlx lint    # Lint from stdin
  cat query.sql | gosqlx lint                 # Pipe file contents
  gosqlx lint -                               # Explicit stdin marker
  gosqlx lint < query.sql                     # Input redirection

Exit Codes:
  0 - No violations found
  1 - Errors or warnings found (warnings only if --fail-on-warn is set)`,
	Args: cobra.MinimumNArgs(0),
	RunE: lintRun,
}

func lintRun(cmd *cobra.Command, args []string) error {
	// Handle stdin input
	if ShouldReadFromStdin(args) {
		return lintFromStdin(cmd)
	}

	// Validate that we have file arguments if not using stdin
	if len(args) == 0 {
		return fmt.Errorf("no input provided: specify file paths or pipe SQL via stdin")
	}

	// Create linter with default rules
	l := createLinter()

	// Process files or directories
	var result linter.Result
	if lintRecursive {
		// Process directories recursively
		for _, path := range args {
			r := l.LintDirectory(path, lintPattern)
			result.Files = append(result.Files, r.Files...)
			result.TotalFiles += r.TotalFiles
			result.TotalViolations += r.TotalViolations
		}
	} else {
		// Process individual files
		result = l.LintFiles(args)
	}

	// Display results
	output := linter.FormatResult(result)
	fmt.Fprint(cmd.OutOrStdout(), output)

	// Apply auto-fix if requested
	if lintAutoFix && result.TotalViolations > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nApplying auto-fixes...")
		fixCount := 0

		for _, fileResult := range result.Files {
			if len(fileResult.Violations) == 0 {
				continue
			}

			// Read file content
			content, err := os.ReadFile(fileResult.Filename)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error reading %s: %v\n", fileResult.Filename, err)
				continue
			}

			fixed := string(content)
			modified := false

			// Apply fixes from each rule
			for _, rule := range l.Rules() {
				if !rule.CanAutoFix() {
					continue
				}

				fixedContent, err := rule.Fix(fixed, fileResult.Violations)
				if err != nil {
					continue
				}

				if fixedContent != fixed {
					fixed = fixedContent
					modified = true
				}
			}

			// Write back if modified
			if modified {
				if err := os.WriteFile(fileResult.Filename, []byte(fixed), 0600); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Error writing %s: %v\n", fileResult.Filename, err)
					continue
				}
				fixCount++
				fmt.Fprintf(cmd.OutOrStdout(), "Fixed: %s\n", fileResult.Filename)
			}
		}

		fmt.Fprintf(cmd.OutOrStdout(), "\nAuto-fixed %d file(s)\n", fixCount)
	}

	// Exit with error code if there were violations
	errorCount := 0
	warningCount := 0
	for _, fileResult := range result.Files {
		for _, violation := range fileResult.Violations {
			if violation.Severity == linter.SeverityError {
				errorCount++
			} else if violation.Severity == linter.SeverityWarning {
				warningCount++
			}
		}
	}

	// Exit with error if there are errors, or warnings with fail-on-warn flag
	if errorCount > 0 || (lintFailOnWarn && warningCount > 0) {
		os.Exit(1)
	}

	return nil
}

// lintFromStdin handles linting from stdin input
func lintFromStdin(cmd *cobra.Command) error {
	// Read from stdin
	content, err := ReadFromStdin()
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	// Validate stdin content
	if err := ValidateStdinInput(content); err != nil {
		return fmt.Errorf("stdin validation failed: %w", err)
	}

	// Create linter
	l := createLinter()

	// Lint the content
	result := l.LintString(string(content), "stdin")

	// Display results
	fmt.Fprintf(cmd.OutOrStdout(), "Linting stdin input:\n\n")

	if len(result.Violations) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No violations found.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Found %d violation(s):\n\n", len(result.Violations))
	for i, violation := range result.Violations {
		fmt.Fprintf(cmd.OutOrStdout(), "%d. %s\n", i+1, linter.FormatViolation(violation))
	}

	// Apply auto-fix if requested
	if lintAutoFix {
		fmt.Fprintln(cmd.OutOrStdout(), "\nAuto-fixed output:")
		fixed := string(content)
		for _, rule := range l.Rules() {
			if rule.CanAutoFix() {
				fixedContent, err := rule.Fix(fixed, result.Violations)
				if err == nil && fixedContent != fixed {
					fixed = fixedContent
				}
			}
		}
		fmt.Fprintln(cmd.OutOrStdout(), fixed)
	}

	// Exit with error code if there were violations
	errorCount := 0
	warningCount := 0
	for _, violation := range result.Violations {
		if violation.Severity == linter.SeverityError {
			errorCount++
		} else if violation.Severity == linter.SeverityWarning {
			warningCount++
		}
	}

	if errorCount > 0 || (lintFailOnWarn && warningCount > 0) {
		os.Exit(1)
	}

	return nil
}

// createLinter creates a new linter instance with configured rules
func createLinter() *linter.Linter {
	return linter.New(
		whitespace.NewTrailingWhitespaceRule(),
		whitespace.NewMixedIndentationRule(),
		whitespace.NewLongLinesRule(lintMaxLength),
	)
}

func init() {
	rootCmd.AddCommand(lintCmd)

	lintCmd.Flags().BoolVarP(&lintRecursive, "recursive", "r", false, "recursively process directories")
	lintCmd.Flags().StringVarP(&lintPattern, "pattern", "p", "*.sql", "file pattern for recursive processing")
	lintCmd.Flags().BoolVar(&lintAutoFix, "auto-fix", false, "automatically fix violations where possible")
	lintCmd.Flags().IntVar(&lintMaxLength, "max-length", 100, "maximum line length (L005 rule)")
	lintCmd.Flags().BoolVar(&lintFailOnWarn, "fail-on-warn", false, "exit with error code on warnings")
}
