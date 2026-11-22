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

package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	sqlsecurity "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

var (
	lintRecursive  bool
	lintPattern    string
	lintAutoFix    bool
	lintMaxLength  int
	lintFailOnWarn bool
	lintSecurity   bool
	lintDialect    string
)

// lintCmd represents the lint command
var lintCmd = &cobra.Command{
	Use:   "lint [file...]",
	Short: "Check SQL code for style and quality issues",
	Long: `Lint SQL files to detect style and quality issues.

The linter checks for common issues like:
  • L001: Trailing whitespace at end of lines
  • L002: Mixed tabs and spaces for indentation
  • L003: Consecutive blank lines
  • L004: Indentation depth (excessive nesting)
  • L005: Lines exceeding maximum length
  • L006: SELECT column alignment
  • L007: Keyword case consistency (uppercase/lowercase)
  • L008: Comma placement (trailing vs leading)
  • L009: Aliasing consistency (table aliases)
  • L010: Redundant whitespace (multiple spaces)

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
  1 - Violations found, or the SQL has a syntax error. With --auto-fix the
      result is judged after the fixes are applied.

Input with no statements (empty, whitespace or only comments) is not a syntax
error.`,
	Args: cobra.MinimumNArgs(0),
	RunE: lintRun,
}

func lintRun(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	// Reject unknown dialect names early before any parsing.
	if err := normalizeDialectFlag(&lintDialect); err != nil {
		return err
	}
	if err := rejectGlobalFormat(cmd); err != nil {
		return err
	}

	// Handle stdin input
	if ShouldReadFromStdin(args) {
		return lintFromStdin(cmd)
	}

	// Validate that we have file arguments if not using stdin
	if len(args) == 0 {
		return fmt.Errorf("no input provided: specify file paths or pipe SQL via stdin")
	}

	// If single argument that looks like inline SQL (not a file), lint it directly
	if len(args) == 1 {
		if _, statErr := os.Stat(args[0]); statErr != nil && looksLikeSQL(args[0]) {
			return lintInlineSQL(cmd, args[0])
		}
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

	// Use a buffer to capture output when writing to file
	var outputBuf bytes.Buffer
	outWriter := io.Writer(cmd.OutOrStdout())
	if outputFile != "" {
		outWriter = &outputBuf
	}

	// Display results
	output := linter.FormatResult(result)
	fmt.Fprint(outWriter, output)

	// Apply auto-fix if requested
	if lintAutoFix && result.TotalViolations > 0 {
		fmt.Fprintln(outWriter, "\nApplying auto-fixes...")
		fixCount := 0

		fixedIdx := make([]int, 0, len(result.Files))
		for idx, fileResult := range result.Files {
			if len(fileResult.Violations) == 0 {
				continue
			}

			// Read file content
			content, err := os.ReadFile(filepath.Clean(fileResult.Filename)) // #nosec G304
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

			// Write back if modified, preserving original file permissions
			if modified {
				// Get original file permissions
				fileInfo, statErr := os.Stat(fileResult.Filename)
				perm := os.FileMode(0644) // Default fallback permission
				if statErr == nil {
					perm = fileInfo.Mode()
				}

				if err := os.WriteFile(fileResult.Filename, []byte(fixed), perm); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Error writing %s: %v\n", fileResult.Filename, err)
					continue
				}
				fixCount++
				fixedIdx = append(fixedIdx, idx)
				fmt.Fprintf(outWriter, "Fixed: %s\n", fileResult.Filename)
			}
		}

		// Judge the run by what is left after the fixes, not by the report
		// printed before them.
		if len(fixedIdx) > 0 {
			for _, idx := range fixedIdx {
				before := result.Files[idx]
				after := l.LintFile(before.Filename)
				result.TotalViolations += len(after.Violations) - len(before.Violations)
				result.Files[idx] = after
			}
			fmt.Fprintf(outWriter, "\n%d violation(s) remain after auto-fix\n", result.TotalViolations)
		}

		fmt.Fprintf(outWriter, "\nAuto-fixed %d file(s)\n", fixCount)
	}

	// Write to file if specified
	if outputFile != "" {
		if err := WriteOutput(outputBuf.Bytes(), outputFile, cmd.OutOrStdout()); err != nil {
			return err
		}
	}

	// Run security scanner if --security flag is set
	securityFindingCount := 0
	if lintSecurity {
		for _, fileResult := range result.Files {
			if fileResult.Error != nil {
				continue
			}
			content, readErr := os.ReadFile(fileResult.Filename)
			if readErr != nil {
				continue
			}
			securityFindingCount += runSecurityScan(string(content), fileResult.Filename, outWriter)
		}
	}

	// Return error if there were violations or file errors
	errorCount := 0
	warningCount := 0
	infoCount := 0
	fileErrorCount := 0
	syntaxErrorCount := 0
	for _, fileResult := range result.Files {
		if fileResult.Error != nil {
			fileErrorCount++
		} else if fileResult.SyntaxError() != nil {
			syntaxErrorCount++
		}
		for _, violation := range fileResult.Violations {
			switch violation.Severity {
			case linter.SeverityError:
				errorCount++
			case linter.SeverityWarning:
				warningCount++
			case linter.SeverityInfo:
				infoCount++
			}
		}
	}

	if fileErrorCount > 0 {
		return fmt.Errorf("linting failed: %d file(s) had errors", fileErrorCount)
	}

	totalViolations := errorCount + warningCount + infoCount
	if syntaxErrorCount > 0 {
		return silentError{fmt.Errorf("%d file(s) contain SQL syntax errors (and %d violation(s))", syntaxErrorCount, totalViolations)}
	}
	if totalViolations > 0 {
		return fmt.Errorf("found %d violation(s): %d error(s), %d warning(s), %d info(s)",
			totalViolations, errorCount, warningCount, infoCount)
	}

	if securityFindingCount > 0 {
		return fmt.Errorf("%d security finding(s) detected", securityFindingCount)
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

	// Use a buffer to capture output when writing to file
	var outputBuf bytes.Buffer
	outWriter := io.Writer(cmd.OutOrStdout())
	if outputFile != "" {
		outWriter = &outputBuf
	}

	// Display results
	fmt.Fprintf(outWriter, "Linting stdin input:\n\n")

	synErr := result.SyntaxError()
	if synErr != nil {
		fmt.Fprintf(outWriter, "Syntax error: %v\n\n", synErr)
	}

	if len(result.Violations) == 0 {
		if synErr == nil {
			fmt.Fprintln(outWriter, "No violations found.")
		}
		// Write to file if specified
		if outputFile != "" {
			if err := WriteOutput(outputBuf.Bytes(), outputFile, cmd.OutOrStdout()); err != nil {
				return err
			}
		}
		return lintOutcomeError(result.Violations, synErr)
	}

	fmt.Fprintf(outWriter, "Found %d violation(s):\n\n", len(result.Violations))
	for i, violation := range result.Violations {
		fmt.Fprintf(outWriter, "%d. %s\n", i+1, linter.FormatViolation(violation))
	}

	// Apply auto-fix if requested. The exit status then reflects what is left
	// in the fixed text.
	if lintAutoFix {
		fmt.Fprintln(outWriter, "\nAuto-fixed output:")
		fixed := string(content)
		for _, rule := range l.Rules() {
			if rule.CanAutoFix() {
				fixedContent, err := rule.Fix(fixed, result.Violations)
				if err == nil && fixedContent != fixed {
					fixed = fixedContent
				}
			}
		}
		fmt.Fprintln(outWriter, fixed)
		if fixed != string(content) {
			result = l.LintString(fixed, "stdin")
			synErr = result.SyntaxError()
			fmt.Fprintf(outWriter, "\n%d violation(s) remain after auto-fix\n", len(result.Violations))
		}
	}

	// Write to file if specified
	if outputFile != "" {
		if err := WriteOutput(outputBuf.Bytes(), outputFile, cmd.OutOrStdout()); err != nil {
			return err
		}
	}

	return lintOutcomeError(result.Violations, synErr)
}

// lintInlineSQL lints inline SQL passed as a command argument
func lintInlineSQL(cmd *cobra.Command, sql string) error {
	l := createLinter()
	result := l.LintString(sql, "inline")

	var outputBuf bytes.Buffer
	outWriter := io.Writer(cmd.OutOrStdout())
	if outputFile != "" {
		outWriter = &outputBuf
	}

	synErr := result.SyntaxError()
	if synErr != nil {
		fmt.Fprintf(outWriter, "Syntax error: %v\n\n", synErr)
	}

	switch {
	case len(result.Violations) > 0:
		fmt.Fprintf(outWriter, "Found %d violation(s):\n\n", len(result.Violations))
		for i, violation := range result.Violations {
			fmt.Fprintf(outWriter, "%d. %s\n", i+1, linter.FormatViolation(violation))
		}
	case synErr == nil:
		fmt.Fprintln(outWriter, "No violations found.")
	}

	if outputFile != "" {
		if err := WriteOutput(outputBuf.Bytes(), outputFile, cmd.OutOrStdout()); err != nil {
			return err
		}
	}

	return lintOutcomeError(result.Violations, synErr)
}

// lintOutcomeError maps one lint run of stdin or inline SQL to the command's
// result: invalid SQL and error-severity violations always fail it, warnings
// only with --fail-on-warn.
func lintOutcomeError(violations []linter.Violation, synErr error) error {
	errorCount := 0
	warningCount := 0
	for _, violation := range violations {
		switch violation.Severity {
		case linter.SeverityError:
			errorCount++
		case linter.SeverityWarning:
			warningCount++
		}
	}

	if synErr != nil {
		// The report already includes the syntax error; main only needs the failure status.
		return silentError{fmt.Errorf("invalid SQL: %w", synErr)}
	}
	if errorCount > 0 || (lintFailOnWarn && warningCount > 0) {
		return fmt.Errorf("%d error(s) and %d warning(s) found", errorCount, warningCount)
	}
	return nil
}

// runSecurityScan runs the security scanner on the given SQL and prints findings.
// Returns the number of security findings.
func runSecurityScan(sql string, filename string, outWriter io.Writer) int {
	var (
		tree *ast.AST
		err  error
	)
	if lintDialect != "" {
		tree, err = gosqlx.ParseWithDialect(sql, sqlkeywords.SQLDialect(lintDialect))
	} else {
		tree, err = gosqlx.Parse(sql)
	}
	if err != nil {
		fmt.Fprintf(outWriter, "  [WARN] %s: could not parse for security scan: %v\n", filename, err)
		return 0
	}
	defer ast.ReleaseAST(tree)
	scanner := sqlsecurity.NewScanner()
	result := mergeSecurityFindings(scanner.Scan(tree), scanner.ScanSQL(sql))
	for _, f := range result.Findings {
		fmt.Fprintf(outWriter, "  [%s] %s:%d:%d - %s (%s)\n",
			f.Severity, filename, f.Line, f.Column, f.Description, f.Pattern)
	}
	return result.TotalCount
}

// createLinter creates a new linter instance with the core rule set
// (L001-L010) from rules.CoreRules, using --max-length for L005.
func createLinter() *linter.Linter {
	cfg := rules.DefaultCoreConfig()
	cfg.MaxLineLength = lintMaxLength
	l := linter.New(rules.CoreRules(cfg)...)
	if lintDialect != "" {
		l.SetDialect(sqlkeywords.SQLDialect(lintDialect))
	}
	return l
}

func init() {
	rootCmd.AddCommand(lintCmd)

	lintCmd.Flags().BoolVarP(&lintRecursive, "recursive", "r", false, "recursively process directories")
	lintCmd.Flags().StringVarP(&lintPattern, "pattern", "p", "*.sql", "file pattern for recursive processing")
	lintCmd.Flags().BoolVar(&lintAutoFix, "auto-fix", false, "automatically fix violations where possible")
	lintCmd.Flags().IntVar(&lintMaxLength, "max-length", 100, "maximum line length (L005 rule)")
	lintCmd.Flags().BoolVar(&lintFailOnWarn, "fail-on-warn", false, "exit with error code on warnings")
	lintCmd.Flags().BoolVar(&lintSecurity, "security", false, "run security scanner (LIKE injection, tautology, UNION injection)")
	lintCmd.Flags().StringVar(&lintDialect, "dialect", "", dialectFlagUsage("default: postgresql"))
}
