package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/optimizer"
)

// optimizeCmd represents the optimize command
var optimizeCmd = &cobra.Command{
	Use:   "optimize [file|sql]",
	Short: "Analyze SQL for optimization opportunities",
	Long: `Analyze SQL queries and provide optimization suggestions.

The optimizer checks for common performance anti-patterns including:
  * OPT-001: SELECT * usage (recommends explicit column lists)
  * OPT-002: UPDATE/DELETE without WHERE (dangerous operations)
  * OPT-003: Cartesian products (implicit cross joins)
  * OPT-004: DISTINCT overuse (may indicate JOIN issues)
  * OPT-005: Subqueries in WHERE (suggests JOIN rewrites)
  * OPT-006: OR conditions preventing index usage
  * OPT-007: Leading wildcard in LIKE (prevents index scans)
  * OPT-008: Functions on indexed columns (prevents index usage)

Each suggestion includes severity (info/warning/error), explanation,
and where possible a suggested rewrite.

Examples:
  gosqlx optimize query.sql                       # Analyze file
  gosqlx optimize "SELECT * FROM users"            # Analyze query directly
  gosqlx optimize -f json query.sql                # JSON output
  echo "DELETE FROM users" | gosqlx optimize       # Analyze from stdin
  gosqlx optimize -                                # Explicit stdin marker

Output includes an optimization score (0-100), complexity classification,
and detailed suggestions.`,
	Args: cobra.MaximumNArgs(1),
	RunE: optimizeRun,
}

func optimizeRun(cmd *cobra.Command, args []string) error {
	// Handle stdin input
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		if ShouldReadFromStdin(args) {
			return optimizeFromStdin(cmd)
		}
		return fmt.Errorf("no input provided: specify file path, SQL query, or pipe via stdin")
	}

	// Detect and read input (file or direct SQL)
	input, err := DetectAndReadInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	return runOptimize(cmd, string(input.Content))
}

// optimizeFromStdin handles optimization from stdin input
func optimizeFromStdin(cmd *cobra.Command) error {
	content, err := ReadFromStdin()
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	if err := ValidateStdinInput(content); err != nil {
		return fmt.Errorf("stdin validation failed: %w", err)
	}

	return runOptimize(cmd, string(content))
}

// runOptimize performs the optimization analysis and outputs results
func runOptimize(cmd *cobra.Command, sql string) error {
	opt := optimizer.New()

	result, err := opt.AnalyzeSQL(sql)
	if err != nil {
		return fmt.Errorf("optimization analysis failed: %w", err)
	}

	// Use a buffer to capture output when writing to file
	var outputBuf bytes.Buffer
	var outWriter io.Writer = cmd.OutOrStdout()
	if outputFile != "" {
		outWriter = &outputBuf
	}

	// Format output based on requested format
	switch strings.ToLower(format) {
	case "json":
		if err := outputOptimizeJSON(outWriter, result); err != nil {
			return err
		}
	default:
		outputOptimizeText(outWriter, result)
	}

	// Write to file if specified
	if outputFile != "" {
		return WriteOutput(outputBuf.Bytes(), outputFile, cmd.OutOrStdout())
	}

	return nil
}

// outputOptimizeJSON writes the optimization result as JSON
func outputOptimizeJSON(w io.Writer, result *optimizer.OptimizationResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputOptimizeText writes the optimization result as human-readable text
func outputOptimizeText(w io.Writer, result *optimizer.OptimizationResult) {
	fmt.Fprint(w, optimizer.FormatResult(result))
}

func init() {
	rootCmd.AddCommand(optimizeCmd)
}
