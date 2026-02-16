// Package optimizecmd implements the gosqlx optimize subcommand.
package optimizecmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/cmdutil"
	"github.com/ajitpratap0/GoSQLX/pkg/advisor"
)

// NewCmd returns the optimize cobra.Command.
//
// The outputFile and format parameters are pointers to the root command's
// persistent flag values, allowing this subcommand to access global flags.
func NewCmd(outputFile *string, format *string) *cobra.Command {
	cmd := &cobra.Command{
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOptimize(cmd, args, outputFile, format)
		},
	}

	return cmd
}

func runOptimize(cmd *cobra.Command, args []string, outputFile *string, format *string) error {
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		if cmdutil.ShouldReadFromStdin(args) {
			return optimizeFromStdin(cmd, outputFile, format)
		}
		return fmt.Errorf("no input provided: specify file path, SQL query, or pipe via stdin")
	}

	input, err := cmdutil.DetectAndReadInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	return doOptimize(cmd, string(input.Content), outputFile, format)
}

func optimizeFromStdin(cmd *cobra.Command, outputFile *string, format *string) error {
	content, err := cmdutil.ReadFromStdin()
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	if err := cmdutil.ValidateStdinInput(content); err != nil {
		return fmt.Errorf("stdin validation failed: %w", err)
	}

	return doOptimize(cmd, string(content), outputFile, format)
}

func doOptimize(cmd *cobra.Command, sql string, outputFile *string, format *string) error {
	opt := advisor.New()

	result, err := opt.AnalyzeSQL(sql)
	if err != nil {
		return fmt.Errorf("optimization analysis failed: %w", err)
	}

	var outputBuf bytes.Buffer
	outWriter := io.Writer(cmd.OutOrStdout())
	if *outputFile != "" {
		outWriter = &outputBuf
	}

	switch strings.ToLower(*format) {
	case "json":
		if err := outputOptimizeJSON(outWriter, result); err != nil {
			return err
		}
	default:
		outputOptimizeText(outWriter, result)
	}

	if *outputFile != "" {
		return cmdutil.WriteOutput(outputBuf.Bytes(), *outputFile, cmd.OutOrStdout())
	}

	return nil
}

func outputOptimizeJSON(w io.Writer, result *advisor.OptimizationResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputOptimizeText(w io.Writer, result *advisor.OptimizationResult) {
	fmt.Fprint(w, advisor.FormatResult(result))
}
