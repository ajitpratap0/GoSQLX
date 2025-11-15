package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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

Performance: 100x faster than SQLFluff for equivalent operations`,
	Args: cobra.MinimumNArgs(1),
	RunE: formatRun,
}

func formatRun(cmd *cobra.Command, args []string) error {
	// Load configuration with CLI flag overrides
	cfg, err := config.LoadDefault()
	if err != nil {
		// If config load fails, use defaults
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

	// Create formatter options from config and flags
	opts := FormatterOptionsFromConfig(cfg, flagsChanged, FormatterFlags{
		InPlace:    formatInPlace,
		IndentSize: formatIndentSize,
		Uppercase:  formatUppercase,
		Compact:    formatCompact,
		Check:      formatCheck,
		MaxLine:    formatMaxLine,
		Verbose:    verbose,
		Output:     output,
	})

	// Create formatter with injectable output writers
	formatter := NewFormatter(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Run formatting
	result, err := formatter.Format(args)
	if err != nil {
		return err
	}

	// Exit with error code if files need formatting in check mode
	if result.NeedsFormatting != nil && len(result.NeedsFormatting) > 0 {
		os.Exit(1)
	}

	return nil
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
