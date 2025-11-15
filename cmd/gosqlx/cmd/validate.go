package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
)

var (
	validateRecursive bool
	validatePattern   string
	validateQuiet     bool
	validateStats     bool
	validateDialect   string
	validateStrict    bool
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

Performance Target: <10ms for typical queries (50-500 characters)
Throughput: 100+ files/second in batch mode`,
	Args: cobra.MinimumNArgs(1),
	RunE: validateRun,
}

func validateRun(cmd *cobra.Command, args []string) error {
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

	// Create validator options from config and flags
	opts := ValidatorOptionsFromConfig(cfg, flagsChanged, ValidatorFlags{
		Recursive:  validateRecursive,
		Pattern:    validatePattern,
		Quiet:      validateQuiet,
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

	// Exit with error code if there were invalid files
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
}
