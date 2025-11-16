package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

var (
	parseShowAST    bool
	parseShowTokens bool
	parseTreeView   bool
)

// parseCmd represents the parse command
var parseCmd = &cobra.Command{
	Use:   "parse [file|query]",
	Short: "AST structure inspection and token analysis",
	Long: `Parse SQL queries and display Abstract Syntax Tree (AST) structure.

Examples:
  gosqlx parse query.sql                          # Parse file and show AST
  gosqlx parse --ast query.sql                    # Show detailed AST structure
  gosqlx parse --tokens query.sql                 # Show tokenization output
  gosqlx parse --tree query.sql                   # Show tree visualization
  gosqlx parse -f json query.sql                  # JSON output format
  gosqlx parse -f yaml query.sql                  # YAML output format
  gosqlx parse "SELECT * FROM users WHERE id=1"   # Parse query directly

Pipeline/Stdin Examples:
  echo "SELECT * FROM users" | gosqlx parse       # Parse from stdin (auto-detect)
  cat query.sql | gosqlx parse                    # Pipe file contents
  gosqlx parse -                                  # Explicit stdin marker
  gosqlx parse < query.sql                        # Input redirection

Output formats: json, yaml, table, tree
Performance: Direct AST inspection without intermediate representations`,
	Args: cobra.MaximumNArgs(1), // Changed to allow stdin with no args
	RunE: parseRun,
}

func parseRun(cmd *cobra.Command, args []string) error {
	// Handle stdin input
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		if ShouldReadFromStdin(args) {
			return parseFromStdin(cmd)
		}
		return fmt.Errorf("no input provided: specify file path, SQL query, or pipe via stdin")
	}

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

	// Create parser options from config and flags
	opts := ParserOptionsFromConfig(cfg, flagsChanged, ParserFlags{
		ShowAST:    parseShowAST,
		ShowTokens: parseShowTokens,
		TreeView:   parseTreeView,
		Format:     format,
		Verbose:    verbose,
	})

	// Create parser with injectable output writers
	parser := NewParser(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Run parsing
	result, err := parser.Parse(args[0])
	if err != nil {
		return err
	}

	// CRITICAL: Always release AST if it was created
	if result.AST != nil {
		defer ast.ReleaseAST(result.AST)
	}

	// Display the result
	return parser.Display(result)
}

// parseFromStdin handles parsing from stdin input
func parseFromStdin(cmd *cobra.Command) error {
	// Read from stdin
	content, err := ReadFromStdin()
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	// Validate stdin content
	if err := ValidateStdinInput(content); err != nil {
		return fmt.Errorf("stdin validation failed: %w", err)
	}

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

	// Create parser options
	opts := ParserOptionsFromConfig(cfg, flagsChanged, ParserFlags{
		ShowAST:    parseShowAST,
		ShowTokens: parseShowTokens,
		TreeView:   parseTreeView,
		Format:     format,
		Verbose:    verbose,
	})

	// Create parser
	parser := NewParser(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Parse the stdin content (Parse accepts string input directly)
	result, err := parser.Parse(string(content))
	if err != nil {
		return err
	}

	// CRITICAL: Always release AST if it was created
	if result.AST != nil {
		defer ast.ReleaseAST(result.AST)
	}

	// Display the result
	return parser.Display(result)
}

func init() {
	rootCmd.AddCommand(parseCmd)

	parseCmd.Flags().BoolVar(&parseShowAST, "ast", false, "show detailed AST structure")
	parseCmd.Flags().BoolVar(&parseShowTokens, "tokens", false, "show tokenization output")
	parseCmd.Flags().BoolVar(&parseTreeView, "tree", false, "show tree visualization")
}
