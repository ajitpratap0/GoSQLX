package cmd

import (
	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose bool
	output  string
	format  string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gosqlx",
	Short: "High-performance SQL parsing and analysis tool",
	Long: `GoSQLX CLI - The fastest SQL parser and analyzer
	
GoSQLX provides ultra-fast SQL parsing, validation, formatting, and analysis
with 100x better performance than existing tools like SQLFluff.

Key features:
• Ultra-fast validation (<10ms for typical queries)
• High-performance formatting with intelligent indentation  
• AST structure inspection and analysis
• Security vulnerability detection
• Multi-dialect SQL support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
• Batch processing with directory/glob patterns
• CI/CD integration with proper exit codes

Performance: 1.38M+ operations/second, 100-1000x faster than competitors.`,
	Version: "1.4.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "auto", "output format: json, yaml, table, tree, auto")
}
