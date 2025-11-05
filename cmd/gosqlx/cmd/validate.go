package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
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

	// Override config with CLI flags if they were explicitly set
	if cmd.Flags().Changed("recursive") {
		cfg.Validation.Recursive = validateRecursive
	} else {
		validateRecursive = cfg.Validation.Recursive
	}
	if cmd.Flags().Changed("pattern") {
		cfg.Validation.Pattern = validatePattern
	} else {
		validatePattern = cfg.Validation.Pattern
	}
	if cmd.Flags().Changed("dialect") {
		cfg.Validation.Dialect = validateDialect
	} else {
		validateDialect = cfg.Validation.Dialect
	}
	if cmd.Flags().Changed("strict") {
		cfg.Validation.StrictMode = validateStrict
	}

	// Use verbose from global flags if set
	if cmd.Parent().PersistentFlags().Changed("verbose") {
		cfg.Output.Verbose = verbose
	} else {
		verbose = cfg.Output.Verbose
	}

	startTime := time.Now()

	files, err := expandFileArgs(args)
	if err != nil {
		return fmt.Errorf("failed to expand file arguments: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no SQL files found matching the specified patterns")
	}

	var totalFiles, validFiles, invalidFiles int
	var totalBytes int64

	for _, file := range files {
		valid, size, err := validateFile(file)
		totalFiles++
		totalBytes += size

		if err != nil {
			if !validateQuiet {
				fmt.Fprintf(os.Stderr, "❌ %s: %v\n", file, err)
			}
			invalidFiles++
			continue
		}

		if valid {
			if !validateQuiet {
				fmt.Printf("✅ %s: Valid SQL\n", file)
			}
			validFiles++
		} else {
			if !validateQuiet {
				fmt.Printf("❌ %s: Invalid SQL\n", file)
			}
			invalidFiles++
		}
	}

	duration := time.Since(startTime)

	if validateStats {
		fmt.Printf("\n📊 Validation Statistics:\n")
		fmt.Printf("   Files processed: %d\n", totalFiles)
		fmt.Printf("   Valid files: %d\n", validFiles)
		fmt.Printf("   Invalid files: %d\n", invalidFiles)
		fmt.Printf("   Total size: %s\n", formatBytes(totalBytes))
		fmt.Printf("   Duration: %v\n", duration)
		fmt.Printf("   Throughput: %.1f files/sec\n", float64(totalFiles)/duration.Seconds())
		if totalBytes > 0 {
			fmt.Printf("   Speed: %s/sec\n", formatBytes(int64(float64(totalBytes)/duration.Seconds())))
		}
	}

	if invalidFiles > 0 {
		os.Exit(1)
	}

	return nil
}

func validateFile(filename string) (bool, int64, error) {
	// Use security validation first
	if err := ValidateFileAccess(filename); err != nil {
		return false, 0, fmt.Errorf("file access validation failed: %w", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read file: %w", err)
	}

	if len(data) == 0 {
		return true, 0, nil // Empty files are considered valid
	}

	// Use pooled tokenizer for performance
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokens, err := tkz.Tokenize(data)
	if err != nil {
		return false, int64(len(data)), fmt.Errorf("tokenization failed: %w", err)
	}

	if len(tokens) == 0 {
		return true, int64(len(data)), nil
	}

	// Convert TokenWithSpan to Token using centralized converter
	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		return false, int64(len(data)), fmt.Errorf("token conversion failed: %w", err)
	}

	// Parse to validate syntax with proper error handling for memory management
	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
	if err != nil {
		// Parser failed, no AST to release
		return false, int64(len(data)), fmt.Errorf("parsing failed: %w", err)
	}

	// CRITICAL: Always release AST
	defer func() {
		ast.ReleaseAST(astObj)
	}()

	return true, int64(len(data)), nil
}

func expandFileArgs(args []string) ([]string, error) {
	var files []string

	for _, arg := range args {
		if validateRecursive && isDirectory(arg) {
			// Recursive directory processing
			pattern := validatePattern
			if pattern == "" {
				pattern = "*.sql"
			}

			err := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if !info.IsDir() {
					matched, err := filepath.Match(pattern, filepath.Base(path))
					if err != nil {
						return err
					}
					if matched {
						files = append(files, path)
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		} else if strings.Contains(arg, "*") || strings.Contains(arg, "?") || strings.Contains(arg, "[") {
			// Glob pattern
			matches, err := filepath.Glob(arg)
			if err != nil {
				return nil, err
			}
			files = append(files, matches...)
		} else {
			// Regular file
			files = append(files, arg)
		}
	}

	return files, nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
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
