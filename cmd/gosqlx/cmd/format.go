package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

var (
	formatInPlace    bool
	formatIndentSize int
	formatUppercase  bool
	formatCompact    bool
	formatCheck      bool
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
	files, err := expandFileArgs(args)
	if err != nil {
		return fmt.Errorf("failed to expand file arguments: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no SQL files found matching the specified patterns")
	}

	var needsFormatting []string
	startTime := time.Now()

	for _, file := range files {
		formatted, changed, err := formatFile(file)
		if err != nil {
			return fmt.Errorf("failed to format %s: %w", file, err)
		}

		if formatCheck {
			if changed {
				needsFormatting = append(needsFormatting, file)
			}
			continue
		}

		if formatInPlace {
			if changed {
				err = os.WriteFile(file, []byte(formatted), 0644)
				if err != nil {
					return fmt.Errorf("failed to write %s: %w", file, err)
				}
				if verbose {
					fmt.Printf("Formatted: %s\n", file)
				}
			} else if verbose {
				fmt.Printf("Already formatted: %s\n", file)
			}
		} else if output != "" {
			err = os.WriteFile(output, []byte(formatted), 0644)
			if err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}
		} else {
			fmt.Print(formatted)
		}
	}

	if formatCheck {
		if len(needsFormatting) > 0 {
			fmt.Fprintf(os.Stderr, "The following files need formatting:\n")
			for _, file := range needsFormatting {
				fmt.Fprintf(os.Stderr, "  %s\n", file)
			}
			os.Exit(1)
		}
		fmt.Printf("All %d files are properly formatted (%v)\n", len(files), time.Since(startTime))
	}

	return nil
}

func formatFile(filename string) (string, bool, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", false, fmt.Errorf("failed to read file: %w", err)
	}

	original := string(data)
	if len(data) == 0 {
		return original, false, nil
	}

	formatted, err := formatSQL(original, FormatOptions{
		IndentSize: formatIndentSize,
		Uppercase:  formatUppercase,
		Compact:    formatCompact,
	})
	if err != nil {
		return "", false, err
	}

	changed := original != formatted
	return formatted, changed, nil
}

type FormatOptions struct {
	IndentSize int
	Uppercase  bool
	Compact    bool
}

func formatSQL(sql string, opts FormatOptions) (string, error) {
	// Use pooled tokenizer for performance
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize the SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("tokenization failed: %w", err)
	}

	if len(tokens) == 0 {
		return "", nil
	}

	// Convert tokens for parser using centralized converter
	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		return "", fmt.Errorf("token conversion failed: %w", err)
	}

	// Parse to AST using pooled AST object
	astObj := ast.NewAST()
	defer ast.ReleaseAST(astObj)

	p := parser.NewParser()
	parsedAST, err := p.Parse(convertedTokens)
	if err != nil {
		return "", fmt.Errorf("parsing failed: %w", err)
	}

	// Configure formatter options
	indentStr := strings.Repeat(" ", opts.IndentSize)
	formatterOpts := FormatterOptions{
		Indent:       indentStr,
		Compact:      opts.Compact,
		UppercaseKw:  opts.Uppercase,
		AlignColumns: !opts.Compact, // Align columns unless in compact mode
	}

	// Create formatter and format the AST
	formatter := NewSQLFormatter(formatterOpts)
	formatted, err := formatter.Format(parsedAST)
	if err != nil {
		return "", fmt.Errorf("formatting failed: %w", err)
	}

	return formatted, nil
}

func init() {
	rootCmd.AddCommand(formatCmd)

	formatCmd.Flags().BoolVarP(&formatInPlace, "in-place", "i", false, "edit files in place")
	formatCmd.Flags().IntVar(&formatIndentSize, "indent", 2, "indentation size in spaces")
	formatCmd.Flags().BoolVar(&formatUppercase, "uppercase", true, "uppercase SQL keywords")
	formatCmd.Flags().BoolVar(&formatCompact, "compact", false, "compact format (minimal whitespace)")
	formatCmd.Flags().BoolVar(&formatCheck, "check", false, "check if files need formatting (CI mode)")

	// Add negation flags
	formatCmd.Flags().BoolVar(&formatUppercase, "no-uppercase", false, "keep original keyword case")
}
