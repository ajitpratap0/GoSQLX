package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
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

Output formats: json, yaml, table, tree
Performance: Direct AST inspection without intermediate representations`,
	Args: cobra.ExactArgs(1),
	RunE: parseRun,
}

func parseRun(cmd *cobra.Command, args []string) error {
	input := args[0]

	// Determine if input is a file or direct SQL
	var sqlContent []byte
	var err error

	if strings.Contains(input, " ") || strings.Contains(input, "SELECT") || strings.Contains(input, "INSERT") ||
		strings.Contains(input, "UPDATE") || strings.Contains(input, "DELETE") || strings.Contains(input, "CREATE") {
		// Direct SQL query
		sqlContent = []byte(input)
	} else {
		// File path
		sqlContent, err = os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", input, err)
		}
	}

	if len(sqlContent) == 0 {
		return fmt.Errorf("empty SQL content")
	}

	// Use pooled tokenizer
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokens, err := tkz.Tokenize(sqlContent)
	if err != nil {
		return fmt.Errorf("tokenization failed: %w", err)
	}

	if parseShowTokens {
		return displayTokens(tokens)
	}

	// Convert TokenWithSpan to Token using centralized converter
	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		return fmt.Errorf("token conversion failed: %w", err)
	}

	// Parse to AST
	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
	if err != nil {
		return fmt.Errorf("parsing failed: %w", err)
	}
	defer ast.ReleaseAST(astObj) // Critical: Prevent memory leaks

	if parseTreeView {
		return displayTree(astObj)
	}

	return displayAST(astObj)
}

func displayTokens(tokens []models.TokenWithSpan) error {
	type TokenDisplay struct {
		Type     string `json:"type" yaml:"type"`
		Value    string `json:"value" yaml:"value"`
		Line     int    `json:"line" yaml:"line"`
		Column   int    `json:"column" yaml:"column"`
		Position int    `json:"position" yaml:"position"`
	}

	var tokenList []TokenDisplay
	for _, token := range tokens {
		tokenList = append(tokenList, TokenDisplay{
			Type:     token.Token.Type.String(),
			Value:    token.Token.Value,
			Line:     token.Start.Line,
			Column:   token.Start.Column,
			Position: token.Start.Line*1000 + token.Start.Column, // Simple position calculation
		})
	}

	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]interface{}{
			"tokens": tokenList,
			"count":  len(tokenList),
		})
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer func() {
			if err := encoder.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close YAML encoder: %v\n", err)
			}
		}()
		return encoder.Encode(map[string]interface{}{
			"tokens": tokenList,
			"count":  len(tokenList),
		})
	default:
		fmt.Printf("Tokens (%d total):\n", len(tokenList))
		fmt.Printf("%-20s %-15s %8s %8s %8s\n", "Type", "Value", "Line", "Column", "Pos")
		fmt.Println(strings.Repeat("-", 70))
		for _, token := range tokenList {
			value := token.Value
			if len(value) > 15 {
				value = value[:12] + "..."
			}
			fmt.Printf("%-20s %-15s %8d %8d %8d\n",
				token.Type, value, token.Line, token.Column, token.Position)
		}
		return nil
	}
}

func displayAST(astObj *ast.AST) error {
	type ASTDisplay struct {
		Type       string                 `json:"type" yaml:"type"`
		Statements []StatementDisplay     `json:"statements" yaml:"statements"`
		TokenCount int                    `json:"token_count" yaml:"token_count"`
		Metadata   map[string]interface{} `json:"metadata" yaml:"metadata"`
	}

	var statements []StatementDisplay
	for _, stmt := range astObj.Statements {
		statements = append(statements, convertStatement(stmt))
	}

	display := ASTDisplay{
		Type:       "AST",
		Statements: statements,
		TokenCount: len(astObj.Statements), // Simplified for now
		Metadata: map[string]interface{}{
			"parser_version": "2.0.0-alpha",
			"sql_compliance": "~80-85% SQL-99",
			"features":       []string{"CTEs", "Window Functions", "JOINs", "Set Operations"},
		},
	}

	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(display)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer func() {
			if err := encoder.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close YAML encoder: %v\n", err)
			}
		}()
		return encoder.Encode(display)
	default:
		fmt.Printf("AST Structure:\n")
		fmt.Printf("  Type: %s\n", display.Type)
		fmt.Printf("  Statements: %d\n", len(display.Statements))
		fmt.Printf("  SQL Compliance: %s\n", display.Metadata["sql_compliance"])
		fmt.Printf("\nStatements:\n")
		for i, stmt := range display.Statements {
			fmt.Printf("  [%d] %s\n", i+1, stmt.Type)
			if stmt.Details != nil {
				for key, value := range stmt.Details {
					fmt.Printf("      %s: %v\n", key, value)
				}
			}
		}
		return nil
	}
}

type StatementDisplay struct {
	Type    string                 `json:"type" yaml:"type"`
	Details map[string]interface{} `json:"details,omitempty" yaml:"details,omitempty"`
}

func convertStatement(stmt ast.Statement) StatementDisplay {
	display := StatementDisplay{
		Type: fmt.Sprintf("%T", stmt),
	}

	// Simplify type name
	if strings.Contains(display.Type, ".") {
		parts := strings.Split(display.Type, ".")
		display.Type = parts[len(parts)-1]
	}

	// Add basic details based on statement type
	details := make(map[string]interface{})

	switch s := stmt.(type) {
	case *ast.SelectStatement:
		details["columns"] = len(s.Columns)
		if len(s.From) > 0 {
			details["has_from"] = true
		}
		if s.Where != nil {
			details["has_where"] = true
		}
		if len(s.GroupBy) > 0 {
			details["has_group_by"] = true
		}
		if len(s.OrderBy) > 0 {
			details["has_order_by"] = true
		}
		if s.Limit != nil {
			details["has_limit"] = true
		}
	case *ast.InsertStatement:
		details["table"] = "present"
		if s.Values != nil {
			details["has_values"] = true
		}
	case *ast.UpdateStatement:
		details["table"] = "present"
		if s.Where != nil {
			details["has_where"] = true
		}
	case *ast.DeleteStatement:
		details["table"] = "present"
		if s.Where != nil {
			details["has_where"] = true
		}
	case *ast.CreateTableStatement:
		details["object_type"] = "table"
	case *ast.CreateIndexStatement:
		details["object_type"] = "index"
	}

	if len(details) > 0 {
		display.Details = details
	}

	return display
}

func displayTree(astObj *ast.AST) error {
	fmt.Printf("🌳 AST Tree Structure:\n")
	fmt.Printf("├── AST Root\n")

	for i, stmt := range astObj.Statements {
		isLast := i == len(astObj.Statements)-1
		prefix := "├──"
		childPrefix := "│   "
		if isLast {
			prefix = "└──"
			childPrefix = "    "
		}

		stmtType := fmt.Sprintf("%T", stmt)
		if strings.Contains(stmtType, ".") {
			parts := strings.Split(stmtType, ".")
			stmtType = parts[len(parts)-1]
		}

		fmt.Printf("%s %s\n", prefix, stmtType)

		// Add basic tree structure for different statement types
		switch s := stmt.(type) {
		case *ast.SelectStatement:
			if len(s.Columns) > 0 {
				fmt.Printf("%s├── Columns (%d items)\n", childPrefix, len(s.Columns))
			}
			if len(s.From) > 0 {
				fmt.Printf("%s├── From (%d tables)\n", childPrefix, len(s.From))
			}
			if s.Where != nil {
				fmt.Printf("%s├── Where\n", childPrefix)
			}
			if len(s.GroupBy) > 0 {
				fmt.Printf("%s├── GroupBy\n", childPrefix)
			}
			if len(s.OrderBy) > 0 {
				fmt.Printf("%s├── OrderBy\n", childPrefix)
			}
			if s.Limit != nil {
				fmt.Printf("%s└── Limit\n", childPrefix)
			}
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(parseCmd)

	parseCmd.Flags().BoolVar(&parseShowAST, "ast", false, "show detailed AST structure")
	parseCmd.Flags().BoolVar(&parseShowTokens, "tokens", false, "show tokenization output")
	parseCmd.Flags().BoolVar(&parseTreeView, "tree", false, "show tree visualization")
}
