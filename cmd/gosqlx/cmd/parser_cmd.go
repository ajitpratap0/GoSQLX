package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/output"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// CLIParserOptions contains configuration for the SQL parser CLI
type CLIParserOptions struct {
	ShowAST    bool
	ShowTokens bool
	TreeView   bool
	Format     string
	Verbose    bool
}

// Parser provides SQL parsing functionality with injectable output
type Parser struct {
	Out  io.Writer
	Err  io.Writer
	Opts CLIParserOptions
}

// ParserResult contains the result of parsing
type ParserResult struct {
	Tokens []models.TokenWithSpan
	AST    *ast.AST
	Error  error
}

// NewParser creates a new Parser with the given options
func NewParser(out, err io.Writer, opts CLIParserOptions) *Parser {
	return &Parser{
		Out:  out,
		Err:  err,
		Opts: opts,
	}
}

// Parse parses the given SQL input (file or direct SQL)
func (p *Parser) Parse(input string) (*ParserResult, error) {
	result := &ParserResult{}

	// Use robust input detection with security checks
	inputResult, err := DetectAndReadInput(input)
	if err != nil {
		result.Error = fmt.Errorf("input processing failed: %w", err)
		return result, result.Error
	}

	// Use pooled tokenizer
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokens, err := tkz.Tokenize(inputResult.Content)
	if err != nil {
		result.Error = fmt.Errorf("tokenization failed: %w", err)
		return result, result.Error
	}

	result.Tokens = tokens

	// If only tokens requested, return early
	if p.Opts.ShowTokens {
		return result, nil
	}

	// Parse to AST with proper error handling for memory management
	pr := parser.NewParser()
	defer pr.Release()
	astObj, err := pr.ParseFromModelTokens(result.Tokens)
	if err != nil {
		// Parser failed, no AST to release
		result.Error = fmt.Errorf("parsing failed: %w", err)
		return result, result.Error
	}

	result.AST = astObj
	return result, nil
}

// Display displays the parsing result based on configuration
func (p *Parser) Display(result *ParserResult) error {
	if p.Opts.ShowTokens {
		return p.displayTokens(result.Tokens)
	}

	if p.Opts.TreeView {
		return p.displayTree(result.AST)
	}

	return p.displayAST(result.AST)
}

// displayTokens displays token information
func (p *Parser) displayTokens(tokens []models.TokenWithSpan) error {
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
			Position: token.Start.Line*1000 + token.Start.Column,
		})
	}

	switch strings.ToLower(p.Opts.Format) {
	case "json":
		encoder := json.NewEncoder(p.Out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]interface{}{
			"tokens": tokenList,
			"count":  len(tokenList),
		})
	case "yaml":
		encoder := yaml.NewEncoder(p.Out)
		defer func() {
			if err := encoder.Close(); err != nil {
				fmt.Fprintf(p.Err, "Warning: failed to close YAML encoder: %v\n", err)
			}
		}()
		return encoder.Encode(map[string]interface{}{
			"tokens": tokenList,
			"count":  len(tokenList),
		})
	default:
		fmt.Fprintf(p.Out, "Tokens (%d total):\n", len(tokenList))
		fmt.Fprintf(p.Out, "%-20s %-15s %8s %8s %8s\n", "Type", "Value", "Line", "Column", "Pos")
		fmt.Fprintf(p.Out, "%s\n", strings.Repeat("-", 70))
		for _, token := range tokenList {
			value := token.Value
			if len(value) > 15 {
				value = value[:12] + "..."
			}
			fmt.Fprintf(p.Out, "%-20s %-15s %8d %8d %8d\n",
				token.Type, value, token.Line, token.Column, token.Position)
		}
		return nil
	}
}

// StatementDisplay represents a simplified statement for display
type StatementDisplay struct {
	Type    string                 `json:"type" yaml:"type"`
	Details map[string]interface{} `json:"details,omitempty" yaml:"details,omitempty"`
}

// displayAST displays AST structure
func (p *Parser) displayAST(astObj *ast.AST) error {
	// Use the new JSON output format for consistency
	if strings.ToLower(p.Opts.Format) == "json" {
		return p.displayASTJSON(astObj)
	}

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
		TokenCount: len(astObj.Statements),
		Metadata: map[string]interface{}{
			"parser_version": "2.0.0-alpha",
			"sql_compliance": "~80-85% SQL-99",
			"features":       []string{"CTEs", "Window Functions", "JOINs", "Set Operations"},
		},
	}

	switch strings.ToLower(p.Opts.Format) {
	case "yaml":
		encoder := yaml.NewEncoder(p.Out)
		defer func() {
			if err := encoder.Close(); err != nil {
				fmt.Fprintf(p.Err, "Warning: failed to close YAML encoder: %v\n", err)
			}
		}()
		return encoder.Encode(display)
	default:
		fmt.Fprintf(p.Out, "AST Structure:\n")
		fmt.Fprintf(p.Out, "  Type: %s\n", display.Type)
		fmt.Fprintf(p.Out, "  Statements: %d\n", len(display.Statements))
		fmt.Fprintf(p.Out, "  SQL Compliance: %s\n", display.Metadata["sql_compliance"])
		fmt.Fprintf(p.Out, "\nStatements:\n")
		for i, stmt := range display.Statements {
			fmt.Fprintf(p.Out, "  [%d] %s\n", i+1, stmt.Type)
			if stmt.Details != nil {
				for key, value := range stmt.Details {
					fmt.Fprintf(p.Out, "      %s: %v\n", key, value)
				}
			}
		}
		return nil
	}
}

// displayASTJSON displays AST in JSON format using the standardized output format
func (p *Parser) displayASTJSON(astObj *ast.AST) error {
	// Use the standardized JSON output format
	jsonData, err := output.FormatParseJSON(astObj, "input", false, nil)
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}

	fmt.Fprint(p.Out, string(jsonData))
	return nil
}

// displayTree displays AST in tree format
func (p *Parser) displayTree(astObj *ast.AST) error {
	fmt.Fprintf(p.Out, "🌳 AST Tree Structure:\n")
	fmt.Fprintf(p.Out, "├── AST Root\n")

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

		fmt.Fprintf(p.Out, "%s %s\n", prefix, stmtType)

		// Add basic tree structure for SELECT statements
		if s, ok := stmt.(*ast.SelectStatement); ok {
			if len(s.Columns) > 0 {
				fmt.Fprintf(p.Out, "%s├── Columns (%d items)\n", childPrefix, len(s.Columns))
			}
			if len(s.From) > 0 {
				fmt.Fprintf(p.Out, "%s├── From (%d tables)\n", childPrefix, len(s.From))
			}
			if s.Where != nil {
				fmt.Fprintf(p.Out, "%s├── Where\n", childPrefix)
			}
			if len(s.GroupBy) > 0 {
				fmt.Fprintf(p.Out, "%s├── GroupBy\n", childPrefix)
			}
			if len(s.OrderBy) > 0 {
				fmt.Fprintf(p.Out, "%s├── OrderBy\n", childPrefix)
			}
			if s.Limit != nil {
				fmt.Fprintf(p.Out, "%s└── Limit\n", childPrefix)
			}
		}
	}

	return nil
}

// convertStatement converts an AST statement to a display format
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

// ParserFlags represents CLI flags for parser command
type ParserFlags struct {
	ShowAST    bool
	ShowTokens bool
	TreeView   bool
	Format     string
	Verbose    bool
}

// ParserOptionsFromConfig creates CLIParserOptions from config and CLI flags
func ParserOptionsFromConfig(cfg *config.Config, flagsChanged map[string]bool, flags ParserFlags) CLIParserOptions {
	opts := CLIParserOptions{
		Format:  cfg.Output.Format,
		Verbose: cfg.Output.Verbose,
	}

	// Override with CLI flags if explicitly set
	if flagsChanged["ast"] {
		opts.ShowAST = flags.ShowAST
	}
	if flagsChanged["tokens"] {
		opts.ShowTokens = flags.ShowTokens
	}
	if flagsChanged["tree"] {
		opts.TreeView = flags.TreeView
	}
	if flagsChanged["format"] {
		opts.Format = flags.Format
	}
	if flagsChanged["verbose"] {
		opts.Verbose = flags.Verbose
	}

	return opts
}
