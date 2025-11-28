package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParser_Parse tests SQL parsing functionality
func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		opts          CLIParserOptions
		expectError   bool
		errorContains string
		checkAST      bool
		checkTokens   bool
	}{
		{
			name:     "valid SQL - basic SELECT",
			input:    "SELECT * FROM users",
			opts:     CLIParserOptions{Format: "table"},
			checkAST: true,
		},
		{
			name:     "valid SQL - complex query",
			input:    "SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.name",
			opts:     CLIParserOptions{Format: "table"},
			checkAST: true,
		},
		{
			name:     "valid SQL - window function",
			input:    "SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees",
			opts:     CLIParserOptions{Format: "table"},
			checkAST: true,
		},
		{
			name:     "valid SQL - CTE",
			input:    "WITH temp AS (SELECT id FROM users) SELECT * FROM temp",
			opts:     CLIParserOptions{Format: "table"},
			checkAST: true,
		},
		{
			name:        "show tokens mode",
			input:       "SELECT * FROM users",
			opts:        CLIParserOptions{Format: "table", ShowTokens: true},
			checkTokens: true,
		},
		{
			name:          "invalid SQL - missing table",
			input:         "SELECT * FROM",
			opts:          CLIParserOptions{Format: "table"},
			expectError:   true,
			errorContains: "parsing failed",
		},
		{
			name:          "empty input",
			input:         "",
			opts:          CLIParserOptions{Format: "table"},
			expectError:   true,
			errorContains: "empty input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			parser := NewParser(&outBuf, &errBuf, tt.opts)

			result, err := parser.Parse(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.checkAST && result.AST == nil {
					t.Error("Expected AST but got nil")
				}
				if tt.checkTokens && len(result.Tokens) == 0 {
					t.Error("Expected tokens but got none")
				}
			}

			// Clean up AST
			if result != nil && result.AST != nil {
				ast.ReleaseAST(result.AST)
			}
		})
	}
}

// TestParser_DisplayAST_JSON tests JSON output format
func TestParser_DisplayAST_JSON(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	parser := NewParser(&outBuf, &errBuf, CLIParserOptions{
		Format: "json",
	})

	result, err := parser.Parse("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer ast.ReleaseAST(result.AST)

	err = parser.Display(result)
	if err != nil {
		t.Fatalf("Failed to display: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected JSON output but got empty string")
	}

	// Basic JSON validation
	if !strings.Contains(output, "{") || !strings.Contains(output, "}") {
		t.Error("Output doesn't look like valid JSON")
	}
}

// TestParser_DisplayAST_YAML tests YAML output format
func TestParser_DisplayAST_YAML(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	parser := NewParser(&outBuf, &errBuf, CLIParserOptions{
		Format: "yaml",
	})

	result, err := parser.Parse("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer ast.ReleaseAST(result.AST)

	err = parser.Display(result)
	if err != nil {
		t.Fatalf("Failed to display: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected YAML output but got empty string")
	}
}

// TestParser_DisplayAST_Table tests table output format
func TestParser_DisplayAST_Table(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	parser := NewParser(&outBuf, &errBuf, CLIParserOptions{
		Format: "table",
	})

	result, err := parser.Parse("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer ast.ReleaseAST(result.AST)

	err = parser.Display(result)
	if err != nil {
		t.Fatalf("Failed to display: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected table output but got empty string")
	}

	// Check for expected table elements
	expectedElements := []string{
		"AST Structure",
		"Statements",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(output, elem) {
			t.Errorf("Expected output to contain '%s', but it doesn't", elem)
		}
	}
}

// TestParser_DisplayTokens tests token display
func TestParser_DisplayTokens(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	parser := NewParser(&outBuf, &errBuf, CLIParserOptions{
		Format:     "table",
		ShowTokens: true,
	})

	result, err := parser.Parse("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	err = parser.Display(result)
	if err != nil {
		t.Fatalf("Failed to display tokens: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected token output but got empty string")
	}

	// Check for token output format
	if !strings.Contains(output, "Tokens") {
		t.Error("Expected 'Tokens' in output")
	}
}

// TestParser_DisplayTree tests tree visualization
func TestParser_DisplayTree(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	parser := NewParser(&outBuf, &errBuf, CLIParserOptions{
		Format:   "table",
		TreeView: true,
	})

	result, err := parser.Parse("SELECT * FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer ast.ReleaseAST(result.AST)

	err = parser.Display(result)
	if err != nil {
		t.Fatalf("Failed to display tree: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected tree output but got empty string")
	}

	// Check for tree visualization elements
	if !strings.Contains(output, "AST Tree") {
		t.Error("Expected 'AST Tree' in output")
	}
	if !strings.Contains(output, "├──") && !strings.Contains(output, "└──") {
		t.Error("Expected tree box-drawing characters in output")
	}
}

// TestParser_ComplexQuery tests parsing complex queries
func TestParser_ComplexQuery(t *testing.T) {
	complexQueries := []string{
		"SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.name",
		"WITH temp AS (SELECT id FROM users) SELECT * FROM temp",
		"SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees",
		"INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
		"UPDATE users SET active = true WHERE id = 1",
		"DELETE FROM users WHERE created_at < '2020-01-01'",
	}

	for _, query := range complexQueries {
		t.Run(query[:30]+"...", func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			parser := NewParser(&outBuf, &errBuf, CLIParserOptions{Format: "table"})

			result, err := parser.Parse(query)
			if err != nil {
				t.Errorf("Failed to parse complex query: %v", err)
			}
			if result != nil && result.AST != nil {
				ast.ReleaseAST(result.AST)
			}
		})
	}
}

// TestConvertStatement tests statement conversion
func TestConvertStatement(t *testing.T) {
	// Test with a simple SELECT statement
	var outBuf, errBuf bytes.Buffer
	parser := NewParser(&outBuf, &errBuf, CLIParserOptions{Format: "table"})

	result, err := parser.Parse("SELECT * FROM users WHERE active = true")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	defer ast.ReleaseAST(result.AST)

	if len(result.AST.Statements) == 0 {
		t.Fatal("Expected at least one statement")
	}

	display := convertStatement(result.AST.Statements[0])

	if display.Type == "" {
		t.Error("Expected type to be set")
	}

	// Should have details for SELECT statement
	if display.Details == nil {
		t.Error("Expected details for SELECT statement")
	}
}

// TestParserOptionsFromConfig tests configuration merging
func TestParserOptionsFromConfig(t *testing.T) {
	opts := &CLIParserOptions{
		ShowAST:    true,
		ShowTokens: false,
		Format:     "json",
	}

	if !opts.ShowAST {
		t.Error("Expected ShowAST=true")
	}
	if opts.ShowTokens {
		t.Error("Expected ShowTokens=false")
	}
	if opts.Format != "json" {
		t.Errorf("Expected Format=json, got %s", opts.Format)
	}
}
