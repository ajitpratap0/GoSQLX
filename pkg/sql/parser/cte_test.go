package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// convertTokensForCTE converts TokenWithSpan to Token for parser
func convertTokensForCTE(tokens []models.TokenWithSpan) []token.Token {
	result := make([]token.Token, 0, len(tokens))
	for _, t := range tokens {
		// Determine token type
		var tokenType token.Type

		switch t.Token.Type {
		case models.TokenTypeIdentifier:
			tokenType = "IDENT"
		case models.TokenTypeKeyword:
			// Use the keyword value as the token type
			tokenType = token.Type(t.Token.Value)
		case models.TokenTypeString:
			tokenType = "STRING"
		case models.TokenTypeNumber:
			tokenType = "INT"
		case models.TokenTypeOperator:
			tokenType = token.Type(t.Token.Value)
		case models.TokenTypeLParen:
			tokenType = "("
		case models.TokenTypeRParen:
			tokenType = ")"
		case models.TokenTypeComma:
			tokenType = ","
		case models.TokenTypePeriod:
			tokenType = "."
		case models.TokenTypeEq:
			tokenType = "="
		default:
			// For any other type, use the value as the type if it looks like a keyword
			if t.Token.Value != "" {
				tokenType = token.Type(t.Token.Value)
			}
		}

		// Only add tokens with valid types and values
		if tokenType != "" && t.Token.Value != "" {
			result = append(result, token.Token{
				Type:    tokenType,
				Literal: t.Token.Value,
			})
		}
	}
	return result
}

func TestParser_SimpleCTE(t *testing.T) {
	sql := `WITH test_cte AS (SELECT name FROM users) SELECT name FROM test_cte`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForCTE(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse CTE: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a SELECT statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	// Verify WITH clause exists
	if selectStmt.With == nil {
		t.Fatal("Expected WITH clause")
	}

	// Verify not recursive
	if selectStmt.With.Recursive {
		t.Error("Expected non-recursive CTE")
	}

	// Verify one CTE
	if len(selectStmt.With.CTEs) != 1 {
		t.Errorf("Expected 1 CTE, got %d", len(selectStmt.With.CTEs))
	}

	// Verify CTE details
	if len(selectStmt.With.CTEs) > 0 {
		cte := selectStmt.With.CTEs[0]
		if cte.Name != "test_cte" {
			t.Errorf("Expected CTE name 'test_cte', got '%s'", cte.Name)
		}

		// Verify CTE statement is a SELECT
		_, ok := cte.Statement.(*ast.SelectStatement)
		if !ok {
			t.Errorf("Expected CTE statement to be SELECT, got %T", cte.Statement)
		}
	}
}

func TestParser_RecursiveCTE(t *testing.T) {
	sql := `WITH RECURSIVE emp_tree AS (SELECT emp_id FROM employees) SELECT emp_id FROM emp_tree`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForCTE(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse recursive CTE: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a SELECT statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	// Verify WITH clause exists
	if selectStmt.With == nil {
		t.Fatal("Expected WITH clause")
	}

	// Verify recursive
	if !selectStmt.With.Recursive {
		t.Error("Expected recursive CTE")
	}

	// Verify one CTE
	if len(selectStmt.With.CTEs) != 1 {
		t.Errorf("Expected 1 CTE, got %d", len(selectStmt.With.CTEs))
	}

	// Verify CTE details
	if len(selectStmt.With.CTEs) > 0 {
		cte := selectStmt.With.CTEs[0]
		if cte.Name != "emp_tree" {
			t.Errorf("Expected CTE name 'emp_tree', got '%s'", cte.Name)
		}
	}
}

func TestParser_MultipleCTEs(t *testing.T) {
	sql := `WITH first_cte AS (SELECT region FROM sales), second_cte AS (SELECT region FROM first_cte) SELECT region FROM second_cte`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForCTE(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse multiple CTEs: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a SELECT statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	// Verify WITH clause exists
	if selectStmt.With == nil {
		t.Fatal("Expected WITH clause")
	}

	// Verify two CTEs
	if len(selectStmt.With.CTEs) != 2 {
		t.Errorf("Expected 2 CTEs, got %d", len(selectStmt.With.CTEs))
	}

	// Verify CTE names
	expectedNames := []string{"first_cte", "second_cte"}
	for i, expectedName := range expectedNames {
		if i < len(selectStmt.With.CTEs) {
			if selectStmt.With.CTEs[i].Name != expectedName {
				t.Errorf("CTE %d: expected name '%s', got '%s'", i, expectedName, selectStmt.With.CTEs[i].Name)
			}
		}
	}
}

func TestParser_CTEWithColumns(t *testing.T) {
	sql := `WITH sales_summary(region, total, avg_sale) AS (SELECT region, amount, amount FROM sales) SELECT region FROM sales_summary`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokensForCTE(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse CTE with columns: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a SELECT statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	// Verify WITH clause exists
	if selectStmt.With == nil {
		t.Fatal("Expected WITH clause")
	}

	// Verify CTE has columns
	if len(selectStmt.With.CTEs) > 0 {
		cte := selectStmt.With.CTEs[0]
		if cte.Name != "sales_summary" {
			t.Errorf("Expected CTE name 'sales_summary', got '%s'", cte.Name)
		}

		expectedColumns := []string{"region", "total", "avg_sale"}
		if len(cte.Columns) != len(expectedColumns) {
			t.Errorf("Expected %d columns, got %d", len(expectedColumns), len(cte.Columns))
		}

		for i, expectedCol := range expectedColumns {
			if i < len(cte.Columns) {
				if cte.Columns[i] != expectedCol {
					t.Errorf("Column %d: expected '%s', got '%s'", i, expectedCol, cte.Columns[i])
				}
			}
		}
	}
}

func TestParser_MaterializedCTE(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		materialized *bool // nil = not specified, true = MATERIALIZED, false = NOT MATERIALIZED
	}{
		{
			name:         "MATERIALIZED CTE",
			sql:          `WITH cached_data AS MATERIALIZED (SELECT name FROM users) SELECT name FROM cached_data`,
			materialized: boolPtr(true),
		},
		{
			name:         "NOT MATERIALIZED CTE",
			sql:          `WITH inline_data AS NOT MATERIALIZED (SELECT name FROM users) SELECT name FROM inline_data`,
			materialized: boolPtr(false),
		},
		{
			name:         "Default CTE (no materialization hint)",
			sql:          `WITH default_data AS (SELECT name FROM users) SELECT name FROM default_data`,
			materialized: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get tokenizer from pool
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			// Tokenize SQL
			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Failed to tokenize: %v", err)
			}

			// Convert tokens for parser
			convertedTokens := convertTokensForCTE(tokens)

			// Parse tokens
			parser := &Parser{}
			astObj, err := parser.Parse(convertedTokens)
			if err != nil {
				t.Fatalf("Failed to parse CTE: %v", err)
			}
			defer ast.ReleaseAST(astObj)

			// Verify we have a SELECT statement
			if len(astObj.Statements) == 0 {
				t.Fatal("No statements parsed")
			}

			selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatal("Expected SELECT statement")
			}

			// Verify WITH clause exists
			if selectStmt.With == nil {
				t.Fatal("Expected WITH clause")
			}

			// Verify one CTE
			if len(selectStmt.With.CTEs) != 1 {
				t.Fatalf("Expected 1 CTE, got %d", len(selectStmt.With.CTEs))
			}

			cte := selectStmt.With.CTEs[0]

			// Verify materialized flag
			if tt.materialized == nil {
				if cte.Materialized != nil {
					t.Errorf("Expected nil Materialized, got %v", *cte.Materialized)
				}
			} else {
				if cte.Materialized == nil {
					t.Errorf("Expected Materialized=%v, got nil", *tt.materialized)
				} else if *cte.Materialized != *tt.materialized {
					t.Errorf("Expected Materialized=%v, got %v", *tt.materialized, *cte.Materialized)
				}
			}
		})
	}
}

// Note: boolPtr helper is defined in ddl_test.go
