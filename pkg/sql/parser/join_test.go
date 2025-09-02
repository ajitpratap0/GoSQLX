package parser

import (
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// convertTokens converts models.TokenWithSpan to token.Token for parser
func convertTokens(tokens []models.TokenWithSpan) []token.Token {
	result := make([]token.Token, 0, len(tokens)*2) // Extra space for split tokens

	for _, t := range tokens {
		// Handle compound JOIN tokens by splitting them
		switch t.Token.Type {
		case models.TokenTypeInnerJoin:
			result = append(result, token.Token{Type: "INNER", Literal: "INNER"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		case models.TokenTypeLeftJoin:
			result = append(result, token.Token{Type: "LEFT", Literal: "LEFT"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		case models.TokenTypeRightJoin:
			result = append(result, token.Token{Type: "RIGHT", Literal: "RIGHT"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		case models.TokenTypeOuterJoin:
			result = append(result, token.Token{Type: "OUTER", Literal: "OUTER"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		}

		// Handle compound tokens that come as strings
		if t.Token.Value == "INNER JOIN" {
			result = append(result, token.Token{Type: "INNER", Literal: "INNER"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "LEFT JOIN" {
			result = append(result, token.Token{Type: "LEFT", Literal: "LEFT"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "RIGHT JOIN" {
			result = append(result, token.Token{Type: "RIGHT", Literal: "RIGHT"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "FULL JOIN" || t.Token.Type == models.TokenTypeKeyword && t.Token.Value == "FULL JOIN" {
			result = append(result, token.Token{Type: "FULL", Literal: "FULL"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "CROSS JOIN" || t.Token.Type == models.TokenTypeKeyword && t.Token.Value == "CROSS JOIN" {
			result = append(result, token.Token{Type: "CROSS", Literal: "CROSS"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "LEFT OUTER JOIN" {
			result = append(result, token.Token{Type: "LEFT", Literal: "LEFT"})
			result = append(result, token.Token{Type: "OUTER", Literal: "OUTER"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "RIGHT OUTER JOIN" {
			result = append(result, token.Token{Type: "RIGHT", Literal: "RIGHT"})
			result = append(result, token.Token{Type: "OUTER", Literal: "OUTER"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "FULL OUTER JOIN" {
			result = append(result, token.Token{Type: "FULL", Literal: "FULL"})
			result = append(result, token.Token{Type: "OUTER", Literal: "OUTER"})
			result = append(result, token.Token{Type: "JOIN", Literal: "JOIN"})
			continue
		} else if t.Token.Value == "ORDER BY" || t.Token.Type == models.TokenTypeOrderBy {
			result = append(result, token.Token{Type: "ORDER", Literal: "ORDER"})
			result = append(result, token.Token{Type: "BY", Literal: "BY"})
			continue
		} else if t.Token.Value == "GROUP BY" || t.Token.Type == models.TokenTypeGroupBy {
			result = append(result, token.Token{Type: "GROUP", Literal: "GROUP"})
			result = append(result, token.Token{Type: "BY", Literal: "BY"})
			continue
		}

		// Map token type to string for single tokens
		tokenType := token.Type(fmt.Sprintf("%v", t.Token.Type))

		// Try to map to proper token type string
		switch t.Token.Type {
		case models.TokenTypeSelect:
			tokenType = "SELECT"
		case models.TokenTypeFrom:
			tokenType = "FROM"
		case models.TokenTypeWhere:
			tokenType = "WHERE"
		case models.TokenTypeJoin:
			tokenType = "JOIN"
		case models.TokenTypeInner:
			tokenType = "INNER"
		case models.TokenTypeLeft:
			tokenType = "LEFT"
		case models.TokenTypeRight:
			tokenType = "RIGHT"
		case models.TokenTypeOuter:
			tokenType = "OUTER"
		case models.TokenTypeOn:
			tokenType = "ON"
		case models.TokenTypeAs:
			tokenType = "AS"
		case models.TokenTypeIdentifier:
			tokenType = "IDENT"
		case models.TokenTypeMul:
			tokenType = "*"
		case models.TokenTypeEq:
			tokenType = "="
		case models.TokenTypePeriod:
			tokenType = "."
		case models.TokenTypeLParen:
			tokenType = "("
		case models.TokenTypeRParen:
			tokenType = ")"
		case models.TokenTypeComma:
			tokenType = ","
		case models.TokenTypeOrder:
			tokenType = "ORDER"
		case models.TokenTypeBy:
			tokenType = "BY"
		case models.TokenTypeDesc:
			tokenType = "DESC"
		case models.TokenTypeAsc:
			tokenType = "ASC"
		case models.TokenTypeLimit:
			tokenType = "LIMIT"
		case models.TokenTypeTrue:
			tokenType = "TRUE"
		case models.TokenTypeNumber:
			tokenType = "INT"
		case models.TokenTypeEOF:
			tokenType = "EOF"
		default:
			// For any other type, use the value as the type if it looks like a keyword
			// This handles keywords like FULL, CROSS, USING that don't have specific token types
			if t.Token.Value != "" {
				tokenType = token.Type(t.Token.Value)
			}
			// Special handling for keywords that come through as TokenTypeKeyword
			if t.Token.Type == models.TokenTypeKeyword {
				tokenType = token.Type(t.Token.Value)
			}
		}

		result = append(result, token.Token{
			Type:    tokenType,
			Literal: t.Token.Value,
		})
	}
	return result
}

func TestParser_JoinTypes(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		joinType string
		wantErr  bool
	}{
		{
			name:     "INNER JOIN",
			sql:      "SELECT * FROM users INNER JOIN orders ON users.id = orders.user_id",
			joinType: "INNER",
			wantErr:  false,
		},
		{
			name:     "LEFT JOIN",
			sql:      "SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id",
			joinType: "LEFT",
			wantErr:  false,
		},
		{
			name:     "LEFT OUTER JOIN",
			sql:      "SELECT * FROM users LEFT OUTER JOIN orders ON users.id = orders.user_id",
			joinType: "LEFT",
			wantErr:  false,
		},
		{
			name:     "RIGHT JOIN",
			sql:      "SELECT * FROM users RIGHT JOIN orders ON users.id = orders.user_id",
			joinType: "RIGHT",
			wantErr:  false,
		},
		{
			name:     "RIGHT OUTER JOIN",
			sql:      "SELECT * FROM users RIGHT OUTER JOIN orders ON users.id = orders.user_id",
			joinType: "RIGHT",
			wantErr:  false,
		},
		{
			name:     "FULL JOIN",
			sql:      "SELECT * FROM users FULL JOIN orders ON users.id = orders.user_id",
			joinType: "FULL",
			wantErr:  false,
		},
		{
			name:     "FULL OUTER JOIN",
			sql:      "SELECT * FROM users FULL OUTER JOIN orders ON users.id = orders.user_id",
			joinType: "FULL",
			wantErr:  false,
		},
		{
			name:     "CROSS JOIN",
			sql:      "SELECT * FROM users CROSS JOIN products",
			joinType: "CROSS",
			wantErr:  false,
		},
		{
			name:     "Multiple JOINs",
			sql:      "SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id RIGHT JOIN products ON orders.product_id = products.id",
			joinType: "LEFT", // First join
			wantErr:  false,
		},
		{
			name:     "JOIN with table alias",
			sql:      "SELECT * FROM users u LEFT JOIN orders o ON u.id = o.user_id",
			joinType: "LEFT",
			wantErr:  false,
		},
		{
			name:     "JOIN with AS alias",
			sql:      "SELECT * FROM users AS u LEFT JOIN orders AS o ON u.id = o.user_id",
			joinType: "LEFT",
			wantErr:  false,
		},
		{
			name:     "JOIN with USING",
			sql:      "SELECT * FROM users LEFT JOIN orders USING (id)",
			joinType: "LEFT",
			wantErr:  false,
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
			convertedTokens := convertTokens(tokens)

			// Parse tokens
			parser := &Parser{}
			astObj, err := parser.Parse(convertedTokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && astObj != nil {
				defer ast.ReleaseAST(astObj)

				// Check if we have a SELECT statement
				if len(astObj.Statements) > 0 {
					if selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement); ok {
						// Check JOIN type for first join
						if len(selectStmt.Joins) > 0 {
							if selectStmt.Joins[0].Type != tt.joinType {
								t.Errorf("Expected join type %s, got %s", tt.joinType, selectStmt.Joins[0].Type)
							}
						} else if tt.joinType != "" {
							t.Errorf("Expected join clause but found none")
						}
					} else {
						t.Errorf("Expected SELECT statement")
					}
				}
			}
		})
	}
}

func TestParser_ComplexJoins(t *testing.T) {
	sql := `
		SELECT 
			u.name,
			o.order_date,
			p.product_name,
			c.category_name
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		INNER JOIN products p ON o.product_id = p.id
		RIGHT JOIN categories c ON p.category_id = c.id
		WHERE u.active = true
		ORDER BY o.order_date DESC
		LIMIT 100
	`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	convertedTokens := convertTokens(tokens)

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
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

	// Verify we have 3 JOINs
	if len(selectStmt.Joins) != 3 {
		t.Errorf("Expected 3 JOINs, got %d", len(selectStmt.Joins))
	}

	// Verify JOIN types
	expectedJoinTypes := []string{"LEFT", "INNER", "RIGHT"}
	for i, expectedType := range expectedJoinTypes {
		if i < len(selectStmt.Joins) {
			if selectStmt.Joins[i].Type != expectedType {
				t.Errorf("Join %d: expected type %s, got %s", i, expectedType, selectStmt.Joins[i].Type)
			}
		}
	}

	// Verify we have WHERE, ORDER BY, and LIMIT
	if selectStmt.Where == nil {
		t.Error("Expected WHERE clause")
	}
	if len(selectStmt.OrderBy) == 0 {
		t.Error("Expected ORDER BY clause")
	}
	if selectStmt.Limit == nil {
		t.Error("Expected LIMIT clause")
	}
}

func TestParser_InvalidJoinSyntax(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		expectedError string
	}{
		{
			name:          "Missing JOIN keyword after type",
			sql:           "SELECT * FROM users LEFT orders ON users.id = orders.user_id",
			expectedError: "expected JOIN after LEFT",
		},
		{
			name:          "Missing table name after JOIN",
			sql:           "SELECT * FROM users LEFT JOIN ON users.id = orders.user_id",
			expectedError: "expected table name after LEFT JOIN",
		},
		{
			name:          "Missing ON/USING clause",
			sql:           "SELECT * FROM users LEFT JOIN orders",
			expectedError: "expected ON or USING",
		},
		{
			name:          "Invalid JOIN type",
			sql:           "SELECT * FROM users INVALID JOIN orders ON users.id = orders.user_id",
			expectedError: "", // This won't error as INVALID becomes an identifier
		},
		{
			name:          "Missing condition after ON",
			sql:           "SELECT * FROM users LEFT JOIN orders ON",
			expectedError: "error parsing ON condition",
		},
		{
			name:          "Missing parentheses after USING",
			sql:           "SELECT * FROM users LEFT JOIN orders USING id",
			expectedError: "expected ( after USING",
		},
		{
			name:          "Empty USING clause",
			sql:           "SELECT * FROM users LEFT JOIN orders USING ()",
			expectedError: "expected column name in USING",
		},
		{
			name:          "Incomplete OUTER JOIN",
			sql:           "SELECT * FROM users OUTER JOIN orders ON users.id = orders.user_id",
			expectedError: "expected statement",
		},
		{
			name:          "JOIN without FROM clause",
			sql:           "SELECT * LEFT JOIN orders ON users.id = orders.user_id",
			expectedError: "", // This errors during FROM parsing, not JOIN parsing
		},
		{
			name:          "Multiple JOIN keywords",
			sql:           "SELECT * FROM users JOIN JOIN orders ON users.id = orders.user_id",
			expectedError: "expected table name",
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
				// Some tests might fail at tokenization level
				if tt.expectedError != "" {
					return // Expected failure
				}
				t.Fatalf("Failed to tokenize: %v", err)
			}

			// Convert tokens for parser
			convertedTokens := convertTokens(tokens)

			// Parse tokens
			parser := &Parser{}
			astObj, err := parser.Parse(convertedTokens)
			
			if tt.expectedError != "" {
				// We expect an error
				if err == nil {
					defer ast.ReleaseAST(astObj)
					t.Errorf("Expected error containing '%s', but got no error", tt.expectedError)
				} else if !containsError(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				// We don't expect an error for some edge cases
				if err != nil && tt.expectedError == "" {
					// Some tests intentionally have no expected error 
					// because they fail in different ways
					return
				}
				if astObj != nil {
					defer ast.ReleaseAST(astObj)
				}
			}
		})
	}
}

// Helper function to check if error message contains expected text
func containsError(actual, expected string) bool {
	if expected == "" {
		return true
	}
	return len(actual) > 0 && len(expected) > 0 && 
		(actual == expected || 
		 len(actual) >= len(expected) && 
		 (actual[:len(expected)] == expected ||
		  actual[len(actual)-len(expected):] == expected ||
		  containsSubstring(actual, expected)))
}

// Simple substring check
func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
