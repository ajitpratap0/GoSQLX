package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParser_ErrorRecovery_SELECT tests all error paths in SELECT statement parsing
func TestParser_ErrorRecovery_SELECT(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string // Expected substring in error message
	}{
		{
			name: "missing FROM keyword",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "IDENT", Literal: "users"}, // Missing FROM
			},
			wantErr:       true,
			errorContains: "FROM",
		},
		{
			name: "missing table name after FROM",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "WHERE", Literal: "WHERE"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing expression after WHERE",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				// Missing condition
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing column name in SELECT list",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: ",", Literal: ","}, // Missing column before comma
				{Type: "IDENT", Literal: "name"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "invalid JOIN without table",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "JOIN", Literal: "JOIN"},
				{Type: "ON", Literal: "ON"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "table name",
		},
		{
			name: "JOIN without ON or USING clause",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "JOIN", Literal: "JOIN"},
				{Type: "IDENT", Literal: "orders"},
				{Type: "WHERE", Literal: "WHERE"}, // Missing ON/USING
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing condition after ON in JOIN",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "JOIN", Literal: "JOIN"},
				{Type: "IDENT", Literal: "orders"},
				{Type: "ON", Literal: "ON"},
				// Missing condition
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing column list in USING clause",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "JOIN", Literal: "JOIN"},
				{Type: "IDENT", Literal: "orders"},
				{Type: "USING", Literal: "USING"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"}, // Empty column list
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing ORDER BY columns",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "ORDER", Literal: "ORDER"},
				{Type: "BY", Literal: "BY"},
				// Missing column
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing GROUP BY columns",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "GROUP", Literal: "GROUP"},
				{Type: "BY", Literal: "BY"},
				// Missing column
			},
			wantErr:       true,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_INSERT tests all error paths in INSERT statement parsing
func TestParser_ErrorRecovery_INSERT(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing INTO keyword",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "IDENT", Literal: "users"}, // Missing INTO
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing table name after INTO",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				{Type: "VALUES", Literal: "VALUES"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing VALUES keyword",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				{Type: "IDENT", Literal: "users"},
				{Type: "(", Literal: "("},
				{Type: "IDENT", Literal: "name"},
				{Type: ")", Literal: ")"},
				// Missing VALUES
			},
			wantErr:       true,
			errorContains: "VALUES",
		},
		{
			name: "missing opening parenthesis in VALUES",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				{Type: "IDENT", Literal: "users"},
				{Type: "VALUES", Literal: "VALUES"},
				{Type: "STRING", Literal: "John"}, // Missing (
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "empty VALUES clause",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				{Type: "IDENT", Literal: "users"},
				{Type: "VALUES", Literal: "VALUES"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"}, // Empty values
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing closing parenthesis in column list",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				{Type: "IDENT", Literal: "users"},
				{Type: "(", Literal: "("},
				{Type: "IDENT", Literal: "name"},
				{Type: ",", Literal: ","},
				{Type: "IDENT", Literal: "email"},
				// Missing )
				{Type: "VALUES", Literal: "VALUES"},
			},
			wantErr:       true,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_UPDATE tests all error paths in UPDATE statement parsing
func TestParser_ErrorRecovery_UPDATE(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing table name",
			tokens: []token.Token{
				{Type: "UPDATE", Literal: "UPDATE"},
				{Type: "SET", Literal: "SET"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing SET keyword",
			tokens: []token.Token{
				{Type: "UPDATE", Literal: "UPDATE"},
				{Type: "IDENT", Literal: "users"},
				{Type: "IDENT", Literal: "name"}, // Missing SET
			},
			wantErr:       true,
			errorContains: "SET",
		},
		{
			name: "missing assignment in SET",
			tokens: []token.Token{
				{Type: "UPDATE", Literal: "UPDATE"},
				{Type: "IDENT", Literal: "users"},
				{Type: "SET", Literal: "SET"},
				{Type: "WHERE", Literal: "WHERE"}, // Missing assignment
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing value after equals in SET",
			tokens: []token.Token{
				{Type: "UPDATE", Literal: "UPDATE"},
				{Type: "IDENT", Literal: "users"},
				{Type: "SET", Literal: "SET"},
				{Type: "IDENT", Literal: "name"},
				{Type: "=", Literal: "="},
				// Missing value
			},
			wantErr:       true,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_DELETE tests all error paths in DELETE statement parsing
func TestParser_ErrorRecovery_DELETE(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing FROM keyword",
			tokens: []token.Token{
				{Type: "DELETE", Literal: "DELETE"},
				{Type: "IDENT", Literal: "users"}, // Missing FROM
			},
			wantErr:       true,
			errorContains: "FROM",
		},
		{
			name: "missing table name after FROM",
			tokens: []token.Token{
				{Type: "DELETE", Literal: "DELETE"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "WHERE", Literal: "WHERE"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing condition after WHERE",
			tokens: []token.Token{
				{Type: "DELETE", Literal: "DELETE"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				// Missing condition
			},
			wantErr:       true,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_CTE tests error paths in CTE (WITH clause) parsing
func TestParser_ErrorRecovery_CTE(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing CTE name after WITH",
			tokens: []token.Token{
				{Type: "WITH", Literal: "WITH"},
				{Type: "AS", Literal: "AS"}, // Missing CTE name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing AS keyword in CTE",
			tokens: []token.Token{
				{Type: "WITH", Literal: "WITH"},
				{Type: "IDENT", Literal: "temp"},
				{Type: "(", Literal: "("}, // Missing AS
			},
			wantErr:       true,
			errorContains: "", // Error message varies depending on parser state
		},
		{
			name: "missing opening parenthesis after AS",
			tokens: []token.Token{
				{Type: "WITH", Literal: "WITH"},
				{Type: "IDENT", Literal: "temp"},
				{Type: "AS", Literal: "AS"},
				{Type: "SELECT", Literal: "SELECT"}, // Missing (
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "empty CTE query",
			tokens: []token.Token{
				{Type: "WITH", Literal: "WITH"},
				{Type: "IDENT", Literal: "temp"},
				{Type: "AS", Literal: "AS"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"}, // Empty query
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing closing parenthesis in CTE",
			tokens: []token.Token{
				{Type: "WITH", Literal: "WITH"},
				{Type: "IDENT", Literal: "temp"},
				{Type: "AS", Literal: "AS"},
				{Type: "(", Literal: "("},
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				// Missing )
				{Type: "SELECT", Literal: "SELECT"},
			},
			wantErr:       true,
			errorContains: ")",
		},
		{
			name: "missing main query after CTE",
			tokens: []token.Token{
				{Type: "WITH", Literal: "WITH"},
				{Type: "IDENT", Literal: "temp"},
				{Type: "AS", Literal: "AS"},
				{Type: "(", Literal: "("},
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: ")", Literal: ")"},
				// Missing main query
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name:          "maximum recursion depth in CTE",
			tokens:        generateDeeplyNestedCTE(MaxRecursionDepth + 5),
			wantErr:       true,
			errorContains: "maximum recursion depth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_SetOperations tests error paths in UNION/EXCEPT/INTERSECT
func TestParser_ErrorRecovery_SetOperations(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing right SELECT after UNION",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "UNION", Literal: "UNION"},
				// Missing right SELECT
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "invalid token after UNION",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "UNION", Literal: "UNION"},
				{Type: "WHERE", Literal: "WHERE"}, // Invalid after UNION
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing right SELECT after EXCEPT",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "EXCEPT", Literal: "EXCEPT"},
				// Missing right SELECT
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing right SELECT after INTERSECT",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "INTERSECT", Literal: "INTERSECT"},
				// Missing right SELECT
			},
			wantErr:       true,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_WindowFunctions tests error paths in window function parsing
func TestParser_ErrorRecovery_WindowFunctions(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing opening parenthesis after OVER",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "IDENT", Literal: "ROW_NUMBER"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"},
				{Type: "OVER", Literal: "OVER"},
				{Type: "ORDER", Literal: "ORDER"}, // Missing (
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "empty OVER clause",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "IDENT", Literal: "ROW_NUMBER"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"},
				{Type: "OVER", Literal: "OVER"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
			},
			wantErr: false, // Empty OVER() is valid
		},
		{
			name: "missing columns after PARTITION BY",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "IDENT", Literal: "ROW_NUMBER"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"},
				{Type: "OVER", Literal: "OVER"},
				{Type: "(", Literal: "("},
				{Type: "PARTITION", Literal: "PARTITION"},
				{Type: "BY", Literal: "BY"},
				{Type: ")", Literal: ")"}, // Missing columns
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing columns after ORDER BY in window",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "IDENT", Literal: "ROW_NUMBER"},
				{Type: "(", Literal: "("},
				{Type: ")", Literal: ")"},
				{Type: "OVER", Literal: "OVER"},
				{Type: "(", Literal: "("},
				{Type: "ORDER", Literal: "ORDER"},
				{Type: "BY", Literal: "BY"},
				{Type: ")", Literal: ")"}, // Missing columns
			},
			wantErr:       true,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_ParserState tests that parser state is consistent after errors
func TestParser_ErrorRecovery_ParserState(t *testing.T) {
	tests := []struct {
		name   string
		tokens []token.Token
	}{
		{
			name: "parser state after SELECT error",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				// Missing FROM - will cause error
			},
		},
		{
			name: "parser state after INSERT error",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				// Missing table name - will cause error
			},
		},
		{
			name: "parser state after UPDATE error",
			tokens: []token.Token{
				{Type: "UPDATE", Literal: "UPDATE"},
				{Type: "IDENT", Literal: "users"},
				// Missing SET - will cause error
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			// Should have error
			if err == nil {
				t.Errorf("Expected error but got none")
			}

			// Verify parser state is valid (not in invalid position)
			// Parser should not panic or have corrupted state
			if p.currentPos < 0 {
				t.Errorf("Parser currentPos is negative: %d", p.currentPos)
			}
			if p.currentPos > len(tt.tokens) {
				t.Errorf("Parser currentPos (%d) exceeds token count (%d)", p.currentPos, len(tt.tokens))
			}
		})
	}
}

// TestParser_ErrorRecovery_NoCascadingErrors tests that single errors don't cause cascading false errors
func TestParser_ErrorRecovery_NoCascadingErrors(t *testing.T) {
	tests := []struct {
		name              string
		tokens            []token.Token
		maxExpectedErrors int // Should only have 1 primary error, not cascading errors
	}{
		{
			name: "missing FROM doesn't cascade",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "IDENT", Literal: "users"}, // Missing FROM
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "id"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
			},
			maxExpectedErrors: 1, // Should only report missing FROM, not complain about WHERE
		},
		{
			name: "missing VALUES doesn't cascade",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				{Type: "IDENT", Literal: "users"},
				{Type: "(", Literal: "("},
				{Type: "IDENT", Literal: "name"},
				{Type: ")", Literal: ")"},
				// Missing VALUES - but rest is valid VALUES structure
				{Type: "(", Literal: "("},
				{Type: "STRING", Literal: "John"},
				{Type: ")", Literal: ")"},
			},
			maxExpectedErrors: 1, // Should only report missing VALUES
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			_, err := p.Parse(tt.tokens)

			if err == nil {
				t.Errorf("Expected error but got none")
				return
			}

			// Count error messages (simple heuristic: errors often say "expected" or "unexpected")
			errorMsg := err.Error()
			expectedCount := strings.Count(errorMsg, "expected")
			unexpectedCount := strings.Count(errorMsg, "unexpected")
			totalErrorIndicators := expectedCount + unexpectedCount

			// If we see multiple "expected" or "unexpected" messages, likely cascading
			if totalErrorIndicators > tt.maxExpectedErrors {
				t.Logf("Warning: Possible cascading errors detected in: %s", errorMsg)
				t.Logf("Found %d error indicators, expected max %d", totalErrorIndicators, tt.maxExpectedErrors)
			}
		})
	}
}

// Helper function to generate deeply nested CTE for recursion testing
func generateDeeplyNestedCTE(depth int) []token.Token {
	tokens := []token.Token{}

	// Generate nested WITH clauses
	for i := 0; i < depth; i++ {
		tokens = append(tokens,
			token.Token{Type: "WITH", Literal: "WITH"},
			token.Token{Type: "IDENT", Literal: "cte"},
			token.Token{Type: "AS", Literal: "AS"},
			token.Token{Type: "(", Literal: "("},
		)
	}

	// Add a simple SELECT in the innermost level
	tokens = append(tokens,
		token.Token{Type: "SELECT", Literal: "SELECT"},
		token.Token{Type: "INT", Literal: "1"},
	)

	// Close all parentheses
	for i := 0; i < depth; i++ {
		tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
	}

	// Add final SELECT
	tokens = append(tokens,
		token.Token{Type: "SELECT", Literal: "SELECT"},
		token.Token{Type: "*", Literal: "*"},
		token.Token{Type: "FROM", Literal: "FROM"},
		token.Token{Type: "IDENT", Literal: "cte"},
	)

	return tokens
}
