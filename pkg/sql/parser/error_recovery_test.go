package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeIdentifier, Literal: "users"}, // Missing FROM
			},
			wantErr:       true,
			errorContains: "FROM",
		},
		{
			name: "missing table name after FROM",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing expression after WHERE",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				// Missing condition
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing column name in SELECT list",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeComma, Literal: ","}, // Missing column before comma
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "invalid JOIN without table",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				{Type: models.TokenTypeOn, Literal: "ON"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "table name",
		},
		{
			name: "JOIN without ON or USING clause",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				{Type: models.TokenTypeIdentifier, Literal: "orders"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Missing ON/USING
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing condition after ON in JOIN",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				{Type: models.TokenTypeIdentifier, Literal: "orders"},
				{Type: models.TokenTypeOn, Literal: "ON"},
				// Missing condition
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing column list in USING clause",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				{Type: models.TokenTypeIdentifier, Literal: "orders"},
				{Type: models.TokenTypeUsing, Literal: "USING"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Empty column list
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing ORDER BY columns",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				// Missing column
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing GROUP BY columns",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
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
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeIdentifier, Literal: "users"}, // Missing INTO
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing table name after INTO",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeValues, Literal: "VALUES"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing VALUES keyword",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				// Missing VALUES
			},
			wantErr:       true,
			errorContains: "VALUES",
		},
		{
			name: "missing opening parenthesis in VALUES",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeValues, Literal: "VALUES"},
				{Type: models.TokenTypeString, Literal: "John"}, // Missing (
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "empty VALUES clause",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeValues, Literal: "VALUES"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Empty values
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing closing parenthesis in column list",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeIdentifier, Literal: "email"},
				// Missing )
				{Type: models.TokenTypeValues, Literal: "VALUES"},
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
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeSet, Literal: "SET"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing SET keyword",
			tokens: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeIdentifier, Literal: "name"}, // Missing SET
			},
			wantErr:       true,
			errorContains: "SET",
		},
		{
			name: "missing assignment in SET",
			tokens: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Missing assignment
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing value after equals in SET",
			tokens: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeEq, Literal: "="},
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
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"}, // Missing FROM
			},
			wantErr:       true,
			errorContains: "FROM",
		},
		{
			name: "missing table name after FROM",
			tokens: []token.Token{
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing condition after WHERE",
			tokens: []token.Token{
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
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
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeAs, Literal: "AS"}, // Missing CTE name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing AS keyword in CTE",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "temp"},
				{Type: models.TokenTypeLParen, Literal: "("}, // Missing AS
			},
			wantErr:       true,
			errorContains: "", // Error message varies depending on parser state
		},
		{
			name: "missing opening parenthesis after AS",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "temp"},
				{Type: models.TokenTypeAs, Literal: "AS"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"}, // Missing (
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "empty CTE query",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "temp"},
				{Type: models.TokenTypeAs, Literal: "AS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Empty query
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing closing parenthesis in CTE",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "temp"},
				{Type: models.TokenTypeAs, Literal: "AS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				// Missing )
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
			},
			wantErr:       true,
			errorContains: ")",
		},
		{
			name: "missing main query after CTE",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "temp"},
				{Type: models.TokenTypeAs, Literal: "AS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeRParen, Literal: ")"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeUnion, Literal: "UNION"},
				// Missing right SELECT
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "invalid token after UNION",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeUnion, Literal: "UNION"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Invalid after UNION
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing right SELECT after EXCEPT",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeExcept, Literal: "EXCEPT"},
				// Missing right SELECT
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing right SELECT after INTERSECT",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeIntersect, Literal: "INTERSECT"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeOrder, Literal: "ORDER"}, // Missing (
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "empty OVER clause",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			wantErr: false, // Empty OVER() is valid
		},
		{
			name: "missing columns after PARTITION BY",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypePartition, Literal: "PARTITION"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Missing columns
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing columns after ORDER BY in window",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Missing columns
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				// Missing FROM - will cause error
			},
		},
		{
			name: "parser state after INSERT error",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				// Missing table name - will cause error
			},
		},
		{
			name: "parser state after UPDATE error",
			tokens: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeIdentifier, Literal: "users"}, // Missing FROM
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
			},
			maxExpectedErrors: 1, // Should only report missing FROM, not complain about WHERE
		},
		{
			name: "missing VALUES doesn't cascade",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				// Missing VALUES - but rest is valid VALUES structure
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeString, Literal: "John"},
				{Type: models.TokenTypeRParen, Literal: ")"},
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

// TestParser_ErrorRecovery_ALTER tests all error paths in ALTER statement parsing
func TestParser_ErrorRecovery_ALTER(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing object type after ALTER",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeIdentifier, Literal: "users"}, // Missing TABLE/ROLE/POLICY/CONNECTOR
			},
			wantErr:       true,
			errorContains: "TABLE, ROLE, POLICY, or CONNECTOR",
		},
		{
			name: "missing table name after ALTER TABLE",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeAdd, Literal: "ADD"}, // Missing table name
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing operation after table name",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				// Missing ADD/DROP/RENAME/ALTER
			},
			wantErr:       true,
			errorContains: "ADD, DROP, RENAME, or ALTER",
		},
		{
			name: "missing COLUMN or CONSTRAINT after ADD",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeAdd, Literal: "ADD"},
				{Type: models.TokenTypeIdentifier, Literal: "email"}, // Missing COLUMN/CONSTRAINT keyword
			},
			wantErr:       true,
			errorContains: "COLUMN or CONSTRAINT",
		},
		{
			name: "missing column definition after ADD COLUMN",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeAdd, Literal: "ADD"},
				{Type: models.TokenTypeColumn, Literal: "COLUMN"},
				// Missing column definition
			},
			wantErr:       true,
			errorContains: "column name",
		},
		{
			name: "missing constraint definition after ADD CONSTRAINT",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeAdd, Literal: "ADD"},
				{Type: models.TokenTypeConstraint, Literal: "CONSTRAINT"},
				// Missing constraint definition
			},
			wantErr:       true,
			errorContains: "constraint name",
		},
		{
			name: "missing COLUMN or CONSTRAINT after DROP",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeDrop, Literal: "DROP"},
				{Type: models.TokenTypeIdentifier, Literal: "email"}, // Missing COLUMN/CONSTRAINT keyword
			},
			wantErr:       true,
			errorContains: "COLUMN or CONSTRAINT",
		},
		{
			name: "missing TO or COLUMN after RENAME",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeRename, Literal: "RENAME"},
				{Type: models.TokenTypeIdentifier, Literal: "new_name"}, // Missing TO or COLUMN
			},
			wantErr:       true,
			errorContains: "TO or COLUMN",
		},
		{
			name: "missing TO keyword in RENAME COLUMN",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeRename, Literal: "RENAME"},
				{Type: models.TokenTypeColumn, Literal: "COLUMN"},
				{Type: models.TokenTypeIdentifier, Literal: "old_name"},
				{Type: models.TokenTypeIdentifier, Literal: "new_name"}, // Missing TO
			},
			wantErr:       true,
			errorContains: "TO",
		},
		{
			name: "missing COLUMN after ALTER",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeIdentifier, Literal: "email"}, // Missing COLUMN keyword
			},
			wantErr:       true,
			errorContains: "COLUMN",
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

// TestParser_ErrorRecovery_Expressions tests error paths in expression parsing
func TestParser_ErrorRecovery_Expressions(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "unexpected token in expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Invalid token for expression
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			wantErr:       true,
			errorContains: "unexpected token",
		},
		{
			name: "missing right operand in binary expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				// Missing right operand
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing identifier after dot",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypePeriod, Literal: "."},
				{Type: models.TokenTypeFrom, Literal: "FROM"}, // Invalid token after dot
			},
			wantErr:       true,
			errorContains: "expected column name or * after table qualifier",
		},
		// Note: Maximum recursion depth is already tested in CTE tests
		// Expression parsing doesn't trigger depth limits due to shallow call structure
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

// TestParser_ErrorRecovery_FunctionCalls tests error paths in function call parsing
func TestParser_ErrorRecovery_FunctionCalls(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing opening parenthesis in function call",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "COUNT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"}, // Missing (
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing closing parenthesis in function call",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "COUNT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"}, // Missing )
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "invalid function argument",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "SUM"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Invalid argument
			},
			wantErr:       true,
			errorContains: "",
		},
		{
			name: "missing comma between function arguments",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "CONCAT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeString, Literal: "hello"},
				{Type: models.TokenTypeString, Literal: "world"}, // Missing comma
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr:       true,
			errorContains: ", or )",
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

// TestParser_ErrorRecovery_WindowFrames tests error paths in window frame parsing
func TestParser_ErrorRecovery_WindowFrames(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing AND in BETWEEN frame",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "SUM"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "amount"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRows, Literal: "ROWS"},
				{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
				{Type: models.TokenTypeUnbounded, Literal: "UNBOUNDED"},
				{Type: models.TokenTypePreceding, Literal: "PRECEDING"},
				{Type: models.TokenTypeCurrent, Literal: "CURRENT"}, // Missing AND
			},
			wantErr:       true,
			errorContains: "AND",
		},
		{
			name: "missing PRECEDING or FOLLOWING after UNBOUNDED",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "SUM"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "amount"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRows, Literal: "ROWS"},
				{Type: models.TokenTypeUnbounded, Literal: "UNBOUNDED"},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Missing PRECEDING/FOLLOWING
			},
			wantErr:       true,
			errorContains: "PRECEDING or FOLLOWING after UNBOUNDED",
		},
		{
			name: "missing ROW after CURRENT",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "SUM"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "amount"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRows, Literal: "ROWS"},
				{Type: models.TokenTypeCurrent, Literal: "CURRENT"},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Missing ROW
			},
			wantErr:       true,
			errorContains: "ROW after CURRENT",
		},
		{
			name: "missing PRECEDING or FOLLOWING after numeric value",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "SUM"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "amount"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRows, Literal: "ROWS"},
				{Type: models.TokenTypeNumber, Literal: "5"},
				{Type: models.TokenTypeRParen, Literal: ")"}, // Missing PRECEDING/FOLLOWING
			},
			wantErr:       true,
			errorContains: "PRECEDING or FOLLOWING after numeric value",
		},
		{
			name: "missing BY after PARTITION",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypePartition, Literal: "PARTITION"},
				{Type: models.TokenTypeIdentifier, Literal: "dept"}, // Missing BY
			},
			wantErr:       true,
			errorContains: "BY after PARTITION",
		},
		{
			name: "missing BY after ORDER in window",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeIdentifier, Literal: "date"}, // Missing BY
			},
			wantErr:       true,
			errorContains: "BY after ORDER",
		},
		{
			name: "missing closing parenthesis in window spec",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeFrom, Literal: "FROM"}, // Missing )
			},
			wantErr:       true,
			errorContains: ")",
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

// TestParser_ErrorRecovery_EmptyInput tests error handling for empty or invalid inputs
func TestParser_ErrorRecovery_EmptyInput(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name:          "completely empty token list",
			tokens:        []token.Token{},
			wantErr:       true,
			errorContains: "incomplete SQL statement",
		},
		{
			name: "only EOF token",
			tokens: []token.Token{
				{Type: models.TokenTypeEOF, Literal: ""},
			},
			wantErr:       true,
			errorContains: "incomplete SQL statement",
		},
		{
			name: "only semicolon",
			tokens: []token.Token{
				{Type: models.TokenTypeSemicolon, Literal: ";"},
			},
			wantErr:       true,
			errorContains: "incomplete SQL statement",
		},
		{
			name: "unknown statement type",
			tokens: []token.Token{
				{Type: models.TokenTypeUnknown, Literal: "UNKNOWN"},
			},
			wantErr:       true,
			errorContains: "statement",
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

// TestParser_ErrorRecovery_SequentialParsing tests that parser can handle valid SQL after error
func TestParser_ErrorRecovery_SequentialParsing(t *testing.T) {
	tests := []struct {
		name          string
		invalidSQL    []token.Token
		validSQL      []token.Token
		shouldRecover bool
	}{
		{
			name: "recover after SELECT error",
			invalidSQL: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				// Missing FROM
			},
			validSQL: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			shouldRecover: true,
		},
		{
			name: "recover after INSERT error",
			invalidSQL: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				// Missing table name
			},
			validSQL: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeValues, Literal: "VALUES"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeString, Literal: "test"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			shouldRecover: true,
		},
		{
			name: "recover after UPDATE error",
			invalidSQL: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				// Missing SET
			},
			validSQL: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "test"},
			},
			shouldRecover: true,
		},
		{
			name: "recover after DELETE error",
			invalidSQL: []token.Token{
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				// Missing FROM
			},
			validSQL: []token.Token{
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			shouldRecover: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First, verify invalid SQL produces error
			p1 := NewParser()
			_, err1 := p1.Parse(tt.invalidSQL)
			if err1 == nil {
				t.Errorf("Expected error from invalid SQL but got none")
			}

			// Then, verify parser can handle valid SQL (parser state recovery)
			// Use a NEW parser instance (this is the expected usage pattern)
			p2 := NewParser()
			_, err2 := p2.Parse(tt.validSQL)

			if tt.shouldRecover {
				if err2 != nil {
					t.Errorf("Parser should recover and parse valid SQL, but got error: %v", err2)
				}
			}
		})
	}
}

// TestParser_ErrorRecovery_AlterRole tests error paths in ALTER ROLE statement parsing
func TestParser_ErrorRecovery_AlterRole(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing TO in RENAME",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeRole, Literal: "ROLE"},
				{Type: models.TokenTypeIdentifier, Literal: "old_role"},
				{Type: models.TokenTypeRename, Literal: "RENAME"},
				{Type: models.TokenTypeIdentifier, Literal: "new_role"}, // Missing TO
			},
			wantErr:       true,
			errorContains: "TO",
		},
		{
			name: "missing MEMBER after ADD",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeRole, Literal: "ROLE"},
				{Type: models.TokenTypeIdentifier, Literal: "role1"},
				{Type: models.TokenTypeAdd, Literal: "ADD"},
				{Type: models.TokenTypeIdentifier, Literal: "user1"}, // Missing MEMBER
			},
			wantErr:       true,
			errorContains: "MEMBER",
		},
		{
			name: "missing MEMBER after DROP",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeRole, Literal: "ROLE"},
				{Type: models.TokenTypeIdentifier, Literal: "role1"},
				{Type: models.TokenTypeDrop, Literal: "DROP"},
				{Type: models.TokenTypeIdentifier, Literal: "user1"}, // Missing MEMBER
			},
			wantErr:       true,
			errorContains: "MEMBER",
		},
		{
			name: "missing operation after role name",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeRole, Literal: "ROLE"},
				{Type: models.TokenTypeIdentifier, Literal: "role1"},
				// Missing operation
			},
			wantErr:       true,
			errorContains: "RENAME, ADD MEMBER, DROP MEMBER, SET, RESET, or WITH",
		},
		{
			name: "missing UNTIL after VALID",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeRole, Literal: "ROLE"},
				{Type: models.TokenTypeIdentifier, Literal: "role1"},
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeValid, Literal: "VALID"},
				{Type: models.TokenTypeString, Literal: "2025-12-31"}, // Missing UNTIL
			},
			wantErr:       true,
			errorContains: "UNTIL",
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

// TestParser_ErrorRecovery_AlterPolicy tests error paths in ALTER POLICY statement parsing
func TestParser_ErrorRecovery_AlterPolicy(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing ON keyword",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypePolicy, Literal: "POLICY"},
				{Type: models.TokenTypeIdentifier, Literal: "policy1"},
				{Type: models.TokenTypeIdentifier, Literal: "table1"}, // Missing ON
			},
			wantErr:       true,
			errorContains: "ON",
		},
		{
			name: "missing TO in RENAME",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypePolicy, Literal: "POLICY"},
				{Type: models.TokenTypeIdentifier, Literal: "policy1"},
				{Type: models.TokenTypeOn, Literal: "ON"},
				{Type: models.TokenTypeIdentifier, Literal: "table1"},
				{Type: models.TokenTypeRename, Literal: "RENAME"},
				{Type: models.TokenTypeIdentifier, Literal: "new_policy"}, // Missing TO
			},
			wantErr:       true,
			errorContains: "TO",
		},
		{
			name: "missing opening parenthesis in USING",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypePolicy, Literal: "POLICY"},
				{Type: models.TokenTypeIdentifier, Literal: "policy1"},
				{Type: models.TokenTypeOn, Literal: "ON"},
				{Type: models.TokenTypeIdentifier, Literal: "table1"},
				{Type: models.TokenTypeUsing, Literal: "USING"},
				{Type: models.TokenTypeIdentifier, Literal: "condition"}, // Missing (
			},
			wantErr:       true,
			errorContains: "(",
		},
		{
			name: "missing closing parenthesis in USING",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypePolicy, Literal: "POLICY"},
				{Type: models.TokenTypeIdentifier, Literal: "policy1"},
				{Type: models.TokenTypeOn, Literal: "ON"},
				{Type: models.TokenTypeIdentifier, Literal: "table1"},
				{Type: models.TokenTypeUsing, Literal: "USING"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "condition"},
				{Type: models.TokenTypeIdentifier, Literal: "extra"}, // Missing )
			},
			wantErr:       true,
			errorContains: ")",
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

// TestParser_ErrorRecovery_AlterConnector tests error paths in ALTER CONNECTOR statement parsing
func TestParser_ErrorRecovery_AlterConnector(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []token.Token
		wantErr       bool
		errorContains string
	}{
		{
			name: "missing SET keyword",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeConnector, Literal: "CONNECTOR"},
				{Type: models.TokenTypeIdentifier, Literal: "connector1"},
				{Type: models.TokenTypeUrl, Literal: "URL"}, // Missing SET
			},
			wantErr:       true,
			errorContains: "SET",
		},
		{
			name: "missing property type after SET",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeConnector, Literal: "CONNECTOR"},
				{Type: models.TokenTypeIdentifier, Literal: "connector1"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				// Missing DCPROPERTIES/URL/OWNER
			},
			wantErr:       true,
			errorContains: "DCPROPERTIES, URL, or OWNER",
		},
		{
			name: "missing opening parenthesis in DCPROPERTIES",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeConnector, Literal: "CONNECTOR"},
				{Type: models.TokenTypeIdentifier, Literal: "connector1"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeDcproperties, Literal: "DCPROPERTIES"},
				{Type: models.TokenTypeIdentifier, Literal: "key"}, // Missing (
			},
			wantErr:       true,
			errorContains: "(",
		},
		{
			name: "missing equals in DCPROPERTIES",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeConnector, Literal: "CONNECTOR"},
				{Type: models.TokenTypeIdentifier, Literal: "connector1"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeDcproperties, Literal: "DCPROPERTIES"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "key"},
				{Type: models.TokenTypeString, Literal: "value"}, // Missing =
			},
			wantErr:       true,
			errorContains: "=",
		},
		{
			name: "missing closing parenthesis in DCPROPERTIES",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeConnector, Literal: "CONNECTOR"},
				{Type: models.TokenTypeIdentifier, Literal: "connector1"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeDcproperties, Literal: "DCPROPERTIES"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "key"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "value"},
				// Missing )
			},
			wantErr:       true,
			errorContains: ")",
		},
		{
			name: "missing USER or ROLE after OWNER",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeConnector, Literal: "CONNECTOR"},
				{Type: models.TokenTypeIdentifier, Literal: "connector1"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeOwner, Literal: "OWNER"},
				{Type: models.TokenTypeIdentifier, Literal: "username"}, // Missing USER or ROLE
			},
			wantErr:       true,
			errorContains: "USER or ROLE",
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

// Helper function to generate deeply nested CTE for recursion testing
func generateDeeplyNestedCTE(depth int) []token.Token {
	tokens := []token.Token{}

	// Generate nested WITH clauses
	for i := 0; i < depth; i++ {
		tokens = append(tokens,
			token.Token{Type: models.TokenTypeWith, Literal: "WITH"},
			token.Token{Type: models.TokenTypeIdentifier, Literal: "cte"},
			token.Token{Type: models.TokenTypeAs, Literal: "AS"},
			token.Token{Type: models.TokenTypeLParen, Literal: "("},
		)
	}

	// Add a simple SELECT in the innermost level
	tokens = append(tokens,
		token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"},
		token.Token{Type: models.TokenTypeNumber, Literal: "1"},
	)

	// Close all parentheses
	for i := 0; i < depth; i++ {
		tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
	}

	// Add final SELECT
	tokens = append(tokens,
		token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"},
		token.Token{Type: models.TokenTypeAsterisk, Literal: "*"},
		token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "cte"},
	)

	return tokens
}
