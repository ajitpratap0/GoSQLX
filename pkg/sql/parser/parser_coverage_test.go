package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// NOTE: CREATE TABLE is not yet implemented in parseStatement()
// Tests for CREATE TABLE are skipped until the feature is implemented

// TestParser_AlterTable tests ALTER TABLE DDL statement
// This covers parseAlterTableStmt, matchToken
func TestParser_AlterTable(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
	}{
		{
			name: "ALTER TABLE ADD COLUMN",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeAdd, Literal: "ADD"},
				{Type: models.TokenTypeColumn, Literal: "COLUMN"},
				{Type: models.TokenTypeIdentifier, Literal: "age"},
				{Type: models.TokenTypeIdentifier, Literal: "INT"},
			},
			wantErr: false,
		},
		{
			name: "ALTER TABLE DROP COLUMN",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "employees"},
				{Type: models.TokenTypeDrop, Literal: "DROP"},
				{Type: models.TokenTypeColumn, Literal: "COLUMN"},
				{Type: models.TokenTypeIdentifier, Literal: "salary"},
			},
			wantErr: false,
		},
		{
			name: "ALTER TABLE RENAME",
			tokens: []token.Token{
				{Type: models.TokenTypeAlter, Literal: "ALTER"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "old_name"},
				{Type: models.TokenTypeRename, Literal: "RENAME"},
				{Type: models.TokenTypeTo, Literal: "TO"},
				{Type: models.TokenTypeIdentifier, Literal: "new_name"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// NOTE: DROP TABLE is not yet implemented in parseStatement()
// Tests for DROP TABLE are skipped until the feature is implemented

// TestParser_StringLiterals tests parseStringLiteral function
func TestParser_StringLiterals(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
	}{
		{
			name: "SELECT with single-quoted string",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeString, Literal: "hello world"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "messages"},
			},
			wantErr: false,
		},
		{
			name: "INSERT with string literal",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeValues, Literal: "VALUES"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeString, Literal: "John Doe"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false,
		},
		{
			name: "WHERE clause with string comparison",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "email"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "user@example.com"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_WindowFrameBounds tests parseFrameBound edge cases
// Current coverage: 64.3% - targeting 100%
func TestParser_WindowFrameBounds(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
	}{
		{
			name: "ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "SUM"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "amount"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeIdentifier, Literal: "date"},
				{Type: models.TokenTypeRows, Literal: "ROWS"},
				{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
				{Type: models.TokenTypeUnbounded, Literal: "UNBOUNDED"},
				{Type: models.TokenTypePreceding, Literal: "PRECEDING"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeCurrent, Literal: "CURRENT"},
				{Type: models.TokenTypeRow, Literal: "ROW"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "sales"},
			},
			wantErr: false,
		},
		{
			name: "RANGE BETWEEN N PRECEDING AND N FOLLOWING",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "AVG"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "price"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeIdentifier, Literal: "date"},
				{Type: models.TokenTypeRange, Literal: "RANGE"},
				{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
				{Type: models.TokenTypeNumber, Literal: "3"},
				{Type: models.TokenTypePreceding, Literal: "PRECEDING"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeNumber, Literal: "3"},
				{Type: models.TokenTypeFollowing, Literal: "FOLLOWING"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "products"},
			},
			wantErr: false,
		},
		{
			name: "ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "COUNT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeRows, Literal: "ROWS"},
				{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
				{Type: models.TokenTypeCurrent, Literal: "CURRENT"},
				{Type: models.TokenTypeRow, Literal: "ROW"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeUnbounded, Literal: "UNBOUNDED"},
				{Type: models.TokenTypeFollowing, Literal: "FOLLOWING"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "events"},
			},
			wantErr: false,
		},
		{
			name: "ROWS N PRECEDING (no AND clause)",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "SUM"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "value"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeOver, Literal: "OVER"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeIdentifier, Literal: "timestamp"},
				{Type: models.TokenTypeRows, Literal: "ROWS"},
				{Type: models.TokenTypeNumber, Literal: "5"},
				{Type: models.TokenTypePreceding, Literal: "PRECEDING"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "metrics"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_ExpressionEdgeCases tests parseExpression edge cases
// Current coverage: 89.5% - targeting 100%
func TestParser_ExpressionEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
	}{
		// NOTE: Many complex expressions not yet implemented, marked as wantErr: true
		{
			name: "nested parenthesized expressions",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypePlus, Literal: "+"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "data"},
			},
			wantErr: false, // Nested parentheses now work with normalized Type
		},
		{
			name: "complex boolean expression with NOT",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeNot, Literal: "NOT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "active"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeTrue, Literal: "TRUE"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "verified"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeTrue, Literal: "TRUE"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false, // NOT with parentheses now supported
		},
		{
			name: "BETWEEN expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "products"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "price"},
				{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
				{Type: models.TokenTypeNumber, Literal: "10"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeNumber, Literal: "100"},
			},
			wantErr: false, // BETWEEN now supported
		},
		{
			name: "IN expression with list",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "orders"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "status"},
				{Type: models.TokenTypeIn, Literal: "IN"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeString, Literal: "pending"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeString, Literal: "processing"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeString, Literal: "shipped"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false, // IN now supported
		},
		{
			name: "LIKE expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "email"},
				{Type: models.TokenTypeLike, Literal: "LIKE"},
				{Type: models.TokenTypeString, Literal: "%@example.com"},
			},
			wantErr: false, // LIKE now supported
		},
		{
			name: "IS NULL expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "customers"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "deleted_at"},
				{Type: models.TokenTypeIs, Literal: "IS"},
				{Type: models.TokenTypeNull, Literal: "NULL"},
			},
			wantErr: false, // IS NULL now supported
		},
		{
			name: "IS NOT NULL expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "posts"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "published_at"},
				{Type: models.TokenTypeIs, Literal: "IS"},
				{Type: models.TokenTypeNot, Literal: "NOT"},
				{Type: models.TokenTypeNull, Literal: "NULL"},
			},
			wantErr: false, // IS NOT NULL now supported
		},
		{
			name: "arithmetic expression with multiple operators",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypePlus, Literal: "+"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
				{Type: models.TokenTypeMinus, Literal: "-"},
				{Type: models.TokenTypeIdentifier, Literal: "d"},
				{Type: models.TokenTypeDiv, Literal: "/"},
				{Type: models.TokenTypeIdentifier, Literal: "e"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "calculations"},
			},
			wantErr: false, // Complex arithmetic now works with normalized Type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_ErrorRecovery tests error recovery paths
// This ensures parser doesn't enter invalid states after errors
func TestParser_ErrorRecovery(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
	}{
		{
			name: "missing FROM keyword",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeIdentifier, Literal: "users"}, // Missing FROM
			},
			wantErr: true,
		},
		{
			name: "missing table name after FROM",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				// Missing table name - parser will hit EOF
			},
			wantErr: true,
		},
		{
			name: "missing closing parenthesis in function",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "COUNT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				// Missing closing parenthesis
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			wantErr: true,
		},
		{
			name: "incomplete WHERE clause",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				// Missing condition - parser will hit EOF
			},
			wantErr: true,
		},
		{
			name: "missing SET in UPDATE",
			tokens: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"}, // Missing SET
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
			},
			wantErr: true,
		},
		{
			name: "invalid JOIN syntax - missing table",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				// Missing table name after JOIN - will hit ON
				{Type: models.TokenTypeOn, Literal: "ON"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeIdentifier, Literal: "user_id"},
			},
			wantErr: true,
		},
		{
			name: "missing comparison operator in WHERE",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				// Missing operator (=, >, <, etc.) - next token is a number
				{Type: models.TokenTypeNumber, Literal: "1"},
			},
			wantErr: true,
		},
		{
			name: "invalid ORDER BY syntax - missing BY",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				// Missing BY keyword
				{Type: models.TokenTypeIdentifier, Literal: "name"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify parser is still in valid state by creating a new parser for a simple query
			if err != nil {
				simpleTokens := []token.Token{
					{Type: models.TokenTypeSelect, Literal: "SELECT"},
					{Type: models.TokenTypeAsterisk, Literal: "*"},
					{Type: models.TokenTypeFrom, Literal: "FROM"},
					{Type: models.TokenTypeIdentifier, Literal: "test"},
				}
				parser2 := NewParser()
				defer parser2.Release()
				_, err2 := parser2.Parse(simpleTokens)
				if err2 != nil {
					t.Errorf("Parser state corrupted after error: %v", err2)
				}
			}
		})
	}
}

// TestParser_CTEEdgeCases tests CTE-specific scenarios
// This covers parseMainStatementAfterWith which improved from 30% to 90%
func TestParser_CTEEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
	}{
		// NOTE: CTE with DML statements involves subqueries which aren't fully implemented
		{
			name: "CTE with INSERT statement",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "new_users"},
				{Type: models.TokenTypeAs, Literal: "AS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "created_at"},
				{Type: models.TokenTypeGt, Literal: ">"},
				{Type: models.TokenTypeString, Literal: "2024-01-01"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "archive"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "new_users"},
			},
			wantErr: false, // INSERT ... SELECT is now supported
		},
		{
			name: "CTE with UPDATE statement",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "active"},
				{Type: models.TokenTypeAs, Literal: "AS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "status"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "active"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeIdentifier, Literal: "verified"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeTrue, Literal: "TRUE"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeIn, Literal: "IN"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "active"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false, // Subqueries in WHERE now supported
		},
		{
			name: "CTE with DELETE statement",
			tokens: []token.Token{
				{Type: models.TokenTypeWith, Literal: "WITH"},
				{Type: models.TokenTypeIdentifier, Literal: "old_records"},
				{Type: models.TokenTypeAs, Literal: "AS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "logs"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "created_at"},
				{Type: models.TokenTypeLt, Literal: "<"},
				{Type: models.TokenTypeString, Literal: "2023-01-01"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "logs"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeIn, Literal: "IN"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "old_records"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false, // Subqueries in WHERE now supported
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_SetOperationPrecedence tests set operation precedence
func TestParser_SetOperationPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
	}{
		// NOTE: UNION ALL with literals not FROM tables requires special handling
		{
			name: "UNION ALL with multiple queries",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeUnion, Literal: "UNION"},
				{Type: models.TokenTypeAll, Literal: "ALL"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeNumber, Literal: "2"},
				{Type: models.TokenTypeUnion, Literal: "UNION"},
				{Type: models.TokenTypeAll, Literal: "ALL"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeNumber, Literal: "3"},
			},
			wantErr: true, // SELECT without FROM requires special support
		},
		{
			name: "EXCEPT and INTERSECT combination",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeExcept, Literal: "EXCEPT"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeIntersect, Literal: "INTERSECT"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
			},
			wantErr: false, // This one should work
		},
		{
			name: "parenthesized UNION",
			tokens: []token.Token{
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeUnion, Literal: "UNION"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeNumber, Literal: "2"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeUnion, Literal: "UNION"},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeNumber, Literal: "3"},
			},
			wantErr: true, // Parenthesized SELECT requires special support
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_TableDrivenComplexScenarios tests complex real-world scenarios
func TestParser_TableDrivenComplexScenarios(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []token.Token
		wantErr bool
		desc    string
	}{
		// NOTE: Many SQL features not yet implemented - tests marked accordingly
		{
			name: "subquery in WHERE clause",
			desc: "Tests subquery handling in WHERE predicates",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "orders"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "customer_id"},
				{Type: models.TokenTypeIn, Literal: "IN"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "customers"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "country"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "USA"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false, // Subqueries in WHERE now supported
		},
		{
			name: "CASE expression in SELECT",
			desc: "Tests CASE WHEN THEN ELSE END expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeCase, Literal: "CASE"},
				{Type: models.TokenTypeWhen, Literal: "WHEN"},
				{Type: models.TokenTypeIdentifier, Literal: "age"},
				{Type: models.TokenTypeLt, Literal: "<"},
				{Type: models.TokenTypeNumber, Literal: "18"},
				{Type: models.TokenTypeThen, Literal: "THEN"},
				{Type: models.TokenTypeString, Literal: "minor"},
				{Type: models.TokenTypeElse, Literal: "ELSE"},
				{Type: models.TokenTypeString, Literal: "adult"},
				{Type: models.TokenTypeEnd, Literal: "END"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
			wantErr: false, // CASE expressions now supported
		},
		{
			name: "DISTINCT with aggregate",
			desc: "Tests DISTINCT keyword with aggregation",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeCount, Literal: "COUNT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
				{Type: models.TokenTypeIdentifier, Literal: "customer_id"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "orders"},
			},
			wantErr: true, // DISTINCT in aggregate not yet supported
		},
		{
			name: "GROUP BY with HAVING",
			desc: "Tests GROUP BY clause with HAVING filter",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "category"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeCount, Literal: "COUNT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "products"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeIdentifier, Literal: "category"},
				{Type: models.TokenTypeHaving, Literal: "HAVING"},
				{Type: models.TokenTypeCount, Literal: "COUNT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeGt, Literal: ">"},
				{Type: models.TokenTypeNumber, Literal: "10"},
			},
			wantErr: true, // HAVING clause not yet supported
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() %s: error = %v, wantErr %v", tt.desc, err, tt.wantErr)
			}
		})
	}
}

// TestParser_GroupingOperations tests SQL-99 ROLLUP, CUBE, GROUPING SETS
func TestParser_GroupingOperations(t *testing.T) {
	tests := []struct {
		name    string
		desc    string
		tokens  []token.Token
		wantErr bool
	}{
		// ROLLUP tests
		{
			name: "ROLLUP with two columns",
			desc: "GROUP BY ROLLUP(a, b)",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeRollup, Literal: "ROLLUP"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false,
		},
		{
			name: "Empty ROLLUP fails",
			desc: "GROUP BY ROLLUP() should fail",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeRollup, Literal: "ROLLUP"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: true,
		},
		// CUBE tests
		{
			name: "CUBE with two columns",
			desc: "GROUP BY CUBE(a, b)",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeCube, Literal: "CUBE"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false,
		},
		{
			name: "Empty CUBE fails",
			desc: "GROUP BY CUBE() should fail",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeCube, Literal: "CUBE"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: true,
		},
		// GROUPING SETS tests
		{
			name: "GROUPING SETS with multiple sets",
			desc: "GROUP BY GROUPING SETS((a, b), (a), ())",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeGroupingSets, Literal: "GROUPING SETS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false,
		},
		{
			name: "GROUPING SETS with only empty set",
			desc: "GROUP BY GROUPING SETS(()) is valid for grand total",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "total"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeGroupingSets, Literal: "GROUPING SETS"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false,
		},
		// Mixed tests
		{
			name: "Mixed regular column and ROLLUP",
			desc: "GROUP BY a, ROLLUP(b, c)",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeRollup, Literal: "ROLLUP"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() %s: error = %v, wantErr %v", tt.desc, err, tt.wantErr)
			}
		})
	}
}
