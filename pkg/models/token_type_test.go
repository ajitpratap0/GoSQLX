package models

import "testing"

func TestTokenType_String(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      string
	}{
		// Special tokens
		{name: "EOF", tokenType: TokenTypeEOF, want: "EOF"},
		{name: "Unknown", tokenType: TokenTypeUnknown, want: "UNKNOWN"},

		// Basic token types
		{name: "Word", tokenType: TokenTypeWord, want: "WORD"},
		{name: "Number", tokenType: TokenTypeNumber, want: "NUMBER"},
		{name: "Identifier", tokenType: TokenTypeIdentifier, want: "IDENTIFIER"},

		// String literals
		{name: "SingleQuotedString", tokenType: TokenTypeSingleQuotedString, want: "STRING"},
		{name: "DoubleQuotedString", tokenType: TokenTypeDoubleQuotedString, want: "DOUBLE_QUOTED_STRING"},

		// Operators
		{name: "Comma", tokenType: TokenTypeComma, want: "COMMA"},
		{name: "Eq", tokenType: TokenTypeEq, want: "EQ"},
		{name: "Neq", tokenType: TokenTypeNeq, want: "NEQ"},
		{name: "Lt", tokenType: TokenTypeLt, want: "LT"},
		{name: "Gt", tokenType: TokenTypeGt, want: "GT"},
		{name: "Plus", tokenType: TokenTypePlus, want: "PLUS"},
		{name: "Minus", tokenType: TokenTypeMinus, want: "MINUS"},
		{name: "Mul", tokenType: TokenTypeMul, want: "MUL"},
		{name: "Div", tokenType: TokenTypeDiv, want: "DIV"},

		// Parentheses
		{name: "LParen", tokenType: TokenTypeLParen, want: "LPAREN"},
		{name: "RParen", tokenType: TokenTypeRParen, want: "RPAREN"},

		// SQL Keywords
		{name: "SELECT", tokenType: TokenTypeSelect, want: "SELECT"},
		{name: "FROM", tokenType: TokenTypeFrom, want: "FROM"},
		{name: "WHERE", tokenType: TokenTypeWhere, want: "WHERE"},
		{name: "AND", tokenType: TokenTypeAnd, want: "AND"},
		{name: "OR", tokenType: TokenTypeOr, want: "OR"},
		{name: "NOT", tokenType: TokenTypeNot, want: "NOT"},
		{name: "GROUP", tokenType: TokenTypeGroup, want: "GROUP"},
		{name: "BY", tokenType: TokenTypeBy, want: "BY"},
		{name: "HAVING", tokenType: TokenTypeHaving, want: "HAVING"},
		{name: "ORDER", tokenType: TokenTypeOrder, want: "ORDER"},

		// Aggregate functions
		{name: "COUNT", tokenType: TokenTypeCount, want: "COUNT"},
		{name: "SUM", tokenType: TokenTypeSum, want: "SUM"},
		{name: "AVG", tokenType: TokenTypeAvg, want: "AVG"},
		{name: "MIN", tokenType: TokenTypeMin, want: "MIN"},
		{name: "MAX", tokenType: TokenTypeMax, want: "MAX"},

		// JOIN types
		{name: "JOIN", tokenType: TokenTypeJoin, want: "JOIN"},
		{name: "INNER", tokenType: TokenTypeInner, want: "INNER"},
		{name: "LEFT", tokenType: TokenTypeLeft, want: "LEFT"},
		{name: "RIGHT", tokenType: TokenTypeRight, want: "RIGHT"},
		{name: "OUTER", tokenType: TokenTypeOuter, want: "OUTER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.String()
			if got != tt.want {
				t.Errorf("TokenType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenType_StringUnknownToken(t *testing.T) {
	// Test with a token type that doesn't exist in the map
	unknownType := TokenType(99999)
	got := unknownType.String()
	if got != "TOKEN" {
		t.Errorf("Unknown TokenType.String() = %v, want 'TOKEN'", got)
	}
}

func TestTokenTypeConstants(t *testing.T) {
	// Test that token type constants have expected values
	tests := []struct {
		name      string
		tokenType TokenType
		wantValue TokenType
	}{
		{name: "EOF", tokenType: TokenTypeEOF, wantValue: 0},
		{name: "Unknown", tokenType: TokenTypeUnknown, wantValue: 1},
		{name: "Word", tokenType: TokenTypeWord, wantValue: 10},
		{name: "Number", tokenType: TokenTypeNumber, wantValue: 11},
		{name: "SELECT", tokenType: TokenTypeSelect, wantValue: 201},
		{name: "FROM", tokenType: TokenTypeFrom, wantValue: 202},
		{name: "WHERE", tokenType: TokenTypeWhere, wantValue: 203},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tokenType != tt.wantValue {
				t.Errorf("%s constant = %d, want %d", tt.name, tt.tokenType, tt.wantValue)
			}
		})
	}
}

func TestTokenTypeAliases(t *testing.T) {
	// Test that aliases have the same value as their base types
	tests := []struct {
		name  string
		alias TokenType
		base  TokenType
	}{
		{name: "LeftParen/LParen", alias: TokenTypeLeftParen, base: TokenTypeLParen},
		{name: "RightParen/RParen", alias: TokenTypeRightParen, base: TokenTypeRParen},
		{name: "Dot/Period", alias: TokenTypeDot, base: TokenTypePeriod},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.alias != tt.base {
				t.Errorf("%s: alias value %d != base value %d", tt.name, tt.alias, tt.base)
			}
		})
	}
}

func TestTokenTypeUniqueness(t *testing.T) {
	// Collect all token type values (excluding aliases)
	tokenTypes := []TokenType{
		TokenTypeEOF, TokenTypeUnknown,
		TokenTypeWord, TokenTypeNumber, TokenTypeChar, TokenTypeWhitespace,
		TokenTypeIdentifier, TokenTypePlaceholder,
		TokenTypeString, TokenTypeSingleQuotedString, TokenTypeDoubleQuotedString,
		TokenTypeComma, TokenTypeEq, TokenTypeNeq, TokenTypeLt, TokenTypeGt,
		TokenTypePlus, TokenTypeMinus, TokenTypeMul, TokenTypeDiv,
		TokenTypeLParen, TokenTypeRParen,
		TokenTypeSelect, TokenTypeFrom, TokenTypeWhere,
		TokenTypeGroup, TokenTypeBy, TokenTypeHaving, TokenTypeOrder,
		TokenTypeCount, TokenTypeSum, TokenTypeAvg, TokenTypeMin, TokenTypeMax,
	}

	// Check for duplicates (excluding known aliases)
	seen := make(map[TokenType]bool)
	for _, tt := range tokenTypes {
		// Skip known aliases
		if tt == TokenTypeLeftParen || tt == TokenTypeRightParen || tt == TokenTypeDot {
			continue
		}

		if seen[tt] {
			t.Errorf("Duplicate token type value: %d", tt)
		}
		seen[tt] = true
	}
}

func TestTokenTypeGrouping(t *testing.T) {
	// Test that token types are in their expected ranges
	tests := []struct {
		name      string
		tokenType TokenType
		minRange  TokenType
		maxRange  TokenType
	}{
		{name: "EOF in special range", tokenType: TokenTypeEOF, minRange: 0, maxRange: 9},
		{name: "Word in basic range", tokenType: TokenTypeWord, minRange: 10, maxRange: 29},
		{name: "String in string range", tokenType: TokenTypeSingleQuotedString, minRange: 30, maxRange: 49},
		{name: "Comma in operator range", tokenType: TokenTypeComma, minRange: 50, maxRange: 99},
		{name: "SELECT in keyword range", tokenType: TokenTypeSelect, minRange: 200, maxRange: 299},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tokenType < tt.minRange || tt.tokenType > tt.maxRange {
				t.Errorf("%s value %d not in expected range [%d, %d]",
					tt.name, tt.tokenType, tt.minRange, tt.maxRange)
			}
		})
	}
}

func TestAllTokenTypesHaveStrings(t *testing.T) {
	// Test that all major token types have string representations
	tokenTypes := []TokenType{
		TokenTypeEOF, TokenTypeUnknown,
		TokenTypeWord, TokenTypeNumber, TokenTypeIdentifier,
		TokenTypeSingleQuotedString, TokenTypeDoubleQuotedString,
		TokenTypeComma, TokenTypeEq, TokenTypePlus, TokenTypeMinus,
		TokenTypeLParen, TokenTypeRParen,
		TokenTypeSelect, TokenTypeFrom, TokenTypeWhere, TokenTypeGroup,
		TokenTypeCount, TokenTypeSum, TokenTypeJoin,
	}

	for _, tt := range tokenTypes {
		str := tt.String()
		if str == "TOKEN" {
			t.Errorf("TokenType %d has no string mapping (returned default 'TOKEN')", tt)
		}
		if str == "" {
			t.Errorf("TokenType %d returned empty string", tt)
		}
	}
}

func TestTokenTypeComparison(t *testing.T) {
	// Test that token types can be compared
	if TokenTypeEOF >= TokenTypeUnknown {
		t.Error("Expected TokenTypeEOF < TokenTypeUnknown")
	}

	if TokenTypeSelect >= TokenTypeFrom {
		t.Error("Expected TokenTypeSelect < TokenTypeFrom")
	}

	if TokenTypeLParen == TokenTypeRParen {
		t.Error("Expected TokenTypeLParen != TokenTypeRParen")
	}
}

func BenchmarkTokenType_String(b *testing.B) {
	tokenType := TokenTypeSelect

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tokenType.String()
	}
}

func BenchmarkTokenType_StringUnknown(b *testing.B) {
	tokenType := TokenType(99999)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tokenType.String()
	}
}

// Tests for new helper methods

func TestTokenType_IsKeyword(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		// SQL keywords should return true
		{name: "SELECT is keyword", tokenType: TokenTypeSelect, want: true},
		{name: "FROM is keyword", tokenType: TokenTypeFrom, want: true},
		{name: "WHERE is keyword", tokenType: TokenTypeWhere, want: true},
		{name: "INSERT is keyword", tokenType: TokenTypeInsert, want: true},
		{name: "UPDATE is keyword", tokenType: TokenTypeUpdate, want: true},
		{name: "DELETE is keyword", tokenType: TokenTypeDelete, want: true},
		{name: "CREATE is keyword", tokenType: TokenTypeCreate, want: true},
		{name: "ALTER is keyword", tokenType: TokenTypeAlter, want: true},
		{name: "DROP is keyword", tokenType: TokenTypeDrop, want: true},
		{name: "WITH is keyword", tokenType: TokenTypeWith, want: true},
		{name: "UNION is keyword", tokenType: TokenTypeUnion, want: true},
		{name: "OVER is keyword", tokenType: TokenTypeOver, want: true},
		{name: "MERGE is keyword", tokenType: TokenTypeMerge, want: true},

		// Non-keywords should return false
		{name: "EOF is not keyword", tokenType: TokenTypeEOF, want: false},
		{name: "Number is not keyword", tokenType: TokenTypeNumber, want: false},
		{name: "Identifier is not keyword", tokenType: TokenTypeIdentifier, want: false},
		{name: "Comma is not keyword", tokenType: TokenTypeComma, want: false},
		{name: "LParen is not keyword", tokenType: TokenTypeLParen, want: false},
		{name: "Asterisk is not keyword", tokenType: TokenTypeAsterisk, want: false},
		{name: "Illegal is not keyword", tokenType: TokenTypeIllegal, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsKeyword()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsKeyword() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsOperator(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		// Operators should return true
		{name: "Comma is operator", tokenType: TokenTypeComma, want: true},
		{name: "Eq is operator", tokenType: TokenTypeEq, want: true},
		{name: "Neq is operator", tokenType: TokenTypeNeq, want: true},
		{name: "Lt is operator", tokenType: TokenTypeLt, want: true},
		{name: "Gt is operator", tokenType: TokenTypeGt, want: true},
		{name: "Plus is operator", tokenType: TokenTypePlus, want: true},
		{name: "Minus is operator", tokenType: TokenTypeMinus, want: true},
		{name: "Mul is operator", tokenType: TokenTypeMul, want: true},
		{name: "Div is operator", tokenType: TokenTypeDiv, want: true},
		{name: "LParen is operator", tokenType: TokenTypeLParen, want: true},
		{name: "Asterisk is operator", tokenType: TokenTypeAsterisk, want: true},
		{name: "DoublePipe is operator", tokenType: TokenTypeDoublePipe, want: true},

		// Non-operators should return false
		{name: "SELECT is not operator", tokenType: TokenTypeSelect, want: false},
		{name: "Number is not operator", tokenType: TokenTypeNumber, want: false},
		{name: "Identifier is not operator", tokenType: TokenTypeIdentifier, want: false},
		{name: "EOF is not operator", tokenType: TokenTypeEOF, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsOperator()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsOperator() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsLiteral(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		// Literals should return true
		{name: "Identifier is literal", tokenType: TokenTypeIdentifier, want: true},
		{name: "Number is literal", tokenType: TokenTypeNumber, want: true},
		{name: "String is literal", tokenType: TokenTypeString, want: true},
		{name: "SingleQuotedString is literal", tokenType: TokenTypeSingleQuotedString, want: true},
		{name: "True is literal", tokenType: TokenTypeTrue, want: true},
		{name: "False is literal", tokenType: TokenTypeFalse, want: true},
		{name: "Null is literal", tokenType: TokenTypeNull, want: true},

		// Non-literals should return false
		{name: "SELECT is not literal", tokenType: TokenTypeSelect, want: false},
		{name: "Comma is not literal", tokenType: TokenTypeComma, want: false},
		{name: "EOF is not literal", tokenType: TokenTypeEOF, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsLiteral()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsLiteral() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsDMLKeyword(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "SELECT is DML", tokenType: TokenTypeSelect, want: true},
		{name: "INSERT is DML", tokenType: TokenTypeInsert, want: true},
		{name: "UPDATE is DML", tokenType: TokenTypeUpdate, want: true},
		{name: "DELETE is DML", tokenType: TokenTypeDelete, want: true},
		{name: "FROM is DML", tokenType: TokenTypeFrom, want: true},
		{name: "WHERE is DML", tokenType: TokenTypeWhere, want: true},
		{name: "INTO is DML", tokenType: TokenTypeInto, want: true},
		{name: "VALUES is DML", tokenType: TokenTypeValues, want: true},
		{name: "SET is DML", tokenType: TokenTypeSet, want: true},

		{name: "CREATE is not DML", tokenType: TokenTypeCreate, want: false},
		{name: "ALTER is not DML", tokenType: TokenTypeAlter, want: false},
		{name: "DROP is not DML", tokenType: TokenTypeDrop, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsDMLKeyword()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsDMLKeyword() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsDDLKeyword(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "CREATE is DDL", tokenType: TokenTypeCreate, want: true},
		{name: "ALTER is DDL", tokenType: TokenTypeAlter, want: true},
		{name: "DROP is DDL", tokenType: TokenTypeDrop, want: true},
		{name: "TABLE is DDL", tokenType: TokenTypeTable, want: true},
		{name: "INDEX is DDL", tokenType: TokenTypeIndex, want: true},
		{name: "VIEW is DDL", tokenType: TokenTypeView, want: true},
		{name: "DATABASE is DDL", tokenType: TokenTypeDatabase, want: true},

		{name: "SELECT is not DDL", tokenType: TokenTypeSelect, want: false},
		{name: "INSERT is not DDL", tokenType: TokenTypeInsert, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsDDLKeyword()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsDDLKeyword() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsJoinKeyword(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "JOIN is join keyword", tokenType: TokenTypeJoin, want: true},
		{name: "INNER is join keyword", tokenType: TokenTypeInner, want: true},
		{name: "LEFT is join keyword", tokenType: TokenTypeLeft, want: true},
		{name: "RIGHT is join keyword", tokenType: TokenTypeRight, want: true},
		{name: "OUTER is join keyword", tokenType: TokenTypeOuter, want: true},
		{name: "CROSS is join keyword", tokenType: TokenTypeCross, want: true},
		{name: "NATURAL is join keyword", tokenType: TokenTypeNatural, want: true},
		{name: "FULL is join keyword", tokenType: TokenTypeFull, want: true},
		{name: "ON is join keyword", tokenType: TokenTypeOn, want: true},
		{name: "USING is join keyword", tokenType: TokenTypeUsing, want: true},
		{name: "InnerJoin is join keyword", tokenType: TokenTypeInnerJoin, want: true},
		{name: "LeftJoin is join keyword", tokenType: TokenTypeLeftJoin, want: true},

		{name: "SELECT is not join keyword", tokenType: TokenTypeSelect, want: false},
		{name: "FROM is not join keyword", tokenType: TokenTypeFrom, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsJoinKeyword()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsJoinKeyword() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsWindowKeyword(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "OVER is window keyword", tokenType: TokenTypeOver, want: true},
		{name: "PARTITION is window keyword", tokenType: TokenTypePartition, want: true},
		{name: "ROWS is window keyword", tokenType: TokenTypeRows, want: true},
		{name: "RANGE is window keyword", tokenType: TokenTypeRange, want: true},
		{name: "UNBOUNDED is window keyword", tokenType: TokenTypeUnbounded, want: true},
		{name: "PRECEDING is window keyword", tokenType: TokenTypePreceding, want: true},
		{name: "FOLLOWING is window keyword", tokenType: TokenTypeFollowing, want: true},
		{name: "CURRENT is window keyword", tokenType: TokenTypeCurrent, want: true},
		{name: "ROW is window keyword", tokenType: TokenTypeRow, want: true},

		{name: "SELECT is not window keyword", tokenType: TokenTypeSelect, want: false},
		{name: "ORDER is not window keyword", tokenType: TokenTypeOrder, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsWindowKeyword()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsWindowKeyword() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsAggregateFunction(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "COUNT is aggregate", tokenType: TokenTypeCount, want: true},
		{name: "SUM is aggregate", tokenType: TokenTypeSum, want: true},
		{name: "AVG is aggregate", tokenType: TokenTypeAvg, want: true},
		{name: "MIN is aggregate", tokenType: TokenTypeMin, want: true},
		{name: "MAX is aggregate", tokenType: TokenTypeMax, want: true},

		{name: "SELECT is not aggregate", tokenType: TokenTypeSelect, want: false},
		{name: "OVER is not aggregate", tokenType: TokenTypeOver, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsAggregateFunction()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsAggregateFunction() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsDataType(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "INT is data type", tokenType: TokenTypeInt, want: true},
		{name: "INTEGER is data type", tokenType: TokenTypeInteger, want: true},
		{name: "VARCHAR is data type", tokenType: TokenTypeVarchar, want: true},
		{name: "TIMESTAMP is data type", tokenType: TokenTypeTimestamp, want: true},
		{name: "BOOLEAN is data type", tokenType: TokenTypeBoolean, want: true},
		{name: "JSON is data type", tokenType: TokenTypeJson, want: true},
		{name: "UUID is data type", tokenType: TokenTypeUuid, want: true},

		{name: "SELECT is not data type", tokenType: TokenTypeSelect, want: false},
		{name: "TABLE is not data type", tokenType: TokenTypeTable, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsDataType()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsDataType() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsConstraint(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "PRIMARY is constraint", tokenType: TokenTypePrimary, want: true},
		{name: "KEY is constraint", tokenType: TokenTypeKey, want: true},
		{name: "FOREIGN is constraint", tokenType: TokenTypeForeign, want: true},
		{name: "REFERENCES is constraint", tokenType: TokenTypeReferences, want: true},
		{name: "UNIQUE is constraint", tokenType: TokenTypeUnique, want: true},
		{name: "CHECK is constraint", tokenType: TokenTypeCheck, want: true},
		{name: "DEFAULT is constraint", tokenType: TokenTypeDefault, want: true},
		{name: "NOT NULL is constraint", tokenType: TokenTypeNotNull, want: true},

		{name: "SELECT is not constraint", tokenType: TokenTypeSelect, want: false},
		{name: "CREATE is not constraint", tokenType: TokenTypeCreate, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsConstraint()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsConstraint() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestTokenType_IsSetOperation(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      bool
	}{
		{name: "UNION is set op", tokenType: TokenTypeUnion, want: true},
		{name: "EXCEPT is set op", tokenType: TokenTypeExcept, want: true},
		{name: "INTERSECT is set op", tokenType: TokenTypeIntersect, want: true},
		{name: "ALL is set op", tokenType: TokenTypeAll, want: true},

		{name: "SELECT is not set op", tokenType: TokenTypeSelect, want: false},
		{name: "JOIN is not set op", tokenType: TokenTypeJoin, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.IsSetOperation()
			if got != tt.want {
				t.Errorf("TokenType(%d).IsSetOperation() = %v, want %v", tt.tokenType, got, tt.want)
			}
		})
	}
}

// Test new token types have string mappings

func TestNewTokenTypes_String(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		want      string
	}{
		// DML Keywords
		{name: "INSERT", tokenType: TokenTypeInsert, want: "INSERT"},
		{name: "UPDATE", tokenType: TokenTypeUpdate, want: "UPDATE"},
		{name: "DELETE", tokenType: TokenTypeDelete, want: "DELETE"},
		{name: "INTO", tokenType: TokenTypeInto, want: "INTO"},
		{name: "VALUES", tokenType: TokenTypeValues, want: "VALUES"},
		{name: "SET", tokenType: TokenTypeSet, want: "SET"},

		// DDL Keywords
		{name: "CREATE", tokenType: TokenTypeCreate, want: "CREATE"},
		{name: "ALTER", tokenType: TokenTypeAlter, want: "ALTER"},
		{name: "DROP", tokenType: TokenTypeDrop, want: "DROP"},
		{name: "TABLE", tokenType: TokenTypeTable, want: "TABLE"},
		{name: "INDEX", tokenType: TokenTypeIndex, want: "INDEX"},
		{name: "VIEW", tokenType: TokenTypeView, want: "VIEW"},

		// CTE and Set Operations
		{name: "WITH", tokenType: TokenTypeWith, want: "WITH"},
		{name: "RECURSIVE", tokenType: TokenTypeRecursive, want: "RECURSIVE"},
		{name: "UNION", tokenType: TokenTypeUnion, want: "UNION"},
		{name: "EXCEPT", tokenType: TokenTypeExcept, want: "EXCEPT"},
		{name: "INTERSECT", tokenType: TokenTypeIntersect, want: "INTERSECT"},

		// Window Function Keywords
		{name: "OVER", tokenType: TokenTypeOver, want: "OVER"},
		{name: "PARTITION", tokenType: TokenTypePartition, want: "PARTITION"},
		{name: "ROWS", tokenType: TokenTypeRows, want: "ROWS"},
		{name: "RANGE", tokenType: TokenTypeRange, want: "RANGE"},

		// Constraint Keywords
		{name: "PRIMARY", tokenType: TokenTypePrimary, want: "PRIMARY"},
		{name: "FOREIGN", tokenType: TokenTypeForeign, want: "FOREIGN"},
		{name: "UNIQUE", tokenType: TokenTypeUnique, want: "UNIQUE"},

		// MERGE Statement Keywords
		{name: "MERGE", tokenType: TokenTypeMerge, want: "MERGE"},
		{name: "MATCHED", tokenType: TokenTypeMatched, want: "MATCHED"},

		// Materialized View
		{name: "MATERIALIZED", tokenType: TokenTypeMaterialized, want: "MATERIALIZED"},
		{name: "REFRESH", tokenType: TokenTypeRefresh, want: "REFRESH"},

		// Grouping Sets
		{name: "ROLLUP", tokenType: TokenTypeRollup, want: "ROLLUP"},
		{name: "CUBE", tokenType: TokenTypeCube, want: "CUBE"},

		// Data Types
		{name: "INT", tokenType: TokenTypeInt, want: "INT"},
		{name: "VARCHAR", tokenType: TokenTypeVarchar, want: "VARCHAR"},
		{name: "TIMESTAMP", tokenType: TokenTypeTimestamp, want: "TIMESTAMP"},
		{name: "JSON", tokenType: TokenTypeJson, want: "JSON"},

		// Special tokens
		{name: "ILLEGAL", tokenType: TokenTypeIllegal, want: "ILLEGAL"},
		{name: "ASTERISK", tokenType: TokenTypeAsterisk, want: "*"},
		{name: "DOUBLEPIPE", tokenType: TokenTypeDoublePipe, want: "||"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tokenType.String()
			if got != tt.want {
				t.Errorf("TokenType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Benchmark helper methods

func BenchmarkTokenType_IsKeyword(b *testing.B) {
	tokenType := TokenTypeSelect
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tokenType.IsKeyword()
	}
}

func BenchmarkTokenType_IsOperator(b *testing.B) {
	tokenType := TokenTypePlus
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tokenType.IsOperator()
	}
}

func BenchmarkTokenType_IsDataType(b *testing.B) {
	tokenType := TokenTypeVarchar
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tokenType.IsDataType()
	}
}
