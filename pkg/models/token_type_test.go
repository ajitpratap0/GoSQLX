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
