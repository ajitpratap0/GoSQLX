package token

import "testing"

// TestToken_IsKeyword tests the IsKeyword method for various token types.
func TestToken_IsKeyword(t *testing.T) {
	tests := []struct {
		name      string
		tokenType Type
		expected  bool
	}{
		// Keywords that should return true
		{"SELECT keyword", SELECT, true},
		{"INSERT keyword", INSERT, true},
		{"UPDATE keyword", UPDATE, true},
		{"DELETE keyword", DELETE, true},
		{"FROM keyword", FROM, true},
		{"WHERE keyword", WHERE, true},
		{"ORDER keyword", ORDER, true},
		{"BY keyword", BY, true},
		{"GROUP keyword", GROUP, true},
		{"HAVING keyword", HAVING, true},
		{"LIMIT keyword", LIMIT, true},
		{"OFFSET keyword", OFFSET, true},
		{"AS keyword", AS, true},
		{"AND keyword", AND, true},
		{"OR keyword", OR, true},
		{"IN keyword", IN, true},
		{"NOT keyword", NOT, true},
		{"NULL keyword", NULL, true},
		{"INTO keyword", INTO, true},
		{"VALUES keyword", VALUES, true},
		{"TRUE keyword", TRUE, true},
		{"FALSE keyword", FALSE, true},
		{"SET keyword", SET, true},
		{"ALTER keyword", ALTER, true},
		{"TABLE keyword", TABLE, true},

		// Non-keywords that should return false
		{"IDENT token", IDENT, false},
		{"INT token", INT, false},
		{"FLOAT token", FLOAT, false},
		{"STRING token", STRING, false},
		{"LPAREN token", LPAREN, false},
		{"RPAREN token", RPAREN, false},
		{"COMMA token", COMMA, false},
		{"SEMICOLON token", SEMICOLON, false},
		{"DOT token", DOT, false},
		{"ASTERISK token", ASTERISK, false},
		{"EQ operator", EQ, false},
		{"NEQ operator", NEQ, false},
		{"LT operator", LT, false},
		{"GT operator", GT, false},
		{"LTE operator", LTE, false},
		{"GTE operator", GTE, false},
		{"EOF token", EOF, false},
		{"ILLEGAL token", ILLEGAL, false},

		// Additional keywords not in the basic list (but defined in token.go)
		{"DROP keyword", DROP, false},     // Not in IsKeyword switch
		{"ADD keyword", ADD, false},       // Not in IsKeyword switch
		{"COLUMN keyword", COLUMN, false}, // Not in IsKeyword switch
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tokenType.IsKeyword()
			if result != tt.expected {
				t.Errorf("Type(%s).IsKeyword() = %v, expected %v", tt.tokenType, result, tt.expected)
			}
		})
	}
}

// TestToken_IsOperator tests the IsOperator method for various token types.
func TestToken_IsOperator(t *testing.T) {
	tests := []struct {
		name      string
		tokenType Type
		expected  bool
	}{
		// Operators that should return true
		{"EQ operator (=)", EQ, true},
		{"NEQ operator (!=)", NEQ, true},
		{"LT operator (<)", LT, true},
		{"LTE operator (<=)", LTE, true},
		{"GT operator (>)", GT, true},
		{"GTE operator (>=)", GTE, true},
		{"ASTERISK operator (*)", ASTERISK, true},

		// Non-operators that should return false
		{"SELECT keyword", SELECT, false},
		{"IDENT token", IDENT, false},
		{"INT token", INT, false},
		{"FLOAT token", FLOAT, false},
		{"STRING token", STRING, false},
		{"LPAREN token", LPAREN, false},
		{"RPAREN token", RPAREN, false},
		{"COMMA token", COMMA, false},
		{"SEMICOLON token", SEMICOLON, false},
		{"DOT token", DOT, false},
		{"EOF token", EOF, false},
		{"ILLEGAL token", ILLEGAL, false},
		{"NULL keyword", NULL, false},
		{"TRUE keyword", TRUE, false},
		{"FALSE keyword", FALSE, false},

		// Alias tokens that resolve to the same value as operators
		{"EQUAL token (=)", EQUAL, true},    // Same value as EQ (alias)
		{"NOT_EQ token (!=)", NOT_EQ, true}, // Same value as NEQ (alias)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tokenType.IsOperator()
			if result != tt.expected {
				t.Errorf("Type(%s).IsOperator() = %v, expected %v", tt.tokenType, result, tt.expected)
			}
		})
	}
}

// TestToken_IsLiteral tests the IsLiteral method for various token types.
func TestToken_IsLiteral(t *testing.T) {
	tests := []struct {
		name      string
		tokenType Type
		expected  bool
	}{
		// Literals that should return true
		{"IDENT literal", IDENT, true},
		{"INT literal", INT, true},
		{"FLOAT literal", FLOAT, true},
		{"STRING literal", STRING, true},
		{"TRUE literal", TRUE, true},
		{"FALSE literal", FALSE, true},

		// Non-literals that should return false
		{"SELECT keyword", SELECT, false},
		{"INSERT keyword", INSERT, false},
		{"FROM keyword", FROM, false},
		{"WHERE keyword", WHERE, false},
		{"NULL keyword", NULL, false},
		{"LPAREN token", LPAREN, false},
		{"RPAREN token", RPAREN, false},
		{"COMMA token", COMMA, false},
		{"SEMICOLON token", SEMICOLON, false},
		{"DOT token", DOT, false},
		{"EQ operator", EQ, false},
		{"NEQ operator", NEQ, false},
		{"LT operator", LT, false},
		{"GT operator", GT, false},
		{"ASTERISK token", ASTERISK, false},
		{"EOF token", EOF, false},
		{"ILLEGAL token", ILLEGAL, false},
		{"WS token", WS, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tokenType.IsLiteral()
			if result != tt.expected {
				t.Errorf("Type(%s).IsLiteral() = %v, expected %v", tt.tokenType, result, tt.expected)
			}
		})
	}
}

// TestToken_MethodCombinations tests combinations of IsKeyword, IsOperator, and IsLiteral.
func TestToken_MethodCombinations(t *testing.T) {
	tests := []struct {
		name       string
		tokenType  Type
		isKeyword  bool
		isOperator bool
		isLiteral  bool
	}{
		{
			name:       "SELECT - keyword only",
			tokenType:  SELECT,
			isKeyword:  true,
			isOperator: false,
			isLiteral:  false,
		},
		{
			name:       "TRUE - keyword and literal",
			tokenType:  TRUE,
			isKeyword:  true,
			isOperator: false,
			isLiteral:  true,
		},
		{
			name:       "FALSE - keyword and literal",
			tokenType:  FALSE,
			isKeyword:  true,
			isOperator: false,
			isLiteral:  true,
		},
		{
			name:       "EQ - operator only",
			tokenType:  EQ,
			isKeyword:  false,
			isOperator: true,
			isLiteral:  false,
		},
		{
			name:       "ASTERISK - operator only",
			tokenType:  ASTERISK,
			isKeyword:  false,
			isOperator: true,
			isLiteral:  false,
		},
		{
			name:       "IDENT - literal only",
			tokenType:  IDENT,
			isKeyword:  false,
			isOperator: false,
			isLiteral:  true,
		},
		{
			name:       "INT - literal only",
			tokenType:  INT,
			isKeyword:  false,
			isOperator: false,
			isLiteral:  true,
		},
		{
			name:       "COMMA - none",
			tokenType:  COMMA,
			isKeyword:  false,
			isOperator: false,
			isLiteral:  false,
		},
		{
			name:       "LPAREN - none",
			tokenType:  LPAREN,
			isKeyword:  false,
			isOperator: false,
			isLiteral:  false,
		},
		{
			name:       "EOF - none",
			tokenType:  EOF,
			isKeyword:  false,
			isOperator: false,
			isLiteral:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tokenType.IsKeyword(); got != tt.isKeyword {
				t.Errorf("IsKeyword() = %v, want %v", got, tt.isKeyword)
			}
			if got := tt.tokenType.IsOperator(); got != tt.isOperator {
				t.Errorf("IsOperator() = %v, want %v", got, tt.isOperator)
			}
			if got := tt.tokenType.IsLiteral(); got != tt.isLiteral {
				t.Errorf("IsLiteral() = %v, want %v", got, tt.isLiteral)
			}
		})
	}
}

// TestToken_EdgeCases tests edge cases for token type classification methods.
func TestToken_EdgeCases(t *testing.T) {
	t.Run("Empty token type", func(t *testing.T) {
		var emptyType Type

		if emptyType.IsKeyword() {
			t.Error("Empty Type should not be a keyword")
		}
		if emptyType.IsOperator() {
			t.Error("Empty Type should not be an operator")
		}
		if emptyType.IsLiteral() {
			t.Error("Empty Type should not be a literal")
		}
	})

	t.Run("Custom token type", func(t *testing.T) {
		customType := Type("CUSTOM_TOKEN")

		if customType.IsKeyword() {
			t.Error("Custom Type should not be a keyword")
		}
		if customType.IsOperator() {
			t.Error("Custom Type should not be an operator")
		}
		if customType.IsLiteral() {
			t.Error("Custom Type should not be a literal")
		}
	})

	t.Run("Case sensitivity", func(t *testing.T) {
		// Token types are case-sensitive
		lowerSelect := Type("select")

		if lowerSelect.IsKeyword() {
			t.Error("Lowercase 'select' should not match SELECT keyword (case-sensitive)")
		}
	})
}

// TestToken_AllTokenTypesClassified tests that all defined token types are properly classified.
func TestToken_AllTokenTypesClassified(t *testing.T) {
	// This test ensures we don't have token types that fall through all classification methods
	// without being classified (unless intentionally structural tokens like COMMA, LPAREN, etc.)

	tokenTypes := []struct {
		typ            Type
		shouldClassify bool // true if it should be keyword, operator, or literal
	}{
		{SELECT, true},
		{INSERT, true},
		{UPDATE, true},
		{DELETE, true},
		{FROM, true},
		{WHERE, true},
		{EQ, true},
		{NEQ, true},
		{LT, true},
		{IDENT, true},
		{INT, true},
		{STRING, true},
		{TRUE, true},
		{FALSE, true},

		// Structural tokens that shouldn't be classified
		{COMMA, false},
		{LPAREN, false},
		{RPAREN, false},
		{SEMICOLON, false},
		{DOT, false},
		{EOF, false},
		{ILLEGAL, false},
	}

	for _, tt := range tokenTypes {
		t.Run(string(tt.typ), func(t *testing.T) {
			isClassified := tt.typ.IsKeyword() || tt.typ.IsOperator() || tt.typ.IsLiteral()

			if tt.shouldClassify && !isClassified {
				t.Errorf("Token type %s should be classified as keyword, operator, or literal, but is not", tt.typ)
			}
			if !tt.shouldClassify && isClassified {
				t.Errorf("Token type %s should not be classified, but is", tt.typ)
			}
		})
	}
}
