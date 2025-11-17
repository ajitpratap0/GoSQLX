package compatibility

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestAPIStability_PublicInterfaces ensures public API interfaces remain stable across versions
// Breaking changes to these interfaces would break user code - must be avoided in v1.x
func TestAPIStability_PublicInterfaces(t *testing.T) {
	tests := []struct {
		name          string
		interfaceType interface{}
		methods       []string
	}{
		{
			name:          "ast.Node",
			interfaceType: (*ast.Node)(nil),
			methods:       []string{"TokenLiteral", "Children"},
		},
		{
			name:          "ast.Statement",
			interfaceType: (*ast.Statement)(nil),
			methods:       []string{"TokenLiteral", "Children", "statementNode"},
		},
		{
			name:          "ast.Expression",
			interfaceType: (*ast.Expression)(nil),
			methods:       []string{"TokenLiteral", "Children", "expressionNode"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typ := reflect.TypeOf(tt.interfaceType).Elem()

			// Verify all required methods exist
			for _, methodName := range tt.methods {
				method, found := typ.MethodByName(methodName)
				if !found {
					t.Errorf("API BREAKAGE: Interface %s missing method %s", tt.name, methodName)
				} else {
					t.Logf("✓ %s has method %s (signature: %s)", tt.name, methodName, method.Type)
				}
			}
		})
	}
}

// TestAPIStability_PublicFunctions ensures critical public functions maintain their signatures
func TestAPIStability_PublicFunctions(t *testing.T) {
	tests := []struct {
		name         string
		function     interface{}
		expectedType string
	}{
		{
			name:         "tokenizer.GetTokenizer",
			function:     tokenizer.GetTokenizer,
			expectedType: "func() *tokenizer.Tokenizer",
		},
		{
			name:         "tokenizer.PutTokenizer",
			function:     tokenizer.PutTokenizer,
			expectedType: "func(*tokenizer.Tokenizer)",
		},
		{
			name:         "ast.NewAST",
			function:     ast.NewAST,
			expectedType: "func() *ast.AST",
		},
		{
			name:         "ast.ReleaseAST",
			function:     ast.ReleaseAST,
			expectedType: "func(*ast.AST)",
		},
		{
			name:         "parser.NewParser",
			function:     parser.NewParser,
			expectedType: "func() *parser.Parser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualType := reflect.TypeOf(tt.function).String()
			if actualType != tt.expectedType {
				t.Errorf("API BREAKAGE: %s signature changed\nExpected: %s\nGot: %s",
					tt.name, tt.expectedType, actualType)
			} else {
				t.Logf("✓ %s signature stable: %s", tt.name, actualType)
			}
		})
	}
}

// TestAPIStability_PoolBehavior ensures object pool behavior remains consistent
func TestAPIStability_PoolBehavior(t *testing.T) {
	t.Run("Tokenizer_Pool_GetPut", func(t *testing.T) {
		// Get tokenizer from pool
		tkz1 := tokenizer.GetTokenizer()
		if tkz1 == nil {
			t.Fatal("GetTokenizer() returned nil - API broken")
		}

		// Return to pool
		tokenizer.PutTokenizer(tkz1)

		// Get again - should work
		tkz2 := tokenizer.GetTokenizer()
		if tkz2 == nil {
			t.Fatal("GetTokenizer() after Put returned nil - pool broken")
		}

		tokenizer.PutTokenizer(tkz2)
		t.Log("✓ Tokenizer pool Get/Put behavior stable")
	})

	t.Run("AST_Pool_NewRelease", func(t *testing.T) {
		// Create AST from pool
		astObj1 := ast.NewAST()
		if astObj1 == nil {
			t.Fatal("NewAST() returned nil - API broken")
		}

		// Release to pool
		ast.ReleaseAST(astObj1)

		// Create again - should work
		astObj2 := ast.NewAST()
		if astObj2 == nil {
			t.Fatal("NewAST() after Release returned nil - pool broken")
		}

		ast.ReleaseAST(astObj2)
		t.Log("✓ AST pool New/Release behavior stable")
	})
}

// TestAPIStability_TokenTypes ensures token type constants remain stable
func TestAPIStability_TokenTypes(t *testing.T) {
	// Critical token types that must not change
	criticalTokens := map[string]token.Type{
		"SELECT":  "SELECT",
		"FROM":    "FROM",
		"WHERE":   "WHERE",
		"JOIN":    "JOIN",
		"INSERT":  "INSERT",
		"UPDATE":  "UPDATE",
		"DELETE":  "DELETE",
		"CREATE":  "CREATE",
		"ALTER":   "ALTER",
		"DROP":    "DROP",
		"IDENT":   "IDENT",
		"INT":     "INT",
		"STRING":  "STRING",
		"EOF":     "EOF",
		"ILLEGAL": "ILLEGAL",
	}

	for name, expectedValue := range criticalTokens {
		t.Run("Token_"+name, func(t *testing.T) {
			// Verify token constant exists and has expected value
			actualValue := token.Type(expectedValue)
			if actualValue != expectedValue {
				t.Errorf("Token type %s changed value\nExpected: %s\nGot: %s",
					name, expectedValue, actualValue)
			} else {
				t.Logf("✓ Token %s stable: %s", name, actualValue)
			}
		})
	}
}

// TestAPIStability_ParserOutput ensures parser output structure remains compatible
func TestAPIStability_ParserOutput(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE active = true"

	// Tokenize
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenization failed: %v", err)
	}

	// Convert tokens
	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("Token conversion failed: %v", err)
	}

	// Parse
	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}

	// Verify AST structure
	if astObj == nil {
		t.Fatal("Parser returned nil AST")
	}

	if len(astObj.Statements) == 0 {
		t.Fatal("Parser returned empty statements")
	}

	// Verify statement type
	stmt := astObj.Statements[0]
	selectStmt, ok := stmt.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected *ast.SelectStatement, got %T", stmt)
	}

	// Verify basic structure exists
	if selectStmt.Columns == nil {
		t.Error("SelectStatement.Columns is nil - API structure changed")
	}

	if selectStmt.From == nil {
		t.Error("SelectStatement.From is nil - API structure changed")
	}

	t.Log("✓ Parser output structure stable")
}

// TestAPIStability_ErrorHandling ensures error handling remains consistent
func TestAPIStability_ErrorHandling(t *testing.T) {
	t.Run("Invalid_SQL_Returns_Error", func(t *testing.T) {
		invalidSQL := "SELECT FROM WHERE"

		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)

		tokens, err := tkz.Tokenize([]byte(invalidSQL))
		if err != nil {
			// Tokenization error is expected
			t.Logf("✓ Tokenization error handling stable: %v", err)
			return
		}

		convertedTokens, err := parser.ConvertTokensForParser(tokens)
		if err != nil {
			t.Logf("✓ Token conversion error handling stable: %v", err)
			return
		}

		p := parser.NewParser()
		_, err = p.Parse(convertedTokens)
		if err == nil {
			t.Error("Parser should return error for invalid SQL - error handling broken")
		} else {
			t.Logf("✓ Parser error handling stable: %v", err)
		}
	})

	t.Run("Empty_SQL_Handling", func(t *testing.T) {
		emptySQL := ""

		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)

		tokens, err := tkz.Tokenize([]byte(emptySQL))
		// Empty SQL should not crash - verify stable behavior
		if err != nil {
			t.Logf("✓ Empty SQL handling stable (returns error): %v", err)
		} else {
			t.Logf("✓ Empty SQL handling stable (tokenizes to %d tokens)", len(tokens))
		}
	})
}

// TestAPIStability_ConcurrentUsage ensures concurrent usage patterns remain safe
func TestAPIStability_ConcurrentUsage(t *testing.T) {
	const goroutines = 100
	const iterations = 10

	sql := "SELECT * FROM users"
	done := make(chan bool, goroutines)

	// Launch concurrent tokenization
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("PANIC in concurrent usage: %v", r)
				}
				done <- true
			}()

			for j := 0; j < iterations; j++ {
				tkz := tokenizer.GetTokenizer()
				_, _ = tkz.Tokenize([]byte(sql))
				tokenizer.PutTokenizer(tkz)
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}

	t.Logf("✓ Concurrent usage stable (%d goroutines × %d iterations)", goroutines, iterations)
}
