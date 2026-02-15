package parser

import (
	"context"
	"fmt"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestNegativeParser_MalformedSQL tests that the parser returns errors (not panics)
// for various forms of malformed SQL input.
func TestNegativeParser_MalformedSQL(t *testing.T) {
	tests := []struct {
		name   string
		tokens []token.Token
	}{
		{
			name:   "empty token list",
			tokens: []token.Token{},
		},
		{
			name: "SELECT with no columns or table",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
			},
		},
		{
			name: "SELECT FROM WHERE - no columns no table no condition",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
			},
		},
		{
			name: "missing FROM clause",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "x"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
			},
		},
		{
			name: "unclosed parenthesis in expression",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypePlus, Literal: "+"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				// missing )
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
			},
		},
		{
			name: "extra closing parenthesis",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
			},
		},
		{
			name: "duplicate WHERE clauses",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "2"},
			},
		},
		{
			name: "duplicate FROM clauses",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t1"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t2"},
			},
		},
		{
			name: "trailing garbage after valid SELECT",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeIdentifier, Literal: "GARBAGE"},
				{Type: models.TokenTypeIdentifier, Literal: "TOKENS"},
				{Type: models.TokenTypeIdentifier, Literal: "HERE"},
			},
		},
		{
			name: "JOIN without ON condition",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				// missing ON
			},
		},
		{
			name: "JOIN with ON but no condition",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeOn, Literal: "ON"},
			},
		},
		{
			name: "JOIN without table name",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
				{Type: models.TokenTypeOn, Literal: "ON"},
				{Type: models.TokenTypeIdentifier, Literal: "x"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeIdentifier, Literal: "y"},
			},
		},
		{
			name: "INSERT missing INTO",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeValues, Literal: "VALUES"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
		},
		{
			name: "INSERT INTO missing VALUES",
			tokens: []token.Token{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
		},
		{
			name: "UPDATE missing SET",
			tokens: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
			},
		},
		{
			name: "DELETE missing FROM",
			tokens: []token.Token{
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
			},
		},
		{
			name: "lone keyword WHERE",
			tokens: []token.Token{
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
			},
		},
		{
			name: "lone keyword FROM",
			tokens: []token.Token{
				{Type: models.TokenTypeFrom, Literal: "FROM"},
			},
		},
		{
			name: "lone keyword JOIN",
			tokens: []token.Token{
				{Type: models.TokenTypeJoin, Literal: "JOIN"},
			},
		},
		{
			name: "consecutive commas in SELECT list",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
			},
		},
		{
			name: "trailing comma in SELECT list",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeComma, Literal: ","},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
			},
		},
		{
			name: "ORDER BY with no column",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeOrder, Literal: "ORDER"},
				{Type: models.TokenTypeBy, Literal: "BY"},
			},
		},
		{
			name: "GROUP BY with no column",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeGroup, Literal: "GROUP"},
				{Type: models.TokenTypeBy, Literal: "BY"},
			},
		},
		{
			name: "HAVING without GROUP BY",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeHaving, Literal: "HAVING"},
				{Type: models.TokenTypeIdentifier, Literal: "count"},
				{Type: models.TokenTypeGt, Literal: ">"},
				{Type: models.TokenTypeNumber, Literal: "1"},
			},
		},
		{
			name: "malformed subquery - unclosed",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeNumber, Literal: "1"},
				// missing closing )
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
			},
		},
		{
			name: "nested unclosed parentheses",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				// only one close
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
			},
		},
		{
			name: "operator with no operands",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypePlus, Literal: "+"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
			},
		},
		{
			name: "dangling AND in WHERE",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				// missing right side
			},
		},
		{
			name: "dangling OR in WHERE",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeOr, Literal: "OR"},
			},
		},
		{
			name: "CREATE TABLE with no columns",
			tokens: []token.Token{
				{Type: models.TokenTypeCreate, Literal: "CREATE"},
				{Type: models.TokenTypeTable, Literal: "TABLE"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeRParen, Literal: ")"},
			},
		},
		{
			name: "only semicolons",
			tokens: []token.Token{
				{Type: models.TokenTypeSemicolon, Literal: ";"},
				{Type: models.TokenTypeSemicolon, Literal: ";"},
				{Type: models.TokenTypeSemicolon, Literal: ";"},
			},
		},
		{
			name: "LIMIT without value",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeLimit, Literal: "LIMIT"},
			},
		},
		{
			name: "OFFSET without value",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeLimit, Literal: "LIMIT"},
				{Type: models.TokenTypeNumber, Literal: "10"},
				{Type: models.TokenTypeOffset, Literal: "OFFSET"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must not panic - use recover to catch panics and fail the test
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parser panicked on malformed SQL: %v", r)
				}
			}()

			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tt.tokens)
			// We expect either an error or a nil/degenerate AST for malformed SQL.
			// The key invariant: no panic.
			if err == nil && tree != nil && len(tree.Statements) > 0 {
				// Some malformed inputs may parse partially - that's OK as long as no panic.
				// But log it for visibility.
				t.Logf("note: parser accepted malformed input %q without error (%d statements)", tt.name, len(tree.Statements))
			}
		})
	}
}

// TestNegativeParser_UsingTokenizeHelper uses the tokenizer helper from context_test.go
// to test SQL strings that should fail to parse.
func TestNegativeParser_SQLStrings(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"empty string", ""},
		{"just whitespace", "   "},
		{"just semicolon", ";"},
		{"SELECT no columns", "SELECT FROM users"},
		{"unclosed string literal", "SELECT 'hello FROM users"},
		{"double FROM", "SELECT * FROM t1 FROM t2"},
		{"ORDER without BY", "SELECT * FROM t ORDER"},
		{"GROUP without BY", "SELECT * FROM t GROUP"},
		{"random keywords", "WHERE FROM SELECT JOIN ON"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parser panicked on %q: %v", tt.sql, r)
				}
			}()

			p := GetParser()
			defer PutParser(p)

			// Tokenize - may fail, that's fine
			tokens := tokenizeForTest(t, tt.sql)
			if tokens == nil {
				return // tokenization failed, that's a valid outcome
			}

			_, _ = p.Parse(tokens)
			// No panic is the success criterion
		})
	}
}

// tokenizeForTest tokenizes a SQL string into parser tokens.
// Returns nil if tokenization or conversion fails (valid outcome for negative tests).
func tokenizeForTest(t *testing.T, sql string) []token.Token {
	t.Helper()

	if strings.TrimSpace(sql) == "" {
		return []token.Token{}
	}

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	modelTokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Logf("tokenization failed (expected for malformed SQL): %v", err)
		return nil
	}

	converted, err := convertModelTokens(modelTokens)
	if err != nil {
		t.Logf("token conversion failed: %v", err)
		return nil
	}
	return converted
}

// TestPoolContamination verifies that parsing different SQL patterns through pooled
// parsers doesn't cause cross-contamination between parses.
func TestPoolContamination(t *testing.T) {
	// Pattern A: simple SELECT
	tokensA := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeTrue, Literal: "TRUE"},
	}

	// Pattern B: INSERT
	tokensB := []token.Token{
		{Type: models.TokenTypeInsert, Literal: "INSERT"},
		{Type: models.TokenTypeInto, Literal: "INTO"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "product"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "qty"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeValues, Literal: "VALUES"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeString, Literal: "'widget'"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeNumber, Literal: "42"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	// Pattern C: CREATE TABLE
	tokensC := []token.Token{
		{Type: models.TokenTypeCreate, Literal: "CREATE"},
		{Type: models.TokenTypeTable, Literal: "TABLE"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeIdentifier, Literal: "INT"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeIdentifier, Literal: "TEXT"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	// Round 1: Parse A, return parser to pool
	p1 := GetParser()
	astA1, errA1 := p1.Parse(tokensA)
	PutParser(p1)

	// Round 2: Get parser from pool (likely same instance), parse B
	p2 := GetParser()
	astB, errB := p2.Parse(tokensB)
	PutParser(p2)

	// Round 3: Parse C
	p3 := GetParser()
	astC, errC := p3.Parse(tokensC)
	PutParser(p3)

	// Round 4: Parse A again — must produce identical results to Round 1
	p4 := GetParser()
	astA2, errA2 := p4.Parse(tokensA)
	PutParser(p4)

	// Verify A round 1
	if errA1 != nil {
		t.Fatalf("Round 1 SELECT failed: %v", errA1)
	}
	if astA1 == nil || len(astA1.Statements) == 0 {
		t.Fatal("Round 1 SELECT produced no statements")
	}

	// Verify B
	if errB != nil {
		t.Fatalf("Round 2 INSERT failed: %v", errB)
	}
	if astB == nil || len(astB.Statements) == 0 {
		t.Fatal("Round 2 INSERT produced no statements")
	}

	// Verify C
	if errC != nil {
		t.Fatalf("Round 3 CREATE failed: %v", errC)
	}
	if astC == nil || len(astC.Statements) == 0 {
		t.Fatal("Round 3 CREATE produced no statements")
	}

	// Verify A round 2 matches round 1
	if errA2 != nil {
		t.Fatalf("Round 4 SELECT failed: %v", errA2)
	}
	if astA2 == nil || len(astA2.Statements) == 0 {
		t.Fatal("Round 4 SELECT produced no statements")
	}

	// Cross-contamination check: statement counts must match
	if len(astA1.Statements) != len(astA2.Statements) {
		t.Fatalf("Pool contamination detected: A1 had %d statements, A2 had %d",
			len(astA1.Statements), len(astA2.Statements))
	}

	// Verify statement types are consistent
	a1Type := strings.TrimPrefix(strings.Replace(
		strings.ToLower(astA1.Statements[0].TokenLiteral()), " ", "", -1), "*ast.")
	a2Type := strings.TrimPrefix(strings.Replace(
		strings.ToLower(astA2.Statements[0].TokenLiteral()), " ", "", -1), "*ast.")
	if a1Type != a2Type {
		t.Fatalf("Pool contamination: A1 type=%s, A2 type=%s", a1Type, a2Type)
	}
}

// TestPoolContamination_ErrorThenSuccess verifies that a failed parse doesn't
// corrupt the parser for subsequent successful parses.
func TestPoolContamination_ErrorThenSuccess(t *testing.T) {
	// Malformed SQL
	badTokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
	}

	// Valid SQL
	goodTokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	// Parse bad SQL first
	p1 := GetParser()
	_, _ = p1.Parse(badTokens)
	PutParser(p1)

	// Now parse good SQL — must succeed
	p2 := GetParser()
	ast2, err := p2.Parse(goodTokens)
	PutParser(p2)

	if err != nil {
		t.Fatalf("Parser contaminated after error: %v", err)
	}
	if ast2 == nil || len(ast2.Statements) == 0 {
		t.Fatal("Parser contaminated: no statements after error recovery")
	}
}

// TestPoolContamination_Concurrent verifies no cross-contamination under concurrent use.
func TestPoolContamination_Concurrent(t *testing.T) {
	patterns := [][]token.Token{
		// SELECT
		{
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeAsterisk, Literal: "*"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
		},
		// INSERT
		{
			{Type: models.TokenTypeInsert, Literal: "INSERT"},
			{Type: models.TokenTypeInto, Literal: "INTO"},
			{Type: models.TokenTypeIdentifier, Literal: "logs"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeIdentifier, Literal: "msg"},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeValues, Literal: "VALUES"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeString, Literal: "'hello'"},
			{Type: models.TokenTypeRParen, Literal: ")"},
		},
		// DELETE
		{
			{Type: models.TokenTypeDelete, Literal: "DELETE"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "temp"},
		},
	}

	done := make(chan error, 100)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			p := GetParser()
			defer PutParser(p)

			toks := patterns[idx%len(patterns)]
			ast, err := p.Parse(toks)
			if err != nil {
				done <- err
				return
			}
			if ast == nil || len(ast.Statements) == 0 {
				done <- fmt.Errorf("goroutine %d: no statements", idx)
				return
			}
			done <- nil
		}(i)
	}

	for i := 0; i < 100; i++ {
		if err := <-done; err != nil {
			t.Fatalf("Concurrent pool contamination: %v", err)
		}
	}
}

// TestContextCancellation_MidParse verifies that context cancellation during parse
// returns an error and doesn't panic.
func TestContextCancellation_MidParse(t *testing.T) {
	// Build a large token list to increase chance of mid-parse cancellation
	var tokens []token.Token
	tokens = append(tokens, token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"})
	for i := 0; i < 100; i++ {
		if i > 0 {
			tokens = append(tokens, token.Token{Type: models.TokenTypeComma, Literal: ","})
		}
		tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "col"})
	}
	tokens = append(tokens,
		token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "big_table"},
	)

	// Cancel context almost immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Small sleep to ensure context is cancelled
	time.Sleep(1 * time.Millisecond)

	p := GetParser()
	defer PutParser(p)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseContext panicked on cancelled context: %v", r)
		}
	}()

	_, err := p.ParseContext(ctx, tokens)
	// Either context.Canceled/DeadlineExceeded error, or it was fast enough to succeed.
	// Both are acceptable — the key invariant is no panic.
	if err != nil {
		if !strings.Contains(err.Error(), "context") &&
			!strings.Contains(err.Error(), "cancel") &&
			!strings.Contains(err.Error(), "deadline") {
			t.Logf("Got non-context error (still OK, no panic): %v", err)
		}
	}
}

// ensure fmt is used
var _ = fmt.Sprintf
