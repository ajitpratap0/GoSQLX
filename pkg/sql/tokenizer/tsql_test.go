package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// newSQLServerTokenizer is a test helper that creates a SQL Server dialect tokenizer.
func newSQLServerTokenizer(t *testing.T) *Tokenizer {
	t.Helper()
	tkz, err := NewWithDialect(keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("NewWithDialect(sqlserver) error = %v", err)
	}
	return tkz
}

// tokenize is a test helper that tokenizes input and strips the trailing EOF.
func tokenize(t *testing.T, tkz *Tokenizer, input string) []models.TokenWithSpan {
	t.Helper()
	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize(%q) error = %v", input, err)
	}
	// Strip trailing EOF
	if len(tokens) > 0 && tokens[len(tokens)-1].Token.Type == models.TokenTypeEOF {
		tokens = tokens[:len(tokens)-1]
	}
	return tokens
}

func TestTSQL_TempTableIdentifiers(t *testing.T) {
	tkz := newSQLServerTokenizer(t)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"local temp table", "#temp", "#temp"},
		{"global temp table", "##global_temp", "##global_temp"},
		{"temp table in SELECT", "SELECT * FROM #orders", "#orders"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenize(t, tkz, tt.input)
			// Find the identifier token with # prefix
			found := false
			for _, tok := range tokens {
				if tok.Token.Value == tt.want {
					if tok.Token.Type != models.TokenTypeIdentifier {
						t.Errorf("expected TokenTypeIdentifier for %q, got %v", tt.want, tok.Token.Type)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("did not find token with value %q in tokens:", tt.want)
				for i, tok := range tokens {
					t.Logf("  [%d] type=%v value=%q", i, tok.Token.Type, tok.Token.Value)
				}
			}
		})
	}
}

func TestTSQL_TempTableStandaloneHash(t *testing.T) {
	// In SQL Server dialect, a standalone # (not followed by identifier) should still be TokenTypeSharp
	tkz := newSQLServerTokenizer(t)
	tokens := tokenize(t, tkz, "# ")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeSharp {
		t.Errorf("expected TokenTypeSharp, got %v", tokens[0].Token.Type)
	}
}

func TestTSQL_TempTableNotInPostgreSQL(t *testing.T) {
	// In PostgreSQL dialect, #temp should NOT be a single identifier
	tkz, err := NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("NewWithDialect error = %v", err)
	}
	tokens := tokenize(t, tkz, "#temp")
	// Should be SHARP + IDENTIFIER (2 tokens)
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens for PostgreSQL #temp, got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeSharp {
		t.Errorf("expected TokenTypeSharp, got %v", tokens[0].Token.Type)
	}
}

func TestTSQL_GlobalVariables(t *testing.T) {
	tkz := newSQLServerTokenizer(t)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"@@ROWCOUNT", "@@ROWCOUNT", "@@ROWCOUNT"},
		{"@@IDENTITY", "@@IDENTITY", "@@IDENTITY"},
		{"@@ERROR", "SELECT @@ERROR", "@@ERROR"},
		{"@@VERSION", "@@VERSION", "@@VERSION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenize(t, tkz, tt.input)
			found := false
			for _, tok := range tokens {
				if tok.Token.Value == tt.want {
					if tok.Token.Type != models.TokenTypeIdentifier {
						t.Errorf("expected TokenTypeIdentifier for %q, got %v", tt.want, tok.Token.Type)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("did not find token with value %q in tokens:", tt.want)
				for i, tok := range tokens {
					t.Logf("  [%d] type=%v value=%q", i, tok.Token.Type, tok.Token.Value)
				}
			}
		})
	}
}

func TestTSQL_AtAtStillWorksInPostgreSQL(t *testing.T) {
	// In PostgreSQL dialect, @@ should still be TokenTypeAtAt
	tkz, err := NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("NewWithDialect error = %v", err)
	}
	tokens := tokenize(t, tkz, "@@")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeAtAt {
		t.Errorf("expected TokenTypeAtAt, got %v", tokens[0].Token.Type)
	}
}

func TestTSQL_NationalStringLiteral(t *testing.T) {
	tkz := newSQLServerTokenizer(t)

	tests := []struct {
		name      string
		input     string
		wantValue string
	}{
		{"N'hello'", "N'hello'", "hello"},
		{"n'hello' lowercase", "n'hello'", "hello"},
		{"N'unicode chars'", "N'こんにちは'", "こんにちは"},
		{"N'' empty", "N''", ""},
		{"in expression", "SELECT N'test'", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenize(t, tkz, tt.input)
			found := false
			for _, tok := range tokens {
				if tok.Token.Type == models.TokenTypeNationalStringLiteral {
					if tok.Token.Value != tt.wantValue {
						t.Errorf("expected value %q, got %q", tt.wantValue, tok.Token.Value)
					}
					if tok.Token.Quote != 'N' {
						t.Errorf("expected Quote='N', got %q", tok.Token.Quote)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("did not find TokenTypeNationalStringLiteral in tokens:")
				for i, tok := range tokens {
					t.Logf("  [%d] type=%v value=%q", i, tok.Token.Type, tok.Token.Value)
				}
			}
		})
	}
}

func TestTSQL_NWithoutQuoteIsIdentifier(t *testing.T) {
	// N not followed by quote should be a regular identifier
	tkz := newSQLServerTokenizer(t)
	tokens := tokenize(t, tkz, "N")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	// N should be an identifier (not a keyword in the map)
	if tokens[0].Token.Type != models.TokenTypeIdentifier {
		t.Errorf("expected TokenTypeIdentifier for bare N, got %v", tokens[0].Token.Type)
	}
}

func TestTSQL_NStringNotInPostgreSQL(t *testing.T) {
	// In PostgreSQL dialect, N'hello' should be IDENTIFIER + STRING (two tokens)
	tkz, err := NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("NewWithDialect error = %v", err)
	}
	tokens := tokenize(t, tkz, "N'hello'")
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens for PostgreSQL N'hello', got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeIdentifier {
		t.Errorf("expected first token to be identifier, got %v", tokens[0].Token.Type)
	}
}

func TestTSQL_BracketIdentifierUnterminatedStructuredError(t *testing.T) {
	tkz := newSQLServerTokenizer(t)
	_, err := tkz.Tokenize([]byte("[unterminated"))
	if err == nil {
		t.Fatal("expected error for unterminated bracket identifier, got nil")
	}

	tokErr, ok := err.(*errors.Error)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if tokErr.Code != errors.ErrCodeInvalidSyntax {
		t.Errorf("expected error code %v, got %v", errors.ErrCodeInvalidSyntax, tokErr.Code)
	}
}

func TestTSQL_BracketIdentifierValid(t *testing.T) {
	tkz := newSQLServerTokenizer(t)
	tokens := tokenize(t, tkz, "[My Column]")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeIdentifier {
		t.Errorf("expected TokenTypeIdentifier, got %v", tokens[0].Token.Type)
	}
	if tokens[0].Token.Value != "My Column" {
		t.Errorf("expected value 'My Column', got %q", tokens[0].Token.Value)
	}
}
