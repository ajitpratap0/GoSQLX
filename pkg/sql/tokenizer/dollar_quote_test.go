package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestDollarQuotedString_Basic(t *testing.T) {
	tkz, err := New()
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := tkz.Tokenize([]byte(`$$hello$$`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be: DollarQuotedString("hello"), EOF
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeDollarQuotedString {
		t.Errorf("expected DollarQuotedString, got %v", tokens[0].Token.Type)
	}
	if tokens[0].Token.Value != "hello" {
		t.Errorf("expected 'hello', got %q", tokens[0].Token.Value)
	}
}

func TestDollarQuotedString_NamedTag(t *testing.T) {
	tkz, _ := New()

	tokens, err := tkz.Tokenize([]byte(`$fn$SELECT 1$fn$`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeDollarQuotedString {
		t.Errorf("expected DollarQuotedString, got %v", tokens[0].Token.Type)
	}
	if tokens[0].Token.Value != "SELECT 1" {
		t.Errorf("expected 'SELECT 1', got %q", tokens[0].Token.Value)
	}
}

func TestDollarQuotedString_Nested(t *testing.T) {
	tkz, _ := New()

	input := `$$outer $inner$nested$inner$ outer$$`
	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens[0].Token.Value != "outer $inner$nested$inner$ outer" {
		t.Errorf("expected nested content, got %q", tokens[0].Token.Value)
	}
}

func TestDollarQuotedString_EmptyContent(t *testing.T) {
	tkz, _ := New()

	tokens, err := tkz.Tokenize([]byte(`$$$$`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens[0].Token.Type != models.TokenTypeDollarQuotedString {
		t.Errorf("expected DollarQuotedString, got %v", tokens[0].Token.Type)
	}
	if tokens[0].Token.Value != "" {
		t.Errorf("expected empty string, got %q", tokens[0].Token.Value)
	}
}

func TestDollarQuotedString_Unterminated(t *testing.T) {
	tkz, _ := New()

	_, err := tkz.Tokenize([]byte(`$$hello`))
	if err == nil {
		t.Fatal("expected error for unterminated dollar-quoted string")
	}
}

func TestDollarQuotedString_UnterminatedNamedTag(t *testing.T) {
	tkz, _ := New()

	_, err := tkz.Tokenize([]byte(`$fn$hello`))
	if err == nil {
		t.Fatal("expected error for unterminated dollar-quoted string")
	}
}

func TestDollarQuotedString_WithNewlines(t *testing.T) {
	tkz, _ := New()

	input := "$$line1\nline2\nline3$$"
	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens[0].Token.Value != "line1\nline2\nline3" {
		t.Errorf("expected multiline content, got %q", tokens[0].Token.Value)
	}
}

func TestDollarQuotedString_WithQuotes(t *testing.T) {
	tkz, _ := New()

	input := `$$it's a "test"$$`
	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens[0].Token.Value != `it's a "test"` {
		t.Errorf("expected content with quotes, got %q", tokens[0].Token.Value)
	}
}

func TestDollarQuotedString_PositionalParamStillWorks(t *testing.T) {
	tkz, _ := New()

	tokens, err := tkz.Tokenize([]byte(`SELECT $1, $2`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SELECT, $1, COMMA, $2, EOF
	found := 0
	for _, tok := range tokens {
		if tok.Token.Type == models.TokenTypePlaceholder {
			found++
		}
	}
	if found != 2 {
		t.Errorf("expected 2 placeholders, got %d", found)
	}
}

func TestDollarQuotedString_StandaloneDollar(t *testing.T) {
	tkz, _ := New()

	// A lone $ followed by something that's not a valid tag or digit
	tokens, err := tkz.Tokenize([]byte(`$ + 1`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens[0].Token.Type != models.TokenTypePlaceholder {
		t.Errorf("expected Placeholder for standalone $, got %v", tokens[0].Token.Type)
	}
}

func TestDollarQuotedString_InContext(t *testing.T) {
	tkz, _ := New()

	input := `CREATE FUNCTION test() RETURNS void AS $$BEGIN RETURN; END;$$ LANGUAGE plpgsql`
	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the dollar-quoted string token
	found := false
	for _, tok := range tokens {
		if tok.Token.Type == models.TokenTypeDollarQuotedString {
			if tok.Token.Value != "BEGIN RETURN; END;" {
				t.Errorf("expected 'BEGIN RETURN; END;', got %q", tok.Token.Value)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("did not find DollarQuotedString token")
	}
}

func TestDollarQuotedString_MismatchedTags(t *testing.T) {
	tkz, _ := New()

	// $a$content$b$ — $a$ opens, looks for $a$ to close, won't find it
	_, err := tkz.Tokenize([]byte(`$a$content$b$`))
	if err == nil {
		t.Fatal("expected error for mismatched dollar-quote tags")
	}
}

func TestDollarQuotedString_TagWithUnderscore(t *testing.T) {
	tkz, _ := New()

	tokens, err := tkz.Tokenize([]byte(`$my_tag$content$my_tag$`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens[0].Token.Value != "content" {
		t.Errorf("expected 'content', got %q", tokens[0].Token.Value)
	}
}
