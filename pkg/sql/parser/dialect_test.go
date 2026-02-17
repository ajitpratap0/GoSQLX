package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParserWithDialectOption(t *testing.T) {
	p := NewParser(WithDialect("mysql"))
	if p.Dialect() != "mysql" {
		t.Errorf("expected mysql, got %s", p.Dialect())
	}

	p2 := NewParser()
	if p2.Dialect() != "postgresql" {
		t.Errorf("expected postgresql default, got %s", p2.Dialect())
	}
}

func TestTokenizerWithDialect(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect(keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	if tkz.Dialect() != keywords.DialectMySQL {
		t.Errorf("expected mysql, got %s", tkz.Dialect())
	}
}

func TestTokenizerSetDialect(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tkz.SetDialect(keywords.DialectMySQL)
	if tkz.Dialect() != keywords.DialectMySQL {
		t.Errorf("expected mysql, got %s", tkz.Dialect())
	}
}

func TestTokenizerDefaultDialect(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect("")
	if err != nil {
		t.Fatal(err)
	}
	if tkz.Dialect() != keywords.DialectPostgreSQL {
		t.Errorf("expected postgresql default, got %s", tkz.Dialect())
	}
}

func TestParseWithDialect(t *testing.T) {
	// Basic SQL should parse with any dialect
	for _, dialect := range []keywords.SQLDialect{
		keywords.DialectPostgreSQL,
		keywords.DialectMySQL,
		keywords.DialectSQLServer,
	} {
		t.Run(string(dialect), func(t *testing.T) {
			ast, err := ParseWithDialect("SELECT 1", dialect)
			if err != nil {
				t.Fatalf("ParseWithDialect(%s) failed: %v", dialect, err)
			}
			if ast == nil {
				t.Fatal("expected non-nil AST")
			}
		})
	}
}

func TestValidateWithDialect(t *testing.T) {
	err := ValidateWithDialect("SELECT * FROM users WHERE id = 1", keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ValidateWithDialect(mysql) failed: %v", err)
	}

	err = ValidateWithDialect("SELECT * FROM users WHERE id = 1", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("ValidateWithDialect(postgresql) failed: %v", err)
	}
}

func TestDefaultBehaviorUnchanged(t *testing.T) {
	// Validate() without dialect should still work (backward compatibility)
	err := Validate("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	ast, err := ParseBytes([]byte("SELECT 1"))
	if err != nil {
		t.Fatalf("ParseBytes() failed: %v", err)
	}
	if ast == nil {
		t.Fatal("expected non-nil AST")
	}
}

func TestMySQLKeywordsRecognized(t *testing.T) {
	// UNSIGNED is a MySQL-specific keyword; tokenizer should recognize it
	tkz, err := tokenizer.NewWithDialect(keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := tkz.Tokenize([]byte("SELECT UNSIGNED"))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}

	// Should have at least 2 tokens (SELECT, UNSIGNED)
	if len(tokens) < 2 {
		t.Fatalf("expected at least 2 tokens, got %d", len(tokens))
	}
}

func TestPostgreSQLKeywordsRecognized(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := tkz.Tokenize([]byte("SELECT ILIKE"))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}

	if len(tokens) < 2 {
		t.Fatalf("expected at least 2 tokens, got %d", len(tokens))
	}
}
