package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// BenchmarkParseWithRecovery_AllValid benchmarks recovery parsing with no errors.
func BenchmarkParseWithRecovery_AllValid(b *testing.B) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		tok("SELECT", "SELECT"), tok("INT", "2"), semi(),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		eof(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := ParseMultiWithRecovery(tokens)
		result.Release()
	}
}

// BenchmarkParseWithRecovery_Mixed benchmarks recovery parsing with mixed valid/invalid.
func BenchmarkParseWithRecovery_Mixed(b *testing.B) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		tok("IDENT", "BAD1"), tok("IDENT", "stuff"), semi(),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		tok("IDENT", "BAD2"), semi(),
		eof(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := ParseMultiWithRecovery(tokens)
		result.Release()
	}
}

// BenchmarkParseWithRecovery_AllInvalid benchmarks recovery parsing with heavy error recovery.
func BenchmarkParseWithRecovery_AllInvalid(b *testing.B) {
	tokens := []token.Token{
		tok("IDENT", "BAD1"), tok("IDENT", "x"), tok("IDENT", "y"), semi(),
		tok("IDENT", "BAD2"), tok("IDENT", "x"), semi(),
		tok("IDENT", "BAD3"), semi(),
		tok("IDENT", "BAD4"), tok("IDENT", "a"), tok("IDENT", "b"), tok("IDENT", "c"), semi(),
		eof(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := ParseMultiWithRecovery(tokens)
		result.Release()
	}
}
