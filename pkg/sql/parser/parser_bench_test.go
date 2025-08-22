package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

var (
	// Simple SELECT query tokens
	simpleSelectTokens = []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "name"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	// Complex SELECT query with JOIN, WHERE, ORDER BY, LIMIT, OFFSET
	complexSelectTokens = []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "name"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "order_date"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "IDENT", Literal: "u"},
		{Type: "JOIN", Literal: "JOIN"},
		{Type: "IDENT", Literal: "orders"},
		{Type: "IDENT", Literal: "o"},
		{Type: "ON", Literal: "ON"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "id"},
		{Type: "=", Literal: "="},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "user_id"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "TRUE", Literal: "TRUE"},
		{Type: "ORDER", Literal: "ORDER"},
		{Type: "BY", Literal: "BY"},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "order_date"},
		{Type: "DESC", Literal: "DESC"},
		{Type: "LIMIT", Literal: "LIMIT"},
		{Type: "INT", Literal: "10"},
		{Type: "OFFSET", Literal: "OFFSET"},
		{Type: "INT", Literal: "20"},
	}

	// INSERT query tokens
	insertTokens = []token.Token{
		{Type: "INSERT", Literal: "INSERT"},
		{Type: "INTO", Literal: "INTO"},
		{Type: "IDENT", Literal: "users"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "name"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "email"},
		{Type: ")", Literal: ")"},
		{Type: "VALUES", Literal: "VALUES"},
		{Type: "(", Literal: "("},
		{Type: "STRING", Literal: "John"},
		{Type: ",", Literal: ","},
		{Type: "STRING", Literal: "john@example.com"},
		{Type: ")", Literal: ")"},
	}

	// UPDATE query tokens
	updateTokens = []token.Token{
		{Type: "UPDATE", Literal: "UPDATE"},
		{Type: "IDENT", Literal: "users"},
		{Type: "SET", Literal: "SET"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "FALSE", Literal: "FALSE"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "last_login"},
		{Type: "<", Literal: "<"},
		{Type: "STRING", Literal: "2024-01-01"},
	}

	// DELETE query tokens
	deleteTokens = []token.Token{
		{Type: "DELETE", Literal: "DELETE"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "FALSE", Literal: "FALSE"},
	}
)

// Helper function to benchmark parser with given tokens
func benchmarkParser(b *testing.B, tokens []token.Token) {
	parser := NewParser()
	defer parser.Release()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree, err := parser.Parse(tokens)
		if err != nil {
			b.Fatal(err)
		}
		if tree == nil {
			b.Fatal("expected non-nil AST")
		}
	}
}

// Helper function to benchmark parser in parallel
func benchmarkParserParallel(b *testing.B, tokens []token.Token) {
	b.RunParallel(func(pb *testing.PB) {
		parser := NewParser()
		defer parser.Release()

		for pb.Next() {
			tree, err := parser.Parse(tokens)
			if err != nil {
				b.Fatal(err)
			}
			if tree == nil {
				b.Fatal("expected non-nil AST")
			}
		}
	})
}

// Benchmark simple queries
func BenchmarkParserSimpleSelect(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, simpleSelectTokens)
}

// Benchmark complex queries
func BenchmarkParserComplexSelect(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, complexSelectTokens)
}

// Benchmark INSERT queries
func BenchmarkParserInsert(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, insertTokens)
}

// Benchmark UPDATE queries
func BenchmarkParserUpdate(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, updateTokens)
}

// Benchmark DELETE queries
func BenchmarkParserDelete(b *testing.B) {
	b.ReportAllocs()
	benchmarkParser(b, deleteTokens)
}

// Benchmark parallel execution
func BenchmarkParserSimpleSelectParallel(b *testing.B) {
	b.ReportAllocs()
	benchmarkParserParallel(b, simpleSelectTokens)
}

func BenchmarkParserComplexSelectParallel(b *testing.B) {
	b.ReportAllocs()
	benchmarkParserParallel(b, complexSelectTokens)
}

// Benchmark parser reuse
func BenchmarkParserReuse(b *testing.B) {
	b.ReportAllocs()
	parser := NewParser()
	defer parser.Release()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Parse different types of queries with the same parser instance
		queries := [][]token.Token{
			simpleSelectTokens,
			complexSelectTokens,
			insertTokens,
			updateTokens,
			deleteTokens,
		}

		for _, tokens := range queries {
			tree, err := parser.Parse(tokens)
			if err != nil {
				b.Fatal(err)
			}
			if tree == nil {
				b.Fatal("expected non-nil AST")
			}
		}
	}
}

// Benchmark parser with mixed workload in parallel
func BenchmarkParserMixedParallel(b *testing.B) {
	queries := [][]token.Token{
		simpleSelectTokens,
		complexSelectTokens,
		insertTokens,
		updateTokens,
		deleteTokens,
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		parser := NewParser()
		defer parser.Release()

		i := 0
		for pb.Next() {
			tokens := queries[i%len(queries)]
			tree, err := parser.Parse(tokens)
			if err != nil {
				b.Fatal(err)
			}
			if tree == nil {
				b.Fatal("expected non-nil AST")
			}
			i++
		}
	})
}
