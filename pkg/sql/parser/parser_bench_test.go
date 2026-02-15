package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

var (
	// Simple SELECT query tokens - with Type for fast int comparison path
	simpleSelectTokens = []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	// Complex SELECT query with JOIN, WHERE, ORDER BY, LIMIT, OFFSET
	complexSelectTokens = []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "order_date"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypeJoin, Literal: "JOIN"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeTrue, Literal: "TRUE"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "order_date"},
		{Type: models.TokenTypeDesc, Literal: "DESC"},
		{Type: models.TokenTypeLimit, Literal: "LIMIT"},
		{Type: models.TokenTypeNumber, Literal: "10"},
		{Type: models.TokenTypeOffset, Literal: "OFFSET"},
		{Type: models.TokenTypeNumber, Literal: "20"},
	}

	// INSERT query tokens
	insertTokens = []token.Token{
		{Type: models.TokenTypeInsert, Literal: "INSERT"},
		{Type: models.TokenTypeInto, Literal: "INTO"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "email"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeValues, Literal: "VALUES"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeString, Literal: "John"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeString, Literal: "john@example.com"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	// UPDATE query tokens
	updateTokens = []token.Token{
		{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeSet, Literal: "SET"},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeFalse, Literal: "FALSE"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "last_login"},
		{Type: models.TokenTypeLt, Literal: "<"},
		{Type: models.TokenTypeString, Literal: "2024-01-01"},
	}

	// DELETE query tokens
	deleteTokens = []token.Token{
		{Type: models.TokenTypeDelete, Literal: "DELETE"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeFalse, Literal: "FALSE"},
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

// BenchmarkParser_RecursionDepthCheck measures the performance impact of recursion depth checking.
// This benchmark compares parsing with depth checks enabled (current implementation) to verify
// that the overhead is negligible (<1% as specified in requirements).
func BenchmarkParser_RecursionDepthCheck(b *testing.B) {
	// Test with various query complexities to ensure depth checking overhead is minimal
	testCases := []struct {
		name   string
		tokens []token.Token
	}{
		{
			name:   "SimpleSelect",
			tokens: simpleSelectTokens,
		},
		{
			name:   "ComplexSelect",
			tokens: complexSelectTokens,
		},
		{
			name: "ModerateNesting",
			tokens: func() []token.Token {
				// Build a moderately nested query (20 levels) - realistic usage
				tokens := []token.Token{{Type: models.TokenTypeSelect, Literal: "SELECT"}}
				for i := 0; i < 20; i++ {
					tokens = append(tokens,
						token.Token{Type: models.TokenTypeIdentifier, Literal: "func"},
						token.Token{Type: models.TokenTypeLParen, Literal: "("},
					)
				}
				tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "x"})
				for i := 0; i < 20; i++ {
					tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
				}
				tokens = append(tokens,
					token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
					token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
				)
				return tokens
			}(),
		},
		{
			name: "DeepNesting80",
			tokens: func() []token.Token {
				// Build a deeply nested query (80 levels) - approaching limit
				// Tests performance near MaxRecursionDepth (100 levels)
				tokens := []token.Token{{Type: models.TokenTypeSelect, Literal: "SELECT"}}
				for i := 0; i < 80; i++ {
					tokens = append(tokens,
						token.Token{Type: models.TokenTypeIdentifier, Literal: "func"},
						token.Token{Type: models.TokenTypeLParen, Literal: "("},
					)
				}
				tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "x"})
				for i := 0; i < 80; i++ {
					tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
				}
				tokens = append(tokens,
					token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
					token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
				)
				return tokens
			}(),
		},
		{
			name: "DeepNesting90",
			tokens: func() []token.Token {
				// Build a very deeply nested query (90 levels) - near limit threshold
				// Tests performance at 90% of MaxRecursionDepth (100 levels)
				tokens := []token.Token{{Type: models.TokenTypeSelect, Literal: "SELECT"}}
				for i := 0; i < 90; i++ {
					tokens = append(tokens,
						token.Token{Type: models.TokenTypeIdentifier, Literal: "func"},
						token.Token{Type: models.TokenTypeLParen, Literal: "("},
					)
				}
				tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "x"})
				for i := 0; i < 90; i++ {
					tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
				}
				tokens = append(tokens,
					token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
					token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
				)
				return tokens
			}(),
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			parser := NewParser()
			defer parser.Release()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tree, err := parser.Parse(tc.tokens)
				if err != nil {
					b.Fatal(err)
				}
				if tree == nil {
					b.Fatal("expected non-nil AST")
				}
			}
		})
	}
}
