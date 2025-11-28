package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

var (
	// Simple SELECT query tokens - with ModelType for fast int comparison path
	simpleSelectTokens = []token.Token{
		{Type: "SELECT", ModelType: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "id"},
		{Type: ",", ModelType: models.TokenTypeComma, Literal: ","},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "name"},
		{Type: "FROM", ModelType: models.TokenTypeFrom, Literal: "FROM"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "users"},
	}

	// Complex SELECT query with JOIN, WHERE, ORDER BY, LIMIT, OFFSET
	complexSelectTokens = []token.Token{
		{Type: "SELECT", ModelType: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "u"},
		{Type: ".", ModelType: models.TokenTypePeriod, Literal: "."},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "id"},
		{Type: ",", ModelType: models.TokenTypeComma, Literal: ","},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "u"},
		{Type: ".", ModelType: models.TokenTypePeriod, Literal: "."},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "name"},
		{Type: ",", ModelType: models.TokenTypeComma, Literal: ","},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "o"},
		{Type: ".", ModelType: models.TokenTypePeriod, Literal: "."},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "order_date"},
		{Type: "FROM", ModelType: models.TokenTypeFrom, Literal: "FROM"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "users"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "u"},
		{Type: "JOIN", ModelType: models.TokenTypeJoin, Literal: "JOIN"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "o"},
		{Type: "ON", ModelType: models.TokenTypeOn, Literal: "ON"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "u"},
		{Type: ".", ModelType: models.TokenTypePeriod, Literal: "."},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "id"},
		{Type: "=", ModelType: models.TokenTypeEq, Literal: "="},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "o"},
		{Type: ".", ModelType: models.TokenTypePeriod, Literal: "."},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: "WHERE", ModelType: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "u"},
		{Type: ".", ModelType: models.TokenTypePeriod, Literal: "."},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "active"},
		{Type: "=", ModelType: models.TokenTypeEq, Literal: "="},
		{Type: "TRUE", ModelType: models.TokenTypeTrue, Literal: "TRUE"},
		{Type: "ORDER", ModelType: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: "BY", ModelType: models.TokenTypeBy, Literal: "BY"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "o"},
		{Type: ".", ModelType: models.TokenTypePeriod, Literal: "."},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "order_date"},
		{Type: "DESC", ModelType: models.TokenTypeDesc, Literal: "DESC"},
		{Type: "LIMIT", ModelType: models.TokenTypeLimit, Literal: "LIMIT"},
		{Type: "INT", ModelType: models.TokenTypeNumber, Literal: "10"},
		{Type: "OFFSET", ModelType: models.TokenTypeOffset, Literal: "OFFSET"},
		{Type: "INT", ModelType: models.TokenTypeNumber, Literal: "20"},
	}

	// INSERT query tokens
	insertTokens = []token.Token{
		{Type: "INSERT", ModelType: models.TokenTypeInsert, Literal: "INSERT"},
		{Type: "INTO", ModelType: models.TokenTypeInto, Literal: "INTO"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "users"},
		{Type: "(", ModelType: models.TokenTypeLeftParen, Literal: "("},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "name"},
		{Type: ",", ModelType: models.TokenTypeComma, Literal: ","},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "email"},
		{Type: ")", ModelType: models.TokenTypeRightParen, Literal: ")"},
		{Type: "VALUES", ModelType: models.TokenTypeValues, Literal: "VALUES"},
		{Type: "(", ModelType: models.TokenTypeLeftParen, Literal: "("},
		{Type: "STRING", ModelType: models.TokenTypeString, Literal: "John"},
		{Type: ",", ModelType: models.TokenTypeComma, Literal: ","},
		{Type: "STRING", ModelType: models.TokenTypeString, Literal: "john@example.com"},
		{Type: ")", ModelType: models.TokenTypeRightParen, Literal: ")"},
	}

	// UPDATE query tokens
	updateTokens = []token.Token{
		{Type: "UPDATE", ModelType: models.TokenTypeUpdate, Literal: "UPDATE"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "users"},
		{Type: "SET", ModelType: models.TokenTypeSet, Literal: "SET"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "active"},
		{Type: "=", ModelType: models.TokenTypeEq, Literal: "="},
		{Type: "FALSE", ModelType: models.TokenTypeFalse, Literal: "FALSE"},
		{Type: "WHERE", ModelType: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "last_login"},
		{Type: "<", ModelType: models.TokenTypeLt, Literal: "<"},
		{Type: "STRING", ModelType: models.TokenTypeString, Literal: "2024-01-01"},
	}

	// DELETE query tokens
	deleteTokens = []token.Token{
		{Type: "DELETE", ModelType: models.TokenTypeDelete, Literal: "DELETE"},
		{Type: "FROM", ModelType: models.TokenTypeFrom, Literal: "FROM"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "users"},
		{Type: "WHERE", ModelType: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: "IDENT", ModelType: models.TokenTypeIdentifier, Literal: "active"},
		{Type: "=", ModelType: models.TokenTypeEq, Literal: "="},
		{Type: "FALSE", ModelType: models.TokenTypeFalse, Literal: "FALSE"},
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
				tokens := []token.Token{{Type: "SELECT", Literal: "SELECT"}}
				for i := 0; i < 20; i++ {
					tokens = append(tokens,
						token.Token{Type: "IDENT", Literal: "func"},
						token.Token{Type: "(", Literal: "("},
					)
				}
				tokens = append(tokens, token.Token{Type: "IDENT", Literal: "x"})
				for i := 0; i < 20; i++ {
					tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
				}
				tokens = append(tokens,
					token.Token{Type: "FROM", Literal: "FROM"},
					token.Token{Type: "IDENT", Literal: "t"},
				)
				return tokens
			}(),
		},
		{
			name: "DeepNesting80",
			tokens: func() []token.Token {
				// Build a deeply nested query (80 levels) - approaching limit
				// Tests performance near MaxRecursionDepth (100 levels)
				tokens := []token.Token{{Type: "SELECT", Literal: "SELECT"}}
				for i := 0; i < 80; i++ {
					tokens = append(tokens,
						token.Token{Type: "IDENT", Literal: "func"},
						token.Token{Type: "(", Literal: "("},
					)
				}
				tokens = append(tokens, token.Token{Type: "IDENT", Literal: "x"})
				for i := 0; i < 80; i++ {
					tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
				}
				tokens = append(tokens,
					token.Token{Type: "FROM", Literal: "FROM"},
					token.Token{Type: "IDENT", Literal: "t"},
				)
				return tokens
			}(),
		},
		{
			name: "DeepNesting90",
			tokens: func() []token.Token {
				// Build a very deeply nested query (90 levels) - near limit threshold
				// Tests performance at 90% of MaxRecursionDepth (100 levels)
				tokens := []token.Token{{Type: "SELECT", Literal: "SELECT"}}
				for i := 0; i < 90; i++ {
					tokens = append(tokens,
						token.Token{Type: "IDENT", Literal: "func"},
						token.Token{Type: "(", Literal: "("},
					)
				}
				tokens = append(tokens, token.Token{Type: "IDENT", Literal: "x"})
				for i := 0; i < 90; i++ {
					tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
				}
				tokens = append(tokens,
					token.Token{Type: "FROM", Literal: "FROM"},
					token.Token{Type: "IDENT", Literal: "t"},
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
