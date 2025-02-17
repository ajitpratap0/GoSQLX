package parser

import (
	"testing"

	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/token"
)

var (
	// Benchmark queries
	simpleQuery = []token.Token{
		{Type: token.SELECT, Literal: "SELECT"},
		{Type: token.IDENT, Literal: "id"},
		{Type: token.COMMA, Literal: ","},
		{Type: token.IDENT, Literal: "name"},
		{Type: token.FROM, Literal: "FROM"},
		{Type: token.IDENT, Literal: "users"},
	}

	complexQuery = generateComplexQuery()
)

func generateComplexQuery() []token.Token {
	tokens := make([]token.Token, 0, 100)
	// SELECT id, name, email, created_at
	tokens = append(tokens,
		token.Token{Type: token.SELECT, Literal: "SELECT"},
		token.Token{Type: token.IDENT, Literal: "id"},
		token.Token{Type: token.COMMA, Literal: ","},
		token.Token{Type: token.IDENT, Literal: "name"},
		token.Token{Type: token.COMMA, Literal: ","},
		token.Token{Type: token.IDENT, Literal: "email"},
		token.Token{Type: token.COMMA, Literal: ","},
		token.Token{Type: token.IDENT, Literal: "created_at"},
	)

	// FROM users
	tokens = append(tokens,
		token.Token{Type: token.FROM, Literal: "FROM"},
		token.Token{Type: token.IDENT, Literal: "users"},
	)

	// WHERE id > 1000 AND created_at >= '2024-01-01'
	tokens = append(tokens,
		token.Token{Type: token.WHERE, Literal: "WHERE"},
		token.Token{Type: token.IDENT, Literal: "id"},
		token.Token{Type: token.GT, Literal: ">"},
		token.Token{Type: token.INT, Literal: "1000"},
		token.Token{Type: token.AND, Literal: "AND"},
		token.Token{Type: token.IDENT, Literal: "created_at"},
		token.Token{Type: token.GTE, Literal: ">="},
		token.Token{Type: token.STRING, Literal: "'2024-01-01'"},
	)

	// ORDER BY created_at DESC
	tokens = append(tokens,
		token.Token{Type: token.ORDER, Literal: "ORDER"},
		token.Token{Type: token.BY, Literal: "BY"},
		token.Token{Type: token.IDENT, Literal: "created_at"},
		token.Token{Type: token.IDENT, Literal: "DESC"},
	)

	return tokens
}

// BenchmarkParserWithPool benchmarks parser with object pooling
func BenchmarkParserWithPool(b *testing.B) {
	b.Run("SimpleQuery", func(b *testing.B) {
		parser := NewParser()
		defer parser.Release()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ast := parser.Parse(simpleQuery)
			if ast == nil {
				b.Fatal("Failed to parse simple query")
			}
		}
	})

	b.Run("ComplexQuery", func(b *testing.B) {
		parser := NewParser()
		defer parser.Release()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ast := parser.Parse(complexQuery)
			if ast == nil {
				b.Fatal("Failed to parse complex query")
			}
		}
	})
}

// BenchmarkTokenPool benchmarks token pool operations
func BenchmarkTokenPool(b *testing.B) {
	b.Run("GetPut", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			t := token.Get()
			t.Type = token.SELECT
			t.Literal = "SELECT"
			token.Put(t)
		}
	})

	b.Run("BatchOperations", func(b *testing.B) {
		tokens := make([]*token.Token, 0, 100)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Get 100 tokens
			for j := 0; j < 100; j++ {
				t := token.Get()
				t.Type = token.IDENT
				t.Literal = "test"
				tokens = append(tokens, t)
			}

			// Return all tokens
			for _, t := range tokens {
				token.Put(t)
			}
			tokens = tokens[:0]
		}
	})
}
