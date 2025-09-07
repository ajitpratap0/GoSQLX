package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Benchmark data - various SQL queries of different complexity
var benchmarkQueries = []struct {
	name string
	sql  string
}{
	{
		name: "simple_select",
		sql:  "SELECT name, email FROM users WHERE active = true",
	},
	{
		name: "select_with_join",
		sql:  "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id WHERE u.active = true",
	},
	{
		name: "complex_join",
		sql: `SELECT u.name, p.title, c.name as category 
		      FROM users u 
		      JOIN posts p ON u.id = p.user_id 
		      JOIN categories c ON p.category_id = c.id 
		      WHERE u.active = true AND p.published = true 
		      ORDER BY p.created_at DESC`,
	},
	{
		name: "window_function",
		sql: `SELECT name, salary, 
		      ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as rank,
		      LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary
		      FROM employees WHERE active = true`,
	},
	{
		name: "cte_query",
		sql: `WITH active_users AS (
		      SELECT id, name FROM users WHERE active = true
		      ),
		      recent_posts AS (
		      SELECT user_id, title FROM posts WHERE created_at > '2024-01-01'
		      )
		      SELECT au.name, rp.title 
		      FROM active_users au 
		      JOIN recent_posts rp ON au.id = rp.user_id`,
	},
}

// BenchmarkTokenConverter_Convert tests the performance of token conversion
func BenchmarkTokenConverter_Convert(b *testing.B) {
	for _, query := range benchmarkQueries {
		b.Run(query.name, func(b *testing.B) {
			// Pre-tokenize the query once
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(query.sql))
			if err != nil {
				b.Fatalf("Failed to tokenize: %v", err)
			}

			// Create converter
			converter := NewTokenConverter()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				result, err := converter.Convert(tokens)
				if err != nil {
					b.Fatalf("Conversion failed: %v", err)
				}
				if len(result.Tokens) == 0 {
					b.Fatal("No tokens converted")
				}
			}
		})
	}
}

// BenchmarkTokenConverter_ConvertLarge tests conversion with large queries
func BenchmarkTokenConverter_ConvertLarge(b *testing.B) {
	// Generate a large query with many columns and conditions
	largeQuery := `SELECT 
		u.id, u.name, u.email, u.phone, u.address, u.city, u.state, u.zip,
		p.id, p.title, p.content, p.created_at, p.updated_at, p.published,
		c.id, c.name, c.description, c.color, c.created_at,
		t.id, t.name, t.description, t.weight
	FROM users u 
		JOIN posts p ON u.id = p.user_id 
		JOIN categories c ON p.category_id = c.id
		JOIN tags t ON p.id = t.post_id
	WHERE u.active = true 
		AND p.published = true 
		AND c.active = true 
		AND t.active = true
		AND u.created_at > '2023-01-01'
		AND p.created_at > '2023-01-01'
		AND LENGTH(u.name) > 3
		AND LENGTH(p.title) > 10
	ORDER BY p.created_at DESC, u.name ASC
	LIMIT 100`

	// Pre-tokenize
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(largeQuery))
	if err != nil {
		b.Fatalf("Failed to tokenize large query: %v", err)
	}

	converter := NewTokenConverter()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := converter.Convert(tokens)
		if err != nil {
			b.Fatalf("Large query conversion failed: %v", err)
		}
		if len(result.Tokens) == 0 {
			b.Fatal("No tokens converted for large query")
		}
	}
}

// BenchmarkTokenConverter_ConvertParallel tests concurrent token conversion
func BenchmarkTokenConverter_ConvertParallel(b *testing.B) {
	// Use a moderately complex query for parallel testing
	sql := `SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id WHERE u.active = true`

	// Pre-tokenize
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("Failed to tokenize: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		converter := NewTokenConverter() // Each goroutine gets its own converter

		for pb.Next() {
			result, err := converter.Convert(tokens)
			if err != nil {
				b.Fatalf("Parallel conversion failed: %v", err)
			}
			if len(result.Tokens) == 0 {
				b.Fatal("No tokens converted in parallel")
			}
		}
	})
}

// BenchmarkTokenConverter_MemoryReuse tests memory reuse efficiency
func BenchmarkTokenConverter_MemoryReuse(b *testing.B) {
	sql := "SELECT name FROM users WHERE active = true"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("Failed to tokenize: %v", err)
	}

	// Test reusing the same converter instance
	converter := NewTokenConverter()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := converter.Convert(tokens)
		if err != nil {
			b.Fatalf("Memory reuse conversion failed: %v", err)
		}
		if len(result.Tokens) == 0 {
			b.Fatal("No tokens converted in memory reuse test")
		}
	}
}

// BenchmarkConvertTokensForParser tests the convenience function
func BenchmarkConvertTokensForParser(b *testing.B) {
	sql := "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id WHERE u.active = true"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("Failed to tokenize: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := ConvertTokensForParser(tokens)
		if err != nil {
			b.Fatalf("ConvertTokensForParser failed: %v", err)
		}
		if len(result) == 0 {
			b.Fatal("No tokens converted by ConvertTokensForParser")
		}
	}
}

// BenchmarkTokenTypeMapping tests type mapping performance
func BenchmarkTokenTypeMapping(b *testing.B) {
	// Create a converter to test its type mapping
	converter := NewTokenConverter()

	// Common token types to test
	testTokens := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeKeyword, Value: "SELECT"}},
		{Token: models.Token{Type: models.TokenTypeKeyword, Value: "FROM"}},
		{Token: models.Token{Type: models.TokenTypeKeyword, Value: "WHERE"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "users"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "name"}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "'test'"}},
		{Token: models.Token{Type: models.TokenTypeNumber, Value: "123"}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: "="}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: ">"}},
		{Token: models.Token{Type: models.TokenTypeComma, Value: ","}},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := converter.Convert(testTokens)
		if err != nil {
			b.Fatalf("Type mapping test failed: %v", err)
		}
	}
}

// BenchmarkTokenConverter_RobustHandling tests performance with edge cases
func BenchmarkTokenConverter_RobustHandling(b *testing.B) {
	converter := NewTokenConverter()

	// Create tokens with unusual but valid types
	edgeCaseTokens := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeKeyword, Value: "SELECT"}},
		{Token: models.Token{Type: models.TokenTypeUnknown, Value: "unknown"}}, // Unknown type
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "name"}},
		{Token: models.Token{Type: models.TokenTypeWhitespace, Value: " "}}, // Whitespace
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := converter.Convert(edgeCaseTokens)
		if err != nil {
			b.Fatalf("Robust handling test failed: %v", err)
		}
		if len(result.Tokens) == 0 {
			b.Fatal("No tokens converted in robust handling test")
		}
	}
}

// BenchmarkCompareConversionMethods compares different conversion approaches
func BenchmarkCompareConversionMethods(b *testing.B) {
	sql := "SELECT name, email FROM users WHERE active = true"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("Failed to tokenize: %v", err)
	}

	b.Run("NewConverter", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			converter := NewTokenConverter()
			_, err := converter.Convert(tokens)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ReusedConverter", func(b *testing.B) {
		converter := NewTokenConverter()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := converter.Convert(tokens)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ConvenienceFunction", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := ConvertTokensForParser(tokens)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
