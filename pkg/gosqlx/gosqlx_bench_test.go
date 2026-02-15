package gosqlx

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// BenchmarkHighLevel_Parse benchmarks the high-level gosqlx.Parse() API
func BenchmarkHighLevel_Parse(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE age > 18"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLowLevel_Parse benchmarks the low-level tokenizer+parser API
func BenchmarkLowLevel_Parse(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE age > 18"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p := parser.NewParser()
		_, err = p.ParseFromModelTokens(tokens)
		if err != nil {
			p.Release()
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p.Release()
		tokenizer.PutTokenizer(tkz)
	}
}

// BenchmarkHighLevel_ParseSimple benchmarks simple SELECT
func BenchmarkHighLevel_ParseSimple(b *testing.B) {
	sql := "SELECT * FROM users"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLowLevel_ParseSimple benchmarks simple SELECT with low-level API
func BenchmarkLowLevel_ParseSimple(b *testing.B) {
	sql := "SELECT * FROM users"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p := parser.NewParser()
		_, err = p.ParseFromModelTokens(tokens)
		if err != nil {
			p.Release()
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p.Release()
		tokenizer.PutTokenizer(tkz)
	}
}

// BenchmarkHighLevel_ParseComplex benchmarks complex query
func BenchmarkHighLevel_ParseComplex(b *testing.B) {
	sql := `
		SELECT
			u.id, u.name, u.email,
			COUNT(o.id) as order_count
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true
		GROUP BY u.id, u.name, u.email
		ORDER BY order_count DESC
		LIMIT 10
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLowLevel_ParseComplex benchmarks complex query with low-level API
func BenchmarkLowLevel_ParseComplex(b *testing.B) {
	sql := `
		SELECT
			u.id, u.name, u.email,
			COUNT(o.id) as order_count
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true
		GROUP BY u.id, u.name, u.email
		ORDER BY order_count DESC
		LIMIT 10
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p := parser.NewParser()
		_, err = p.ParseFromModelTokens(tokens)
		if err != nil {
			p.Release()
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p.Release()
		tokenizer.PutTokenizer(tkz)
	}
}

// BenchmarkHighLevel_ParseWindowFunction benchmarks window functions
func BenchmarkHighLevel_ParseWindowFunction(b *testing.B) {
	sql := "SELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLowLevel_ParseWindowFunction benchmarks window functions with low-level API
func BenchmarkLowLevel_ParseWindowFunction(b *testing.B) {
	sql := "SELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p := parser.NewParser()
		_, err = p.ParseFromModelTokens(tokens)
		if err != nil {
			p.Release()
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p.Release()
		tokenizer.PutTokenizer(tkz)
	}
}

// BenchmarkHighLevel_ParseCTE benchmarks CTE queries
func BenchmarkHighLevel_ParseCTE(b *testing.B) {
	sql := `
		WITH active_users AS (
			SELECT * FROM users WHERE active = true
		)
		SELECT * FROM active_users
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLowLevel_ParseCTE benchmarks CTE queries with low-level API
func BenchmarkLowLevel_ParseCTE(b *testing.B) {
	sql := `
		WITH active_users AS (
			SELECT * FROM users WHERE active = true
		)
		SELECT * FROM active_users
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p := parser.NewParser()
		_, err = p.ParseFromModelTokens(tokens)
		if err != nil {
			p.Release()
			tokenizer.PutTokenizer(tkz)
			b.Fatal(err)
		}

		p.Release()
		tokenizer.PutTokenizer(tkz)
	}
}

// BenchmarkHighLevel_Validate benchmarks validation
func BenchmarkHighLevel_Validate(b *testing.B) {
	sql := "SELECT * FROM users WHERE active = true"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Validate(sql)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHighLevel_ParseMultiple benchmarks batch parsing
func BenchmarkHighLevel_ParseMultiple(b *testing.B) {
	queries := []string{
		"SELECT * FROM users",
		"SELECT * FROM orders",
		"SELECT * FROM products",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseMultiple(queries)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLowLevel_ParseMultiple benchmarks batch parsing with low-level API
func BenchmarkLowLevel_ParseMultiple(b *testing.B) {
	queries := []string{
		"SELECT * FROM users",
		"SELECT * FROM orders",
		"SELECT * FROM products",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sql := range queries {
			tkz := tokenizer.GetTokenizer()
			tokens, err := tkz.Tokenize([]byte(sql))
			if err != nil {
				tokenizer.PutTokenizer(tkz)
				b.Fatal(err)
			}

			p := parser.NewParser()
			_, err = p.ParseFromModelTokens(tokens)
			if err != nil {
				p.Release()
				tokenizer.PutTokenizer(tkz)
				b.Fatal(err)
			}

			p.Release()
			tokenizer.PutTokenizer(tkz)
		}
	}
}

// BenchmarkHighLevel_ParseBytes benchmarks ParseBytes
func BenchmarkHighLevel_ParseBytes(b *testing.B) {
	sqlBytes := []byte("SELECT * FROM users WHERE active = true")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseBytes(sqlBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}
