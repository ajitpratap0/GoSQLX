package tokenizer

import (
	"context"
	"testing"
)

// Benchmark tokenization without context
func BenchmarkTokenize_WithoutContext(b *testing.B) {
	sql := []byte("SELECT id, name, email, created_at FROM users WHERE active = true AND role = 'admin' ORDER BY created_at DESC LIMIT 100")
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.Tokenize(sql)
		if err != nil {
			b.Fatalf("Tokenize() error = %v", err)
		}
	}
}

// Benchmark tokenization with context (background)
func BenchmarkTokenize_WithContext(b *testing.B) {
	sql := []byte("SELECT id, name, email, created_at FROM users WHERE active = true AND role = 'admin' ORDER BY created_at DESC LIMIT 100")
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.TokenizeContext(ctx, sql)
		if err != nil {
			b.Fatalf("TokenizeContext() error = %v", err)
		}
	}
}

// Benchmark simple query without context
func BenchmarkTokenize_SimpleQuery_WithoutContext(b *testing.B) {
	sql := []byte("SELECT * FROM users")
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.Tokenize(sql)
		if err != nil {
			b.Fatalf("Tokenize() error = %v", err)
		}
	}
}

// Benchmark simple query with context
func BenchmarkTokenize_SimpleQuery_WithContext(b *testing.B) {
	sql := []byte("SELECT * FROM users")
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.TokenizeContext(ctx, sql)
		if err != nil {
			b.Fatalf("TokenizeContext() error = %v", err)
		}
	}
}

// Benchmark complex query without context
func BenchmarkTokenize_ComplexQuery_WithoutContext(b *testing.B) {
	sql := []byte(`
		SELECT
			u.id, u.name, u.email, u.created_at,
			o.id, o.total, o.status, o.created_at,
			p.name, p.price, p.category
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		LEFT JOIN products p ON o.product_id = p.id
		WHERE u.active = true
		  AND u.created_at > '2020-01-01'
		  AND o.status IN ('completed', 'shipped')
		GROUP BY u.id, o.id, p.id
		HAVING COUNT(o.id) > 5
		ORDER BY u.created_at DESC, o.total DESC
		LIMIT 100 OFFSET 0
	`)
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.Tokenize(sql)
		if err != nil {
			b.Fatalf("Tokenize() error = %v", err)
		}
	}
}

// Benchmark complex query with context
func BenchmarkTokenize_ComplexQuery_WithContext(b *testing.B) {
	sql := []byte(`
		SELECT
			u.id, u.name, u.email, u.created_at,
			o.id, o.total, o.status, o.created_at,
			p.name, p.price, p.category
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		LEFT JOIN products p ON o.product_id = p.id
		WHERE u.active = true
		  AND u.created_at > '2020-01-01'
		  AND o.status IN ('completed', 'shipped')
		GROUP BY u.id, o.id, p.id
		HAVING COUNT(o.id) > 5
		ORDER BY u.created_at DESC, o.total DESC
		LIMIT 100 OFFSET 0
	`)
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.TokenizeContext(ctx, sql)
		if err != nil {
			b.Fatalf("TokenizeContext() error = %v", err)
		}
	}
}

// Benchmark CTE query without context
func BenchmarkTokenize_CTEQuery_WithoutContext(b *testing.B) {
	sql := []byte(`
		WITH active_users AS (
			SELECT id, name, email FROM users WHERE active = true
		),
		recent_orders AS (
			SELECT user_id, COUNT(*) as order_count FROM orders WHERE created_at > '2023-01-01' GROUP BY user_id
		)
		SELECT au.name, ro.order_count
		FROM active_users au
		LEFT JOIN recent_orders ro ON au.id = ro.user_id
	`)
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.Tokenize(sql)
		if err != nil {
			b.Fatalf("Tokenize() error = %v", err)
		}
	}
}

// Benchmark CTE query with context
func BenchmarkTokenize_CTEQuery_WithContext(b *testing.B) {
	sql := []byte(`
		WITH active_users AS (
			SELECT id, name, email FROM users WHERE active = true
		),
		recent_orders AS (
			SELECT user_id, COUNT(*) as order_count FROM orders WHERE created_at > '2023-01-01' GROUP BY user_id
		)
		SELECT au.name, ro.order_count
		FROM active_users au
		LEFT JOIN recent_orders ro ON au.id = ro.user_id
	`)
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tkz.TokenizeContext(ctx, sql)
		if err != nil {
			b.Fatalf("TokenizeContext() error = %v", err)
		}
	}
}

// Benchmark parallel tokenization without context
func BenchmarkTokenize_Parallel_WithoutContext(b *testing.B) {
	sql := []byte("SELECT id, name, email FROM users WHERE active = true")

	b.RunParallel(func(pb *testing.PB) {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		for pb.Next() {
			_, err := tkz.Tokenize(sql)
			if err != nil {
				b.Fatalf("Tokenize() error = %v", err)
			}
		}
	})
}

// Benchmark parallel tokenization with context
func BenchmarkTokenize_Parallel_WithContext(b *testing.B) {
	sql := []byte("SELECT id, name, email FROM users WHERE active = true")
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		for pb.Next() {
			_, err := tkz.TokenizeContext(ctx, sql)
			if err != nil {
				b.Fatalf("TokenizeContext() error = %v", err)
			}
		}
	})
}
