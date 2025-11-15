package gosqlx

import (
	"context"
	"testing"
	"time"
)

// Benchmark parsing without context
func BenchmarkParse_WithoutContext(b *testing.B) {
	sql := "SELECT id, name, email, created_at FROM users WHERE active = true AND role = 'admin' ORDER BY created_at DESC LIMIT 100"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
	}
}

// Benchmark parsing with context (background)
func BenchmarkParse_WithContext(b *testing.B) {
	sql := "SELECT id, name, email, created_at FROM users WHERE active = true AND role = 'admin' ORDER BY created_at DESC LIMIT 100"
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseWithContext(ctx, sql)
		if err != nil {
			b.Fatalf("ParseWithContext() error = %v", err)
		}
	}
}

// Benchmark simple query without context
func BenchmarkParse_SimpleQuery_WithoutContext(b *testing.B) {
	sql := "SELECT * FROM users"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
	}
}

// Benchmark simple query with context
func BenchmarkParse_SimpleQuery_WithContext(b *testing.B) {
	sql := "SELECT * FROM users"
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseWithContext(ctx, sql)
		if err != nil {
			b.Fatalf("ParseWithContext() error = %v", err)
		}
	}
}

// Benchmark complex query without context
func BenchmarkParse_ComplexQuery_WithoutContext(b *testing.B) {
	sql := `
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
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
	}
}

// Benchmark complex query with context
func BenchmarkParse_ComplexQuery_WithContext(b *testing.B) {
	sql := `
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
	`
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseWithContext(ctx, sql)
		if err != nil {
			b.Fatalf("ParseWithContext() error = %v", err)
		}
	}
}

// Benchmark CTE query without context
func BenchmarkParse_CTEQuery_WithoutContext(b *testing.B) {
	sql := `
		WITH active_users AS (
			SELECT id, name, email FROM users WHERE active = true
		),
		recent_orders AS (
			SELECT user_id, COUNT(*) as order_count FROM orders WHERE created_at > '2023-01-01' GROUP BY user_id
		)
		SELECT au.name, ro.order_count
		FROM active_users au
		LEFT JOIN recent_orders ro ON au.id = ro.user_id
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
	}
}

// Benchmark CTE query with context
func BenchmarkParse_CTEQuery_WithContext(b *testing.B) {
	sql := `
		WITH active_users AS (
			SELECT id, name, email FROM users WHERE active = true
		),
		recent_orders AS (
			SELECT user_id, COUNT(*) as order_count FROM orders WHERE created_at > '2023-01-01' GROUP BY user_id
		)
		SELECT au.name, ro.order_count
		FROM active_users au
		LEFT JOIN recent_orders ro ON au.id = ro.user_id
	`
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseWithContext(ctx, sql)
		if err != nil {
			b.Fatalf("ParseWithContext() error = %v", err)
		}
	}
}

// Benchmark window function query without context
func BenchmarkParse_WindowFunction_WithoutContext(b *testing.B) {
	sql := `
		SELECT
			name,
			salary,
			ROW_NUMBER() OVER (ORDER BY salary DESC) as rank,
			LAG(salary, 1) OVER (ORDER BY salary) as prev_salary
		FROM employees
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(sql)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
	}
}

// Benchmark window function query with context
func BenchmarkParse_WindowFunction_WithContext(b *testing.B) {
	sql := `
		SELECT
			name,
			salary,
			ROW_NUMBER() OVER (ORDER BY salary DESC) as rank,
			LAG(salary, 1) OVER (ORDER BY salary) as prev_salary
		FROM employees
	`
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseWithContext(ctx, sql)
		if err != nil {
			b.Fatalf("ParseWithContext() error = %v", err)
		}
	}
}

// Benchmark ParseWithTimeout
func BenchmarkParseWithTimeout(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE active = true"
	timeout := 5 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseWithTimeout(sql, timeout)
		if err != nil {
			b.Fatalf("ParseWithTimeout() error = %v", err)
		}
	}
}

// Benchmark parallel parsing without context
func BenchmarkParse_Parallel_WithoutContext(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE active = true"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := Parse(sql)
			if err != nil {
				b.Fatalf("Parse() error = %v", err)
			}
		}
	})
}

// Benchmark parallel parsing with context
func BenchmarkParse_Parallel_WithContext(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE active = true"
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := ParseWithContext(ctx, sql)
			if err != nil {
				b.Fatalf("ParseWithContext() error = %v", err)
			}
		}
	})
}

// Benchmark ParseWithTimeout in parallel
func BenchmarkParseWithTimeout_Parallel(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE active = true"
	timeout := 5 * time.Second

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := ParseWithTimeout(sql, timeout)
			if err != nil {
				b.Fatalf("ParseWithTimeout() error = %v", err)
			}
		}
	})
}
