package tokenizer

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// SQL Test Cases with varying sizes and complexity
var (
	// Small SQL queries (< 1KB)
	smallSQL1KB = []byte(`SELECT id, name, email FROM users WHERE active = true`)

	// Medium SQL queries (~10KB)
	mediumSQL10KB = generateComplexSQL(10000)

	// Large SQL queries (~100KB)
	largeSQL100KB = generateComplexSQL(100000)

	// Very Large SQL queries (~1MB)
	veryLargeSQL1MB = generateComplexSQL(1000000)

	// Complex queries with different patterns
	deeplyNestedSQL     = generateDeeplyNestedSQL()
	wideJoinSQL         = generateWideJoinSQL()
	largeInClauseSQL    = generateLargeInClauseSQL()
	complexAnalyticsSQL = generateComplexAnalyticsSQL()
)

// generateComplexSQL creates SQL of approximately target size
func generateComplexSQL(targetSize int) []byte {
	baseQuery := `
	SELECT 
		u.id, u.name, u.email, u.created_at, u.updated_at,
		p.profile_id, p.bio, p.avatar_url, p.website,
		COUNT(o.id) as order_count,
		SUM(o.total) as total_spent,
		AVG(o.total) as avg_order_value,
		MAX(o.created_at) as last_order_date,
		MIN(o.created_at) as first_order_date,
		CASE 
			WHEN COUNT(o.id) > 50 THEN 'Premium'
			WHEN COUNT(o.id) > 20 THEN 'VIP'
			WHEN COUNT(o.id) > 5 THEN 'Regular'
			ELSE 'New'
		END as customer_tier,
		ROW_NUMBER() OVER (PARTITION BY u.created_at ORDER BY COUNT(o.id) DESC) as customer_rank
	FROM users u
	LEFT JOIN profiles p ON u.id = p.user_id
	LEFT JOIN orders o ON u.id = o.user_id
	LEFT JOIN order_items oi ON o.id = oi.order_id
	LEFT JOIN products pr ON oi.product_id = pr.id
	LEFT JOIN categories c ON pr.category_id = c.id
	WHERE u.created_at >= '2023-01-01'
		AND u.active = true
		AND (u.email LIKE '%@gmail.com' OR u.email LIKE '%@yahoo.com' OR u.email LIKE '%@hotmail.com')
		AND u.id NOT IN (SELECT user_id FROM banned_users WHERE banned_at > '2023-01-01')
	GROUP BY u.id, u.name, u.email, u.created_at, u.updated_at, p.profile_id, p.bio, p.avatar_url, p.website
	HAVING COUNT(o.id) > 0 
		AND SUM(o.total) > 100.00
		AND AVG(o.total) BETWEEN 10.00 AND 1000.00
	ORDER BY total_spent DESC, customer_rank ASC, u.created_at DESC
	LIMIT 1000
	OFFSET 0;
	`

	// Repeat and modify the query to reach target size
	var builder strings.Builder
	for builder.Len() < targetSize {
		builder.WriteString(baseQuery)
		builder.WriteString("\n\n")
	}

	return []byte(builder.String()[:targetSize])
}

// generateDeeplyNestedSQL creates SQL with deep subquery nesting
func generateDeeplyNestedSQL() []byte {
	return []byte(`
	SELECT u.id, u.name,
		(SELECT COUNT(*) FROM orders o1 WHERE o1.user_id = u.id AND o1.status = 'completed' AND
			o1.total > (SELECT AVG(o2.total) FROM orders o2 WHERE o2.user_id = u.id AND 
				o2.created_at > (SELECT MIN(o3.created_at) FROM orders o3 WHERE o3.user_id = u.id AND
					o3.status IN (SELECT status FROM order_statuses WHERE active = true AND
						id IN (SELECT status_id FROM user_preferences up WHERE up.user_id = u.id AND
							up.preference_type = 'order_tracking' AND
							up.enabled = true AND
							up.created_at > (SELECT registration_date FROM users WHERE id = u.id)
						)
					)
				)
			)
		) as complex_order_count,
		(SELECT SUM(oi.quantity * oi.price) FROM order_items oi 
			JOIN orders o ON oi.order_id = o.id 
			WHERE o.user_id = u.id AND
				oi.product_id IN (SELECT p.id FROM products p WHERE p.category_id IN 
					(SELECT c.id FROM categories c WHERE c.name LIKE '%electronics%' AND
						c.parent_id IN (SELECT pc.id FROM categories pc WHERE pc.level = 1 AND
							pc.created_at > (SELECT MIN(created_at) FROM categories WHERE active = true)
						)
					)
				)
		) as electronics_total
	FROM users u
	WHERE u.id IN (
		SELECT DISTINCT user_id FROM orders WHERE status = 'completed' AND
		created_at > (SELECT DATE_SUB(NOW(), INTERVAL 1 YEAR)) AND
		total > (SELECT AVG(total) FROM orders WHERE status = 'completed' AND
			user_id IN (SELECT id FROM users WHERE active = true AND
				created_at > (SELECT DATE_SUB(NOW(), INTERVAL 2 YEAR))
			)
		)
	)
	ORDER BY complex_order_count DESC, electronics_total DESC
	LIMIT 100;
	`)
}

// generateWideJoinSQL creates SQL with many joins
func generateWideJoinSQL() []byte {
	return []byte(`
	SELECT 
		u.id, u.name, u.email,
		p.bio, p.avatar_url,
		a.street, a.city, a.state, a.country, a.postal_code,
		o.total, o.status, o.created_at as order_date,
		oi.quantity, oi.price,
		pr.name as product_name, pr.description, pr.sku,
		c.name as category_name, c.description as category_desc,
		b.name as brand_name, b.website as brand_website,
		s.name as supplier_name, s.contact_email,
		sh.method as shipping_method, sh.cost as shipping_cost,
		pm.method as payment_method, pm.provider,
		r.rating, r.review, r.created_at as review_date,
		t.name as tag_name, t.color,
		cp.code as coupon_code, cp.discount_amount,
		w.name as warehouse_name, w.location,
		inv.quantity_available, inv.reserved_quantity,
		ret.reason as return_reason, ret.status as return_status
	FROM users u
	LEFT JOIN profiles p ON u.id = p.user_id
	LEFT JOIN addresses a ON u.id = a.user_id AND a.is_primary = true
	LEFT JOIN orders o ON u.id = o.user_id
	LEFT JOIN order_items oi ON o.id = oi.order_id
	LEFT JOIN products pr ON oi.product_id = pr.id
	LEFT JOIN categories c ON pr.category_id = c.id
	LEFT JOIN brands b ON pr.brand_id = b.id
	LEFT JOIN suppliers s ON pr.supplier_id = s.id
	LEFT JOIN shipping_methods sh ON o.shipping_method_id = sh.id
	LEFT JOIN payment_methods pm ON o.payment_method_id = pm.id
	LEFT JOIN reviews r ON pr.id = r.product_id AND r.user_id = u.id
	LEFT JOIN product_tags pt ON pr.id = pt.product_id
	LEFT JOIN tags t ON pt.tag_id = t.id
	LEFT JOIN coupons cp ON o.coupon_id = cp.id
	LEFT JOIN warehouses w ON pr.warehouse_id = w.id
	LEFT JOIN inventory inv ON pr.id = inv.product_id AND inv.warehouse_id = w.id
	LEFT JOIN returns ret ON o.id = ret.order_id
	WHERE u.active = true
		AND o.created_at >= '2024-01-01'
		AND o.status IN ('completed', 'shipped', 'delivered')
	ORDER BY o.created_at DESC, u.name ASC
	LIMIT 500;
	`)
}

// generateLargeInClauseSQL creates SQL with large IN clauses
func generateLargeInClauseSQL() []byte {
	// Generate 1000 IDs for the IN clause
	var ids []string
	for i := 1; i <= 1000; i++ {
		ids = append(ids, fmt.Sprintf("%d", i))
	}

	query := fmt.Sprintf(`
	SELECT 
		u.id, u.name, u.email, u.created_at,
		COUNT(o.id) as order_count,
		SUM(o.total) as total_spent,
		AVG(o.total) as avg_order_value
	FROM users u
	LEFT JOIN orders o ON u.id = o.user_id
	WHERE u.id IN (%s)
		AND u.active = true
		AND u.email NOT IN (
			'spam@example.com', 'test@test.com', 'fake@fake.com',
			'bot@bot.com', 'invalid@invalid.com', 'temp@temp.com',
			'demo@demo.com', 'sample@sample.com', 'noreply@noreply.com'
		)
		AND o.status IN (
			'pending', 'processing', 'shipped', 'delivered', 'completed',
			'cancelled', 'refunded', 'returned', 'exchanged', 'backordered'
		)
	GROUP BY u.id, u.name, u.email, u.created_at
	HAVING COUNT(o.id) > 0
	ORDER BY total_spent DESC, order_count DESC
	LIMIT 100;
	`, strings.Join(ids, ", "))

	return []byte(query)
}

// generateComplexAnalyticsSQL creates complex analytical SQL
func generateComplexAnalyticsSQL() []byte {
	return []byte(`
	WITH monthly_sales AS (
		SELECT 
			DATE_TRUNC('month', o.created_at) as month,
			u.id as user_id,
			COUNT(o.id) as monthly_orders,
			SUM(o.total) as monthly_revenue,
			AVG(o.total) as avg_order_value
		FROM orders o
		JOIN users u ON o.user_id = u.id
		WHERE o.status = 'completed'
			AND o.created_at >= DATE_SUB(NOW(), INTERVAL 24 MONTH)
		GROUP BY DATE_TRUNC('month', o.created_at), u.id
	),
	user_segments AS (
		SELECT 
			user_id,
			SUM(monthly_revenue) as total_revenue,
			AVG(monthly_orders) as avg_monthly_orders,
			COUNT(DISTINCT month) as active_months,
			CASE 
				WHEN SUM(monthly_revenue) > 10000 THEN 'High Value'
				WHEN SUM(monthly_revenue) > 5000 THEN 'Medium Value'
				WHEN SUM(monthly_revenue) > 1000 THEN 'Low Value'
				ELSE 'Minimal Value'
			END as value_segment,
			CASE 
				WHEN COUNT(DISTINCT month) >= 12 THEN 'Highly Active'
				WHEN COUNT(DISTINCT month) >= 6 THEN 'Moderately Active'
				WHEN COUNT(DISTINCT month) >= 3 THEN 'Occasionally Active'
				ELSE 'Rarely Active'
			END as activity_segment
		FROM monthly_sales
		GROUP BY user_id
	),
	product_performance AS (
		SELECT 
			p.id as product_id,
			p.name as product_name,
			c.name as category_name,
			COUNT(oi.id) as times_ordered,
			SUM(oi.quantity) as total_quantity_sold,
			SUM(oi.quantity * oi.price) as total_revenue,
			AVG(oi.price) as avg_selling_price,
			RANK() OVER (PARTITION BY c.id ORDER BY SUM(oi.quantity * oi.price) DESC) as category_rank
		FROM products p
		JOIN categories c ON p.category_id = c.id
		JOIN order_items oi ON p.id = oi.product_id
		JOIN orders o ON oi.order_id = o.id
		WHERE o.status = 'completed'
			AND o.created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
		GROUP BY p.id, p.name, c.id, c.name
	)
	SELECT 
		u.id,
		u.name,
		u.email,
		us.value_segment,
		us.activity_segment,
		us.total_revenue,
		us.avg_monthly_orders,
		us.active_months,
		COUNT(DISTINCT pp.product_id) as unique_products_purchased,
		STRING_AGG(DISTINCT pp.category_name, ', ') as purchased_categories,
		MAX(pp.total_revenue) as top_category_spend,
		LAG(us.total_revenue) OVER (ORDER BY us.total_revenue DESC) as prev_user_revenue,
		LEAD(us.total_revenue) OVER (ORDER BY us.total_revenue DESC) as next_user_revenue,
		NTILE(10) OVER (ORDER BY us.total_revenue DESC) as revenue_decile,
		ROW_NUMBER() OVER (PARTITION BY us.value_segment ORDER BY us.total_revenue DESC) as segment_rank
	FROM users u
	JOIN user_segments us ON u.id = us.user_id
	LEFT JOIN orders o ON u.id = o.user_id AND o.status = 'completed'
	LEFT JOIN order_items oi ON o.id = oi.order_id
	LEFT JOIN product_performance pp ON oi.product_id = pp.product_id
	WHERE u.active = true
	GROUP BY u.id, u.name, u.email, us.value_segment, us.activity_segment, 
			 us.total_revenue, us.avg_monthly_orders, us.active_months
	ORDER BY us.total_revenue DESC, us.active_months DESC
	LIMIT 1000;
	`)
}

// Comprehensive Performance Benchmarks

func BenchmarkTokenizerVariedSizes(b *testing.B) {
	b.Run("SmallSQL_1KB", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(smallSQL1KB)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})

	b.Run("MediumSQL_10KB", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(mediumSQL10KB)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})

	b.Run("LargeSQL_100KB", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(largeSQL100KB)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})

	b.Run("VeryLargeSQL_1MB", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(veryLargeSQL1MB)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})
}

func BenchmarkTokenizerComplexPatterns(b *testing.B) {
	b.Run("DeeplyNested", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(deeplyNestedSQL)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})

	b.Run("WideJoins", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(wideJoinSQL)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})

	b.Run("LargeInClause", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(largeInClauseSQL)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})

	b.Run("ComplexAnalytics", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(complexAnalyticsSQL)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})
}

// Memory allocation tracking benchmarks
func BenchmarkTokenizerMemoryEfficiency(b *testing.B) {
	testCases := []struct {
		name string
		sql  []byte
	}{
		{"Small_1KB", smallSQL1KB},
		{"Medium_10KB", mediumSQL10KB},
		{"Large_100KB", largeSQL100KB},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(tc.sql)
				if err != nil {
					b.Fatal(err)
				}
				PutTokenizer(tokenizer)
			}
		})
	}
}

// Throughput measurement (tokens per second)
func BenchmarkTokenizerThroughput(b *testing.B) {
	tokenizer := GetTokenizer()
	defer PutTokenizer(tokenizer)

	b.Run("TokensPerSecond", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		start := time.Now()
		totalTokens := 0
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(smallSQL1KB)
			if err != nil {
				b.Fatal(err)
			}
			totalTokens += len(tokens)
		}

		// Calculate and report tokens per second
		duration := time.Since(start)
		tokensPerSecond := float64(totalTokens) / duration.Seconds()
		b.ReportMetric(tokensPerSecond, "tokens/sec")
	})
}
