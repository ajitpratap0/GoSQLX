package tokenizer

import (
	"testing"
)

var (
	simpleSQL  = []byte(`SELECT id, name FROM users WHERE age > 25`)
	complexSQL = []byte(`
        SELECT 
            u.id, 
            u.name, 
            u.email,
            COUNT(o.id) as order_count,
            SUM(o.total) as total_spent,
            CASE 
                WHEN COUNT(o.id) > 10 THEN 'VIP'
                WHEN COUNT(o.id) > 5 THEN 'Regular'
                ELSE 'New'
            END as customer_type
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.created_at >= '2024-01-01'
        GROUP BY u.id, u.name, u.email
        HAVING COUNT(o.id) > 0
        ORDER BY total_spent DESC
        LIMIT 100
    `)
)

func BenchmarkTokenizer(b *testing.B) {
	b.Run("SimpleSQL", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(simpleSQL)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})

	b.Run("ComplexSQL", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tokens, err := tokenizer.Tokenize(complexSQL)
			if err != nil {
				b.Fatal(err)
			}
			if len(tokens) == 0 {
				b.Fatal("no tokens produced")
			}
		}
	})
}

func BenchmarkTokenizerPool(b *testing.B) {
	b.Run("GetPut", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tokenizer := GetTokenizer()
			PutTokenizer(tokenizer)
		}
	})

	b.Run("ConcurrentTokenization", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(simpleSQL)
				if err != nil {
					b.Fatal(err)
				}
				PutTokenizer(tokenizer)
			}
		})
	})
}

func BenchmarkBufferPool(b *testing.B) {
	b.Run("GetPut", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := getBuffer()
			putBuffer(buf)
		}
	})

	b.Run("WithWrite", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := getBuffer()
			buf.WriteString("test string with some content")
			putBuffer(buf)
		}
	})
}

// Benchmark memory allocations
func BenchmarkTokenizerAllocations(b *testing.B) {
	b.Run("SimpleSQL", func(b *testing.B) {
		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := tokenizer.Tokenize(simpleSQL)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
