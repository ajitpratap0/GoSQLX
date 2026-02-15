package token

import (
	"runtime"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestTokenPool tests basic token pool operations
func TestTokenPool(t *testing.T) {
	t.Run("Get and Put", func(t *testing.T) {
		tok := Get()
		if tok == nil {
			t.Fatal("Get() returned nil")
		}

		tok.Type = models.TokenTypeIdentifier
		tok.Literal = "test"

		err := Put(tok)
		if err != nil {
			t.Errorf("Put() returned error: %v", err)
		}

		if tok.Type != models.TokenTypeUnknown {
			t.Errorf("Type not cleared, got %v", tok.Type)
		}
		if tok.Literal != "" {
			t.Errorf("Literal not cleared, got %v", tok.Literal)
		}
	})

	t.Run("Put nil token", func(t *testing.T) {
		err := Put(nil)
		if err != nil {
			t.Errorf("Put(nil) returned error: %v", err)
		}
	})

	t.Run("Token reuse", func(t *testing.T) {
		tok1 := Get()
		tok1.Type = models.TokenTypeSelect
		tok1.Literal = "SELECT"

		Put(tok1)

		tok2 := Get()
		if tok2 == nil {
			t.Fatal("Get() returned nil on reuse")
		}

		if tok2.Type != models.TokenTypeUnknown {
			t.Errorf("Reused token not clean, Type = %v", tok2.Type)
		}
		if tok2.Literal != "" {
			t.Errorf("Reused token not clean, Literal = %v", tok2.Literal)
		}

		Put(tok2)
	})
}

// TestMemoryLeaks_TokenPool tests for memory leaks in token pool
func TestMemoryLeaks_TokenPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	for i := 0; i < iterations; i++ {
		tok := Get()
		tok.Type = models.TokenTypeIdentifier
		tok.Literal = "test_column_name"
		Put(tok)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	const maxAllocIncrease = 512 * 1024
	const maxBytesPerOp = 2000

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak detected: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}
	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}
}

// TestMemoryLeaks_TokenPool_VariableTypes tests with different token types
func TestMemoryLeaks_TokenPool_VariableTypes(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	tokenTypes := []struct {
		typ     models.TokenType
		literal string
	}{
		{models.TokenTypeIdentifier, "column_name"},
		{models.TokenTypeSelect, "SELECT"},
		{models.TokenTypeFrom, "FROM"},
		{models.TokenTypeWhere, "WHERE"},
		{models.TokenTypeString, "'test string'"},
		{models.TokenTypeNumber, "12345"},
		{models.TokenTypeEq, "="},
		{models.TokenTypeComma, ","},
	}

	for i := 0; i < iterations; i++ {
		tokType := tokenTypes[i%len(tokenTypes)]
		tok := Get()
		tok.Type = tokType.typ
		tok.Literal = tokType.literal
		Put(tok)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	const maxAllocIncrease = 512 * 1024
	const maxBytesPerOp = 2500

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak detected: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}
	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}
}

// TestTokenReset tests that Reset() properly clears token fields
func TestTokenReset(t *testing.T) {
	tok := &Token{
		Type:    models.TokenTypeIdentifier,
		Literal: "test",
	}

	tok.Reset()

	if tok.Type != models.TokenTypeUnknown {
		t.Errorf("Type not cleared by Reset(), got %v", tok.Type)
	}
	if tok.Literal != "" {
		t.Errorf("Literal not cleared by Reset(), got %v", tok.Literal)
	}
}

// BenchmarkTokenPool benchmarks token pool operations
func BenchmarkTokenPool(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tok := Get()
		tok.Type = models.TokenTypeIdentifier
		tok.Literal = "column_name"
		Put(tok)
	}
}

// BenchmarkTokenPoolParallel benchmarks concurrent token pool operations
func BenchmarkTokenPoolParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tok := Get()
			tok.Type = models.TokenTypeIdentifier
			tok.Literal = "column_name"
			Put(tok)
		}
	})
}
