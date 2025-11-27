package errors

import (
	"sync"
	"testing"
)

func TestKeywordSuggestionCache(t *testing.T) {
	// Clear cache before testing
	ClearSuggestionCache()

	t.Run("cache miss then hit", func(t *testing.T) {
		// First call should compute the result
		result1 := SuggestKeyword("SELCT")
		if result1 != "SELECT" {
			t.Errorf("SuggestKeyword(SELCT) = %q, want SELECT", result1)
		}

		// Check cache size increased
		if SuggestionCacheSize() != 1 {
			t.Errorf("cache size = %d, want 1", SuggestionCacheSize())
		}

		// Second call should return cached result
		result2 := SuggestKeyword("SELCT")
		if result2 != "SELECT" {
			t.Errorf("SuggestKeyword(SELCT) cached = %q, want SELECT", result2)
		}
	})

	t.Run("cache stores empty results", func(t *testing.T) {
		ClearSuggestionCache()

		// This should return empty (too different from any keyword)
		result1 := SuggestKeyword("XYZABC123")
		if result1 != "" {
			t.Errorf("SuggestKeyword(XYZABC123) = %q, want empty", result1)
		}

		// Verify it was cached
		if SuggestionCacheSize() != 1 {
			t.Errorf("cache size = %d, want 1", SuggestionCacheSize())
		}

		// Second call should return cached empty result
		result2 := SuggestKeyword("XYZABC123")
		if result2 != "" {
			t.Errorf("SuggestKeyword(XYZABC123) cached = %q, want empty", result2)
		}
	})

	t.Run("case insensitive caching", func(t *testing.T) {
		ClearSuggestionCache()

		// Lowercase input should be normalized to uppercase
		result := SuggestKeyword("frm")
		if result != "FROM" {
			t.Errorf("SuggestKeyword(frm) = %q, want FROM", result)
		}

		// The cache key should be uppercase "FRM"
		if SuggestionCacheSize() != 1 {
			t.Errorf("cache size = %d, want 1", SuggestionCacheSize())
		}
	})

	t.Run("clear cache", func(t *testing.T) {
		// Add some entries
		SuggestKeyword("SELCT")
		SuggestKeyword("WHRE")

		// Clear
		ClearSuggestionCache()

		if SuggestionCacheSize() != 0 {
			t.Errorf("cache size after clear = %d, want 0", SuggestionCacheSize())
		}
	})

	t.Run("cache stats", func(t *testing.T) {
		ClearSuggestionCache()

		SuggestKeyword("SELCT")
		SuggestKeyword("WHRE")

		stats := GetSuggestionCacheStats()
		if stats.Size != 2 {
			t.Errorf("stats.Size = %d, want 2", stats.Size)
		}
		if stats.MaxSize != 1000 {
			t.Errorf("stats.MaxSize = %d, want 1000", stats.MaxSize)
		}
	})
}

func TestKeywordSuggestionCacheConcurrency(t *testing.T) {
	ClearSuggestionCache()

	var wg sync.WaitGroup
	inputs := []string{"SELCT", "WHRE", "FRMO", "JION", "ORDR"}

	// Run multiple goroutines concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			input := inputs[idx%len(inputs)]
			_ = SuggestKeyword(input)
		}(i)
	}

	wg.Wait()

	// Cache should have at most len(inputs) entries
	size := SuggestionCacheSize()
	if size > len(inputs) {
		t.Errorf("cache size = %d, want <= %d", size, len(inputs))
	}
}

func BenchmarkSuggestKeywordWithCache(b *testing.B) {
	ClearSuggestionCache()

	// First call to populate cache
	SuggestKeyword("SELCT")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This should be a cache hit
		_ = SuggestKeyword("SELCT")
	}
}

func BenchmarkSuggestKeywordCacheMiss(b *testing.B) {
	ClearSuggestionCache()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force cache miss by using unique input
		ClearSuggestionCache()
		_ = SuggestKeyword("SELCT")
	}
}
