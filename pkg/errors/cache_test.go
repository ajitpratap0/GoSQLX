package errors

import (
	"sync"
	"testing"
)

func TestKeywordSuggestionCache(t *testing.T) {
	// Clear cache and stats before testing
	ClearSuggestionCache()
	ResetSuggestionCacheStats()

	t.Run("cache miss then hit", func(t *testing.T) {
		ClearSuggestionCache()
		ResetSuggestionCacheStats()

		// First call should compute the result (cache miss)
		result1 := SuggestKeyword("SELCT")
		if result1 != "SELECT" {
			t.Errorf("SuggestKeyword(SELCT) = %q, want SELECT", result1)
		}

		// Check cache size increased
		if SuggestionCacheSize() != 1 {
			t.Errorf("cache size = %d, want 1", SuggestionCacheSize())
		}

		// Second call should return cached result (cache hit)
		result2 := SuggestKeyword("SELCT")
		if result2 != "SELECT" {
			t.Errorf("SuggestKeyword(SELCT) cached = %q, want SELECT", result2)
		}

		// Verify hit/miss stats
		stats := GetSuggestionCacheStats()
		if stats.Hits != 1 {
			t.Errorf("stats.Hits = %d, want 1", stats.Hits)
		}
		if stats.Misses != 1 {
			t.Errorf("stats.Misses = %d, want 1", stats.Misses)
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
		ResetSuggestionCacheStats()

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

	t.Run("hit rate calculation", func(t *testing.T) {
		ClearSuggestionCache()
		ResetSuggestionCacheStats()

		// First call - miss
		SuggestKeyword("SELCT")
		// Second call - hit
		SuggestKeyword("SELCT")
		// Third call - hit
		SuggestKeyword("SELCT")

		stats := GetSuggestionCacheStats()
		// 2 hits, 1 miss = 66.67% hit rate
		expectedHitRate := 2.0 / 3.0
		if stats.HitRate < expectedHitRate-0.01 || stats.HitRate > expectedHitRate+0.01 {
			t.Errorf("stats.HitRate = %f, want ~%f", stats.HitRate, expectedHitRate)
		}
	})
}

func TestKeywordSuggestionCacheEviction(t *testing.T) {
	// Create a small cache for testing eviction
	oldCache := suggestionCache
	suggestionCache = newKeywordSuggestionCache(10)
	defer func() { suggestionCache = oldCache }()

	ClearSuggestionCache()
	ResetSuggestionCacheStats()

	// Fill the cache to max
	for i := 0; i < 10; i++ {
		// Generate unique inputs that won't match any keyword
		input := string(rune('A'+i)) + "XYZQ" + string(rune('0'+i))
		SuggestKeyword(input)
	}

	if SuggestionCacheSize() != 10 {
		t.Errorf("cache size after fill = %d, want 10", SuggestionCacheSize())
	}

	// Add one more to trigger eviction
	SuggestKeyword("NEWENTRY")

	// Should have evicted half (5 entries) and added 1, so size should be 6
	size := SuggestionCacheSize()
	if size != 6 {
		t.Errorf("cache size after eviction = %d, want 6", size)
	}

	// Check eviction counter
	stats := GetSuggestionCacheStats()
	if stats.Evictions != 5 {
		t.Errorf("stats.Evictions = %d, want 5", stats.Evictions)
	}
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
	ResetSuggestionCacheStats()

	// First call to populate cache
	SuggestKeyword("SELCT")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This should be a cache hit
		_ = SuggestKeyword("SELCT")
	}
}

func BenchmarkSuggestKeywordCacheMiss(b *testing.B) {
	ClearSuggestionCache()
	ResetSuggestionCacheStats()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force cache miss by using unique input
		ClearSuggestionCache()
		_ = SuggestKeyword("SELCT")
	}
}
