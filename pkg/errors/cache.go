package errors

import (
	"sync"
	"sync/atomic"
)

// keywordSuggestionCache caches keyword suggestions to avoid
// repeated Levenshtein distance calculations for the same input.
// This is particularly useful in LSP scenarios where the same
// typo may be evaluated multiple times.
type keywordSuggestionCache struct {
	mu    sync.RWMutex
	cache map[string]string
	// maxSize limits cache growth; partial eviction when exceeded
	maxSize int
	// metrics for observability
	hits      uint64
	misses    uint64
	evictions uint64
}

var (
	// suggestionCache is the global keyword suggestion cache
	suggestionCache = newKeywordSuggestionCache(1000)
)

// newKeywordSuggestionCache creates a new cache with the given max size
func newKeywordSuggestionCache(maxSize int) *keywordSuggestionCache {
	return &keywordSuggestionCache{
		cache:   make(map[string]string),
		maxSize: maxSize,
	}
}

// get retrieves a cached suggestion if available
func (c *keywordSuggestionCache) get(input string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, ok := c.cache[input]
	if ok {
		atomic.AddUint64(&c.hits, 1)
	} else {
		atomic.AddUint64(&c.misses, 1)
	}
	return result, ok
}

// set stores a suggestion in the cache
func (c *keywordSuggestionCache) set(input, suggestion string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Partial eviction: keep half the entries when max size is reached
	// This prevents cache thrashing while maintaining performance
	if len(c.cache) >= c.maxSize {
		newCache := make(map[string]string, c.maxSize/2)
		count := 0
		for k, v := range c.cache {
			if count >= c.maxSize/2 {
				break
			}
			newCache[k] = v
			count++
		}
		evicted := len(c.cache) - count
		atomic.AddUint64(&c.evictions, uint64(evicted))
		c.cache = newCache
	}

	c.cache[input] = suggestion
}

// clear removes all entries from the cache
func (c *keywordSuggestionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]string)
}

// size returns the number of cached entries
func (c *keywordSuggestionCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// ClearSuggestionCache clears the keyword suggestion cache.
// Useful for testing or when keyword list changes.
func ClearSuggestionCache() {
	suggestionCache.clear()
}

// SuggestionCacheSize returns the current size of the suggestion cache.
// Useful for monitoring and debugging.
func SuggestionCacheSize() int {
	return suggestionCache.size()
}

// SuggestionCacheStats returns cache statistics
type SuggestionCacheStats struct {
	Size      int
	MaxSize   int
	Hits      uint64
	Misses    uint64
	Evictions uint64
	HitRate   float64
}

// GetSuggestionCacheStats returns current cache statistics
func GetSuggestionCacheStats() SuggestionCacheStats {
	hits := atomic.LoadUint64(&suggestionCache.hits)
	misses := atomic.LoadUint64(&suggestionCache.misses)
	evictions := atomic.LoadUint64(&suggestionCache.evictions)

	var hitRate float64
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return SuggestionCacheStats{
		Size:      suggestionCache.size(),
		MaxSize:   suggestionCache.maxSize,
		Hits:      hits,
		Misses:    misses,
		Evictions: evictions,
		HitRate:   hitRate,
	}
}

// ResetSuggestionCacheStats resets the cache statistics counters.
// Useful for testing and monitoring.
func ResetSuggestionCacheStats() {
	atomic.StoreUint64(&suggestionCache.hits, 0)
	atomic.StoreUint64(&suggestionCache.misses, 0)
	atomic.StoreUint64(&suggestionCache.evictions, 0)
}
