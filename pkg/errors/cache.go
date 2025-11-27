package errors

import (
	"sync"
)

// keywordSuggestionCache caches keyword suggestions to avoid
// repeated Levenshtein distance calculations for the same input.
// This is particularly useful in LSP scenarios where the same
// typo may be evaluated multiple times.
type keywordSuggestionCache struct {
	mu    sync.RWMutex
	cache map[string]string
	// maxSize limits cache growth; oldest entries are evicted when exceeded
	maxSize int
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
	return result, ok
}

// set stores a suggestion in the cache
func (c *keywordSuggestionCache) set(input, suggestion string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: clear cache when max size is reached
	// In production, you might want LRU eviction
	if len(c.cache) >= c.maxSize {
		c.cache = make(map[string]string)
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
	Size    int
	MaxSize int
}

// GetSuggestionCacheStats returns current cache statistics
func GetSuggestionCacheStats() SuggestionCacheStats {
	return SuggestionCacheStats{
		Size:    suggestionCache.size(),
		MaxSize: suggestionCache.maxSize,
	}
}
