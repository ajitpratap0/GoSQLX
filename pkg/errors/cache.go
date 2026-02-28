// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	// Partial eviction: keep half the entries when max size is reached.
	// This prevents cache thrashing while maintaining performance.
	//
	// Note on non-determinism: Go map iteration order is intentionally randomised
	// by the runtime, so the specific entries copied into newCache are
	// unpredictable — the eviction effectively removes a random ~50% of entries
	// rather than the least-recently-used ones.  For a keyword suggestion cache
	// this is perfectly acceptable: all retained entries are equally valid
	// suggestions, and the cost of a cache miss is only a Levenshtein distance
	// calculation.  Adding a true LRU eviction policy (e.g., via a doubly-linked
	// list or separate access-order map) would substantially increase complexity
	// and lock contention for negligible practical benefit.
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
		atomic.AddUint64(&c.evictions, uint64(evicted)) // #nosec G115
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

// ClearSuggestionCache removes all entries from the keyword suggestion cache.
// Call this in tests to ensure a clean state between test cases, or after
// modifying the keyword list so that stale suggestions are not served.
func ClearSuggestionCache() {
	suggestionCache.clear()
}

// SuggestionCacheSize returns the number of entries currently held in the keyword
// suggestion cache. Use this for monitoring cache growth and deciding whether to
// adjust the maximum size.
func SuggestionCacheSize() int {
	return suggestionCache.size()
}

// SuggestionCacheStats holds observability metrics for the keyword suggestion cache.
// Retrieve an instance via GetSuggestionCacheStats and reset counters via
// ResetSuggestionCacheStats.
//
// Fields:
//   - Size: Current number of entries in the cache
//   - MaxSize: Configured maximum capacity (default 1000)
//   - Hits: Number of cache lookups that returned a cached value
//   - Misses: Number of cache lookups that required computing a new suggestion
//   - Evictions: Total number of entries removed during partial eviction sweeps
//   - HitRate: Ratio of Hits to (Hits + Misses); 0.0 when no lookups have occurred
type SuggestionCacheStats struct {
	Size      int
	MaxSize   int
	Hits      uint64
	Misses    uint64
	Evictions uint64
	HitRate   float64
}

// GetSuggestionCacheStats returns a snapshot of the current keyword suggestion cache
// metrics. The returned struct is safe to read without any additional locking.
// Use this in observability dashboards or benchmarks to track cache efficiency.
//
// Example:
//
//	stats := errors.GetSuggestionCacheStats()
//	fmt.Printf("Cache hit rate: %.1f%%\n", stats.HitRate*100)
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

// ResetSuggestionCacheStats zeroes all hit, miss, and eviction counters in the
// keyword suggestion cache without clearing cached entries. Call this at the start
// of a benchmark or monitoring interval to obtain a clean measurement window.
func ResetSuggestionCacheStats() {
	atomic.StoreUint64(&suggestionCache.hits, 0)
	atomic.StoreUint64(&suggestionCache.misses, 0)
	atomic.StoreUint64(&suggestionCache.evictions, 0)
}
