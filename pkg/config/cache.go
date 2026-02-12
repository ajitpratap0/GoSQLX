package config

import (
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// configCacheEntry holds a cached configuration and its metadata
type configCacheEntry struct {
	config   *Config
	modTime  time.Time
	loadedAt time.Time
}

// configCache provides thread-safe caching of loaded configurations
// Note: There is a potential TOCTOU (Time-of-Check-Time-of-Use) race condition
// between checking file modification time and using the cached config. This is
// acceptable for a caching scenario as the worst case is returning slightly
// stale data which will be refreshed on the next access.
type configCache struct {
	mu      sync.RWMutex
	entries map[string]*configCacheEntry
	maxSize int
	ttl     time.Duration // Time-to-live for cache entries
	// metrics for observability
	hits      uint64
	misses    uint64
	evictions uint64
}

var (
	// fileConfigCache is the global config file cache
	fileConfigCache = newConfigCache(100, 5*time.Minute)
)

// newConfigCache creates a new config cache
func newConfigCache(maxSize int, ttl time.Duration) *configCache {
	return &configCache{
		entries: make(map[string]*configCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// get retrieves a cached config if it's still valid
func (c *configCache) get(path string) (*Config, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[path]
	if !ok {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	// Check TTL
	if time.Since(entry.loadedAt) > c.ttl {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	// Check if file has been modified
	stat, err := os.Stat(path)
	if err != nil {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	if stat.ModTime() != entry.modTime {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	atomic.AddUint64(&c.hits, 1)
	// Return a clone to prevent mutation of cached config
	return entry.config.Clone(), true
}

// set stores a config in the cache
func (c *configCache) set(path string, cfg *Config) {
	stat, err := os.Stat(path)
	if err != nil {
		// Don't cache if we can't get file info
		// Note: This is a silent failure, but acceptable since caching is optional
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Partial eviction: keep half the entries when max size is reached
	// This prevents cache thrashing while maintaining performance
	if len(c.entries) >= c.maxSize {
		newEntries := make(map[string]*configCacheEntry, c.maxSize/2)
		count := 0
		for k, v := range c.entries {
			if count >= c.maxSize/2 {
				break
			}
			newEntries[k] = v
			count++
		}
		evicted := len(c.entries) - count
		atomic.AddUint64(&c.evictions, uint64(evicted)) // #nosec G115
		c.entries = newEntries
	}

	c.entries[path] = &configCacheEntry{
		config:   cfg.Clone(), // Store a clone to prevent mutation
		modTime:  stat.ModTime(),
		loadedAt: time.Now(),
	}
}

// invalidate removes a specific entry from the cache
func (c *configCache) invalidate(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, path)
}

// clear removes all entries from the cache
func (c *configCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*configCacheEntry)
}

// size returns the number of cached entries
func (c *configCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ClearConfigCache clears the config file cache.
// Useful for testing or when configuration changes need to be reloaded.
func ClearConfigCache() {
	fileConfigCache.clear()
}

// InvalidateConfigCache invalidates a specific config file in the cache.
func InvalidateConfigCache(path string) {
	fileConfigCache.invalidate(path)
}

// ConfigCacheSize returns the current size of the config cache.
func ConfigCacheSize() int {
	return fileConfigCache.size()
}

// ConfigCacheStats holds cache statistics
type ConfigCacheStats struct {
	Size      int
	MaxSize   int
	TTL       time.Duration
	Hits      uint64
	Misses    uint64
	Evictions uint64
	HitRate   float64
}

// GetConfigCacheStats returns current cache statistics
func GetConfigCacheStats() ConfigCacheStats {
	hits := atomic.LoadUint64(&fileConfigCache.hits)
	misses := atomic.LoadUint64(&fileConfigCache.misses)
	evictions := atomic.LoadUint64(&fileConfigCache.evictions)

	var hitRate float64
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return ConfigCacheStats{
		Size:      fileConfigCache.size(),
		MaxSize:   fileConfigCache.maxSize,
		TTL:       fileConfigCache.ttl,
		Hits:      hits,
		Misses:    misses,
		Evictions: evictions,
		HitRate:   hitRate,
	}
}

// ResetConfigCacheStats resets the cache statistics counters.
// Useful for testing and monitoring.
func ResetConfigCacheStats() {
	atomic.StoreUint64(&fileConfigCache.hits, 0)
	atomic.StoreUint64(&fileConfigCache.misses, 0)
	atomic.StoreUint64(&fileConfigCache.evictions, 0)
}

// LoadFromFileCached loads configuration from a file with caching.
// If the file hasn't changed since the last load, returns the cached version.
func LoadFromFileCached(path string) (*Config, error) {
	// Try cache first
	if cached, ok := fileConfigCache.get(path); ok {
		return cached, nil
	}

	// Load from file
	config, err := LoadFromFile(path)
	if err != nil {
		return nil, err
	}

	// Cache the result
	fileConfigCache.set(path, config)

	return config, nil
}
