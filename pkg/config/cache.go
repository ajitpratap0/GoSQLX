package config

import (
	"os"
	"sync"
	"time"
)

// configCacheEntry holds a cached configuration and its metadata
type configCacheEntry struct {
	config   *Config
	modTime  time.Time
	loadedAt time.Time
}

// configCache provides thread-safe caching of loaded configurations
type configCache struct {
	mu      sync.RWMutex
	entries map[string]*configCacheEntry
	maxSize int
	ttl     time.Duration // Time-to-live for cache entries
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
		return nil, false
	}

	// Check TTL
	if time.Since(entry.loadedAt) > c.ttl {
		return nil, false
	}

	// Check if file has been modified
	stat, err := os.Stat(path)
	if err != nil {
		return nil, false
	}

	if stat.ModTime() != entry.modTime {
		return nil, false
	}

	// Return a clone to prevent mutation of cached config
	return entry.config.Clone(), true
}

// set stores a config in the cache
func (c *configCache) set(path string, cfg *Config) {
	stat, err := os.Stat(path)
	if err != nil {
		return // Don't cache if we can't get file info
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: clear cache when max size is reached
	if len(c.entries) >= c.maxSize {
		c.entries = make(map[string]*configCacheEntry)
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
	Size    int
	MaxSize int
	TTL     time.Duration
}

// GetConfigCacheStats returns current cache statistics
func GetConfigCacheStats() ConfigCacheStats {
	return ConfigCacheStats{
		Size:    fileConfigCache.size(),
		MaxSize: fileConfigCache.maxSize,
		TTL:     fileConfigCache.ttl,
	}
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
