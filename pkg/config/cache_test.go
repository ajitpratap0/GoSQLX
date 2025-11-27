package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConfigCache(t *testing.T) {
	// Create a temp directory for test files
	tmpDir := t.TempDir()

	t.Run("cache miss then hit", func(t *testing.T) {
		ClearConfigCache()

		// Create a test config file
		configPath := filepath.Join(tmpDir, "test1.yaml")
		configContent := `
format:
  indent: 4
validation:
  dialect: mysql
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		// First load should be a cache miss
		cfg1, err := LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached failed: %v", err)
		}

		if cfg1.Format.Indent != 4 {
			t.Errorf("config.Format.Indent = %d, want 4", cfg1.Format.Indent)
		}

		if ConfigCacheSize() != 1 {
			t.Errorf("cache size = %d, want 1", ConfigCacheSize())
		}

		// Second load should be a cache hit
		cfg2, err := LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached (cached) failed: %v", err)
		}

		if cfg2.Format.Indent != 4 {
			t.Errorf("cached config.Format.Indent = %d, want 4", cfg2.Format.Indent)
		}
	})

	t.Run("cache invalidation on file modification", func(t *testing.T) {
		ClearConfigCache()

		// Create a test config file
		configPath := filepath.Join(tmpDir, "test2.yaml")
		configContent := `
format:
  indent: 2
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		// Load the config
		cfg1, err := LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached failed: %v", err)
		}

		if cfg1.Format.Indent != 2 {
			t.Errorf("config.Format.Indent = %d, want 2", cfg1.Format.Indent)
		}

		// Wait a moment to ensure file mtime changes
		time.Sleep(10 * time.Millisecond)

		// Modify the file
		newContent := `
format:
  indent: 8
`
		if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
			t.Fatalf("failed to update test config: %v", err)
		}

		// Load again - should detect modification and reload
		cfg2, err := LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached (after mod) failed: %v", err)
		}

		if cfg2.Format.Indent != 8 {
			t.Errorf("reloaded config.Format.Indent = %d, want 8", cfg2.Format.Indent)
		}
	})

	t.Run("clear cache", func(t *testing.T) {
		// Create a test config file
		configPath := filepath.Join(tmpDir, "test3.yaml")
		if err := os.WriteFile(configPath, []byte("format:\n  indent: 2\n"), 0644); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		// Load to populate cache
		_, err := LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached failed: %v", err)
		}

		if ConfigCacheSize() == 0 {
			t.Error("cache should not be empty after loading")
		}

		// Clear
		ClearConfigCache()

		if ConfigCacheSize() != 0 {
			t.Errorf("cache size after clear = %d, want 0", ConfigCacheSize())
		}
	})

	t.Run("invalidate specific entry", func(t *testing.T) {
		ClearConfigCache()

		// Create two test config files
		config1Path := filepath.Join(tmpDir, "test4a.yaml")
		config2Path := filepath.Join(tmpDir, "test4b.yaml")

		if err := os.WriteFile(config1Path, []byte("format:\n  indent: 2\n"), 0644); err != nil {
			t.Fatalf("failed to write test config 1: %v", err)
		}
		if err := os.WriteFile(config2Path, []byte("format:\n  indent: 4\n"), 0644); err != nil {
			t.Fatalf("failed to write test config 2: %v", err)
		}

		// Load both
		_, _ = LoadFromFileCached(config1Path)
		_, _ = LoadFromFileCached(config2Path)

		if ConfigCacheSize() != 2 {
			t.Errorf("cache size = %d, want 2", ConfigCacheSize())
		}

		// Invalidate one
		InvalidateConfigCache(config1Path)

		if ConfigCacheSize() != 1 {
			t.Errorf("cache size after invalidate = %d, want 1", ConfigCacheSize())
		}
	})

	t.Run("cache stats", func(t *testing.T) {
		ClearConfigCache()
		ResetConfigCacheStats()

		stats := GetConfigCacheStats()
		if stats.Size != 0 {
			t.Errorf("stats.Size = %d, want 0", stats.Size)
		}
		if stats.MaxSize != 100 {
			t.Errorf("stats.MaxSize = %d, want 100", stats.MaxSize)
		}
		if stats.TTL != 5*time.Minute {
			t.Errorf("stats.TTL = %v, want 5m", stats.TTL)
		}
	})

	t.Run("hit/miss metrics", func(t *testing.T) {
		ClearConfigCache()
		ResetConfigCacheStats()

		// Create a test config file
		configPath := filepath.Join(tmpDir, "metrics_test.yaml")
		if err := os.WriteFile(configPath, []byte("format:\n  indent: 2\n"), 0644); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		// First load - miss
		_, err := LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached failed: %v", err)
		}

		// Second load - hit
		_, err = LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached failed: %v", err)
		}

		stats := GetConfigCacheStats()
		if stats.Misses != 1 {
			t.Errorf("stats.Misses = %d, want 1", stats.Misses)
		}
		if stats.Hits != 1 {
			t.Errorf("stats.Hits = %d, want 1", stats.Hits)
		}
		if stats.HitRate != 0.5 {
			t.Errorf("stats.HitRate = %f, want 0.5", stats.HitRate)
		}
	})

	t.Run("returns clone", func(t *testing.T) {
		ClearConfigCache()

		configPath := filepath.Join(tmpDir, "test5.yaml")
		if err := os.WriteFile(configPath, []byte("format:\n  indent: 2\n"), 0644); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}

		cfg1, _ := LoadFromFileCached(configPath)
		cfg2, _ := LoadFromFileCached(configPath)

		// Modify one - should not affect the other
		cfg1.Format.Indent = 999

		if cfg2.Format.Indent == 999 {
			t.Error("cache returned same instance, expected clone")
		}
	})
}

func TestConfigCacheTTLExpiration(t *testing.T) {
	// Create a cache with a very short TTL for testing
	oldCache := fileConfigCache
	fileConfigCache = newConfigCache(100, 50*time.Millisecond)
	defer func() { fileConfigCache = oldCache }()

	ClearConfigCache()
	ResetConfigCacheStats()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "ttl_test.yaml")
	if err := os.WriteFile(configPath, []byte("format:\n  indent: 2\n"), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	// First load - miss
	_, err := LoadFromFileCached(configPath)
	if err != nil {
		t.Fatalf("LoadFromFileCached failed: %v", err)
	}

	// Immediate second load - should be hit
	_, err = LoadFromFileCached(configPath)
	if err != nil {
		t.Fatalf("LoadFromFileCached failed: %v", err)
	}

	stats := GetConfigCacheStats()
	if stats.Hits != 1 {
		t.Errorf("stats.Hits = %d, want 1 (before TTL)", stats.Hits)
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Third load - should be miss (TTL expired)
	_, err = LoadFromFileCached(configPath)
	if err != nil {
		t.Fatalf("LoadFromFileCached failed: %v", err)
	}

	stats = GetConfigCacheStats()
	if stats.Misses != 2 {
		t.Errorf("stats.Misses = %d, want 2 (after TTL expiration)", stats.Misses)
	}
}

func TestConfigCacheEviction(t *testing.T) {
	// Create a small cache for testing eviction
	oldCache := fileConfigCache
	fileConfigCache = newConfigCache(5, 5*time.Minute)
	defer func() { fileConfigCache = oldCache }()

	ClearConfigCache()
	ResetConfigCacheStats()

	tmpDir := t.TempDir()

	// Fill the cache to max
	for i := 0; i < 5; i++ {
		configPath := filepath.Join(tmpDir, "eviction_test_"+string(rune('a'+i))+".yaml")
		if err := os.WriteFile(configPath, []byte("format:\n  indent: "+string(rune('0'+i))+"\n"), 0644); err != nil {
			t.Fatalf("failed to write test config: %v", err)
		}
		_, err := LoadFromFileCached(configPath)
		if err != nil {
			t.Fatalf("LoadFromFileCached failed: %v", err)
		}
	}

	if ConfigCacheSize() != 5 {
		t.Errorf("cache size after fill = %d, want 5", ConfigCacheSize())
	}

	// Add one more to trigger eviction
	newConfigPath := filepath.Join(tmpDir, "eviction_new.yaml")
	if err := os.WriteFile(newConfigPath, []byte("format:\n  indent: 9\n"), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	_, err := LoadFromFileCached(newConfigPath)
	if err != nil {
		t.Fatalf("LoadFromFileCached failed: %v", err)
	}

	// maxSize/2 = 5/2 = 2 (integer division), so we keep 2 entries and add 1 for total of 3
	size := ConfigCacheSize()
	if size != 3 {
		t.Errorf("cache size after eviction = %d, want 3", size)
	}

	// Check eviction counter - we evicted 5 - 2 = 3 entries
	stats := GetConfigCacheStats()
	if stats.Evictions < 3 {
		t.Errorf("stats.Evictions = %d, want >= 3", stats.Evictions)
	}
}

func TestConfigCacheFileNotFound(t *testing.T) {
	ClearConfigCache()
	ResetConfigCacheStats()

	// Try to load a non-existent file
	_, err := LoadFromFileCached("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("LoadFromFileCached should fail for non-existent file")
	}

	// Cache should not have any entries
	if ConfigCacheSize() != 0 {
		t.Errorf("cache size = %d, want 0", ConfigCacheSize())
	}
}

func TestConfigCacheConcurrency(t *testing.T) {
	ClearConfigCache()
	ResetConfigCacheStats()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "concurrent.yaml")
	if err := os.WriteFile(configPath, []byte("format:\n  indent: 2\n"), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	var wg sync.WaitGroup

	// Run multiple goroutines concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := LoadFromFileCached(configPath)
			if err != nil {
				t.Errorf("concurrent LoadFromFileCached failed: %v", err)
			}
		}()
	}

	wg.Wait()

	// Should have exactly 1 entry
	if ConfigCacheSize() != 1 {
		t.Errorf("cache size = %d, want 1", ConfigCacheSize())
	}
}

func BenchmarkLoadFromFileCached(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "bench.yaml")
	if err := os.WriteFile(configPath, []byte("format:\n  indent: 2\n"), 0644); err != nil {
		b.Fatalf("failed to write test config: %v", err)
	}

	ClearConfigCache()
	ResetConfigCacheStats()
	// First call to populate cache
	_, _ = LoadFromFileCached(configPath)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadFromFileCached(configPath)
	}
}

func BenchmarkLoadFromFileUncached(b *testing.B) {
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "bench.yaml")
	if err := os.WriteFile(configPath, []byte("format:\n  indent: 2\n"), 0644); err != nil {
		b.Fatalf("failed to write test config: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadFromFile(configPath)
	}
}
