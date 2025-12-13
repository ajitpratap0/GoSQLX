// Package config provides unified configuration management for GoSQLX across CLI, LSP server,
// and IDE integrations. It supports loading from multiple sources with a layered priority system,
// including configuration files (YAML/JSON), environment variables, and LSP initialization options.
//
// # Configuration Architecture
//
// The config package implements a flexible, multi-source configuration system with:
//
//   - File-based configuration (YAML, JSON) with multiple search paths
//   - Environment variable overrides with GOSQLX_ prefix
//   - LSP initialization options for IDE integration
//   - Intelligent merging with proper precedence handling
//   - Thread-safe caching with automatic invalidation
//   - Comprehensive validation with detailed error messages
//
// # Configuration Sources
//
// Configurations can be loaded from multiple sources in order of precedence (highest to lowest):
//
//  1. CLI flags (handled by cmd/gosqlx)
//  2. Environment variables (GOSQLX_*)
//  3. Configuration files (.gosqlx.yaml, gosqlx.json, etc.)
//  4. Default values
//
// # Supported Configuration Sections
//
// Format: SQL formatting and output styling
//
//   - indent: Number of spaces for indentation (default: 2)
//   - uppercase_keywords: Convert SQL keywords to uppercase (default: true)
//   - max_line_length: Maximum line length before wrapping (default: 120)
//   - compact: Use compact formatting (default: false)
//
// Validation: SQL validation and dialect settings
//
//   - dialect: Target SQL dialect - postgresql, mysql, sqlserver, oracle, sqlite (default: postgresql)
//   - strict_mode: Enable strict validation mode (default: false)
//   - recursive: Recursively validate files in directories (default: false)
//   - pattern: File pattern for recursive validation (default: "*.sql")
//   - security.max_file_size: Maximum file size in bytes (default: 10MB)
//
// Output: Output formatting options
//
//   - format: Output format - text, json, yaml (default: text)
//   - verbose: Enable verbose output (default: false)
//
// Analyze: SQL analysis settings
//
//   - security: Enable security analysis (default: false)
//   - performance: Enable performance analysis (default: false)
//   - complexity: Enable complexity analysis (default: false)
//   - all: Enable all analysis types (default: false)
//
// LSP: Language Server Protocol settings
//
//   - rate_limit_requests: Max requests per window (default: 100)
//   - rate_limit_window: Rate limit time window (default: 1s)
//   - request_timeout: Request timeout (default: 30s)
//   - max_document_size: Max document size in bytes (default: 1MB)
//   - max_content_length: Max content length (default: 10MB)
//   - trace_server: LSP trace level - off, messages, verbose (default: off)
//
// Server: General server settings
//
//   - log_level: Log level - debug, info, warn, error (default: info)
//   - log_file: Log file path (default: stderr)
//   - metrics_enabled: Enable metrics collection (default: true)
//   - shutdown_timeout: Graceful shutdown timeout (default: 5s)
//
// # Basic Usage
//
// Loading configuration from a file:
//
//	config, err := config.LoadFromFile("gosqlx.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Loading with defaults and environment variables:
//
//	config, err := config.LoadWithDefaults("", true)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Multi-Source Configuration
//
// Loading from multiple sources with proper precedence:
//
//	// Create base configuration
//	defaults := config.DefaultConfig()
//
//	// Load from file (if exists)
//	fileConfig, _ := config.LoadFromFile("gosqlx.yaml")
//
//	// Load from environment
//	envConfig, _ := config.LoadFromEnvironment("GOSQLX")
//
//	// Merge configurations (later sources override earlier)
//	merged := config.Merge(defaults, fileConfig, envConfig)
//
// # Configuration Files
//
// YAML format (.gosqlx.yaml):
//
//	format:
//	  indent: 4
//	  uppercase_keywords: true
//	  max_line_length: 100
//
//	validation:
//	  dialect: postgresql
//	  strict_mode: false
//	  security:
//	    max_file_size: 10485760
//
//	lsp:
//	  trace_server: messages
//	  request_timeout: 30s
//
//	server:
//	  log_level: info
//	  metrics_enabled: true
//
// JSON format (gosqlx.json):
//
//	{
//	  "format": {
//	    "indent": 4,
//	    "uppercaseKeywords": true
//	  },
//	  "validation": {
//	    "dialect": "postgresql"
//	  }
//	}
//
// # Environment Variables
//
// All configuration options can be set via environment variables using the GOSQLX_ prefix:
//
//	export GOSQLX_FORMAT_INDENT=4
//	export GOSQLX_FORMAT_UPPERCASE_KEYWORDS=true
//	export GOSQLX_VALIDATION_DIALECT=postgresql
//	export GOSQLX_LSP_TRACE_SERVER=messages
//	export GOSQLX_SERVER_LOG_LEVEL=debug
//
// Boolean values accept: true, false, 1, 0, t, f, T, F
// Duration values accept: 30s, 5m, 1h, etc.
//
// # LSP Integration
//
// Loading from LSP initialization options:
//
//	config, err := config.LoadFromLSPInitOptions(initOptions)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Converting to LSP settings format:
//
//	settings := config.ToLSPSettings(myConfig)
//	// Returns map suitable for VSCode settings.json
//
// Merging LSP configuration changes:
//
//	updated, err := config.MergeLSPConfig(currentConfig, changes)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Configuration Caching
//
// The package includes built-in caching for file-based configurations with automatic
// invalidation based on file modification times:
//
//	// Cached loading (recommended for repeated access)
//	config, err := config.LoadFromFileCached("gosqlx.yaml")
//
//	// Clear cache (useful after config changes)
//	config.ClearConfigCache()
//
//	// Invalidate specific file
//	config.InvalidateConfigCache("gosqlx.yaml")
//
//	// Get cache statistics
//	stats := config.GetConfigCacheStats()
//	fmt.Printf("Cache hit rate: %.2f%%\n", stats.HitRate * 100)
//
// Cache characteristics:
//
//   - Thread-safe operations with RWMutex
//   - Automatic invalidation on file modification
//   - TTL-based expiration (default: 5 minutes)
//   - LRU-style eviction when max size reached
//   - Atomic metrics tracking (hits, misses, evictions)
//
// # Configuration Search Paths
//
// Default search paths (in order of precedence):
//
//  1. ./gosqlx.yaml
//  2. ./gosqlx.yml
//  3. ./gosqlx.json
//  4. ./.gosqlx.yaml
//  5. ./.gosqlx.yml
//  6. ~/.config/gosqlx/config.yaml
//  7. ~/.config/gosqlx/config.yml
//  8. ~/.config/gosqlx/config.json
//  9. /etc/gosqlx/config.yaml
//  10. /etc/gosqlx/config.yml
//  11. /etc/gosqlx/config.json
//
// Loading from search paths:
//
//	paths := config.GetDefaultConfigPaths()
//	cfg, err := config.LoadFromFiles(paths)
//	if err != nil {
//	    // No config file found in any location
//	    cfg = config.DefaultConfig()
//	}
//
// # Validation
//
// All loaded configurations are automatically validated:
//
//	config := config.DefaultConfig()
//	config.Format.Indent = -1  // Invalid value
//
//	err := config.Validate()
//	// err: "format.indent must be non-negative, got -1"
//
// Validation checks:
//
//   - Format: Non-negative indent and max_line_length
//   - Validation: Valid dialect (postgresql, mysql, sqlserver, oracle, sqlite)
//   - Output: Valid format (text, json, yaml)
//   - LSP: Non-negative rate limits, timeouts, and size limits
//   - LSP: Valid trace server level (off, messages, verbose)
//   - Server: Valid log level (debug, info, warn, error)
//   - Server: Non-negative shutdown timeout
//
// # Helper Functions
//
// The package provides helper functions for working with boolean pointers:
//
//	// Create bool pointer
//	ptr := config.Bool(true)
//
//	// Get bool value with default
//	value := config.BoolValue(ptr)  // Returns false if nil
//
//	// Get bool value with custom default
//	value := config.BoolValueOr(ptr, true)  // Returns true if nil
//
// These helpers distinguish between "not set" (nil) and "explicitly set to false".
//
// # Thread Safety
//
// The config package is designed for concurrent use:
//
//   - All exported functions are safe for concurrent calls
//   - Config caching uses sync.RWMutex for thread-safe access
//   - Metrics use atomic operations for lock-free updates
//   - Immutable Config objects after loading (use Clone() for modifications)
//
// # Performance Considerations
//
// Configuration loading performance characteristics:
//
//   - File loading: I/O bound, uses caching for repeated access
//   - Environment loading: Fast, reads environment once
//   - LSP loading: Fast, JSON marshaling/unmarshaling overhead
//   - Merging: Fast, linear in number of config sections
//   - Validation: Fast, constant time checks
//
// Recommended practices:
//
//   - Use LoadFromFileCached() for repeated file access
//   - Load configuration once at startup, reuse throughout application
//   - Use Clone() when creating modified configurations
//   - Monitor cache hit rate with GetConfigCacheStats()
//
// # Example: Complete CLI Integration
//
//	package main
//
//	import (
//	    "flag"
//	    "log"
//
//	    "github.com/ajitpratap0/GoSQLX/pkg/config"
//	)
//
//	func main() {
//	    configFile := flag.String("config", "", "Configuration file path")
//	    dialect := flag.String("dialect", "", "SQL dialect override")
//	    flag.Parse()
//
//	    // Load configuration with defaults
//	    cfg, err := config.LoadWithDefaults(*configFile, true)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Apply CLI flag overrides
//	    if *dialect != "" {
//	        cfg.Validation.Dialect = *dialect
//	        if err := cfg.Validate(); err != nil {
//	            log.Fatal(err)
//	        }
//	    }
//
//	    // Use configuration
//	    log.Printf("Using dialect: %s", cfg.Validation.Dialect)
//	    log.Printf("Indent: %d spaces", cfg.Format.Indent)
//	}
//
// # Example: LSP Server Integration
//
//	package main
//
//	import (
//	    "log"
//
//	    "github.com/ajitpratap0/GoSQLX/pkg/config"
//	)
//
//	func handleInitialize(initOptions interface{}) {
//	    // Load base configuration
//	    baseConfig, _ := config.LoadWithDefaults("", true)
//
//	    // Merge LSP initialization options
//	    cfg, err := config.MergeLSPConfig(baseConfig, initOptions)
//	    if err != nil {
//	        log.Printf("Invalid LSP config: %v", err)
//	        cfg = baseConfig
//	    }
//
//	    // Configure LSP server with merged settings
//	    startLSPServer(cfg)
//	}
//
//	func handleConfigChange(changes interface{}) {
//	    // Merge configuration changes
//	    cfg, err := config.MergeLSPConfig(currentConfig, changes)
//	    if err != nil {
//	        log.Printf("Invalid config change: %v", err)
//	        return
//	    }
//
//	    // Apply new configuration
//	    updateConfiguration(cfg)
//	}
//
// # Version History
//
// v1.6.0: Initial release with unified configuration system
//   - File-based configuration (YAML/JSON)
//   - Environment variable support
//   - LSP integration
//   - Thread-safe caching
//   - Comprehensive validation
//
// # See Also
//
//   - docs/CONFIGURATION.md - Complete configuration guide
//   - docs/LSP_GUIDE.md - LSP server configuration
//   - cmd/gosqlx - CLI tool using this package
//   - pkg/lsp - LSP server using this package
package config
