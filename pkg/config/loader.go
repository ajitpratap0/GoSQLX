package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// LoadFromFile loads configuration from a single file.
// Supports both YAML and JSON formats based on file extension.
func LoadFromFile(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config file path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found %s: %w", path, err)
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	config := DefaultConfig()
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config %s: %w", path, err)
		}
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config %s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s (must be .yaml, .yml, or .json)", ext)
	}

	config.Source = path
	config.ApplyDefaults()

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config in %s: %w", path, err)
	}

	return config, nil
}

// LoadFromFiles tries to load configuration from multiple paths in order.
// Returns the first successfully loaded configuration, or an error if none can be loaded.
// This is useful for searching common config locations like:
// - ./gosqlx.yaml
// - ~/.config/gosqlx/config.yaml
// - /etc/gosqlx/config.yaml
func LoadFromFiles(searchPaths []string) (*Config, error) {
	if len(searchPaths) == 0 {
		return nil, fmt.Errorf("no search paths provided")
	}

	var errs []error
	for _, path := range searchPaths {
		config, err := LoadFromFile(path)
		if err == nil {
			return config, nil
		}

		// Continue trying other paths if file doesn't exist
		if errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("%s: not found", path))
			continue
		}

		// If it's not a "file not found" error, it's a real error - return immediately
		return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
	}

	// If we get here, no config file was found
	return nil, fmt.Errorf("no config file found in search paths")
}

// LoadFromEnvironment loads configuration from environment variables.
// Variable names are prefixed with the given prefix (e.g., "GOSQLX_").
// Nested fields use underscores: GOSQLX_FORMAT_INDENT, GOSQLX_LSP_REQUEST_TIMEOUT, etc.
// Only values explicitly set in environment variables are included in the returned config.
func LoadFromEnvironment(prefix string) (*Config, error) {
	if prefix == "" {
		prefix = "GOSQLX_"
	}
	if !strings.HasSuffix(prefix, "_") {
		prefix += "_"
	}

	// Start with empty config - only set values that are explicitly in environment
	config := &Config{Source: "environment"}

	// Format settings
	if v := os.Getenv(prefix + "FORMAT_INDENT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Format.Indent = i
		}
	}
	if v := os.Getenv(prefix + "FORMAT_UPPERCASE_KEYWORDS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Format.UppercaseKeywords = b
		}
	}
	if v := os.Getenv(prefix + "FORMAT_MAX_LINE_LENGTH"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.Format.MaxLineLength = i
		}
	}
	if v := os.Getenv(prefix + "FORMAT_COMPACT"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Format.Compact = b
		}
	}

	// Validation settings
	if v := os.Getenv(prefix + "VALIDATION_DIALECT"); v != "" {
		config.Validation.Dialect = v
	}
	if v := os.Getenv(prefix + "VALIDATION_STRICT_MODE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Validation.StrictMode = b
		}
	}
	if v := os.Getenv(prefix + "VALIDATION_RECURSIVE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Validation.Recursive = b
		}
	}
	if v := os.Getenv(prefix + "VALIDATION_PATTERN"); v != "" {
		config.Validation.Pattern = v
	}
	if v := os.Getenv(prefix + "VALIDATION_SECURITY_MAX_FILE_SIZE"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			config.Validation.Security.MaxFileSize = i
		}
	}

	// Output settings
	if v := os.Getenv(prefix + "OUTPUT_FORMAT"); v != "" {
		config.Output.Format = v
	}
	if v := os.Getenv(prefix + "OUTPUT_VERBOSE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Output.Verbose = b
		}
	}

	// Analyze settings
	if v := os.Getenv(prefix + "ANALYZE_SECURITY"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Analyze.Security = b
		}
	}
	if v := os.Getenv(prefix + "ANALYZE_PERFORMANCE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Analyze.Performance = b
		}
	}
	if v := os.Getenv(prefix + "ANALYZE_COMPLEXITY"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Analyze.Complexity = b
		}
	}
	if v := os.Getenv(prefix + "ANALYZE_ALL"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Analyze.All = b
		}
	}

	// LSP settings
	if v := os.Getenv(prefix + "LSP_RATE_LIMIT_REQUESTS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.LSP.RateLimitRequests = i
		}
	}
	if v := os.Getenv(prefix + "LSP_RATE_LIMIT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.LSP.RateLimitWindow = d
		}
	}
	if v := os.Getenv(prefix + "LSP_REQUEST_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.LSP.RequestTimeout = d
		}
	}
	if v := os.Getenv(prefix + "LSP_MAX_DOCUMENT_SIZE"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.LSP.MaxDocumentSize = i
		}
	}
	if v := os.Getenv(prefix + "LSP_MAX_CONTENT_LENGTH"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			config.LSP.MaxContentLength = i
		}
	}
	if v := os.Getenv(prefix + "LSP_TRACE_SERVER"); v != "" {
		config.LSP.TraceServer = v
	}

	// Server settings
	if v := os.Getenv(prefix + "SERVER_LOG_LEVEL"); v != "" {
		config.Server.LogLevel = v
	}
	if v := os.Getenv(prefix + "SERVER_LOG_FILE"); v != "" {
		config.Server.LogFile = v
	}
	if v := os.Getenv(prefix + "SERVER_METRICS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			config.Server.MetricsEnabled = b
		}
	}
	if v := os.Getenv(prefix + "SERVER_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.ShutdownTimeout = d
		}
	}

	// Note: We don't validate here because this config is meant to be merged
	// with other configs. Validation happens after merging in LoadWithDefaults.
	return config, nil
}

// Merge merges multiple configurations, with later configs taking precedence over earlier ones.
// Zero values in later configs are ignored (won't override non-zero values from earlier configs).
// This allows layered configuration: defaults -> file -> environment -> CLI flags.
func Merge(configs ...*Config) *Config {
	if len(configs) == 0 {
		return DefaultConfig()
	}

	// Start with the first config
	result := configs[0].Clone()
	if result == nil {
		result = DefaultConfig()
	}

	// Merge each subsequent config
	for i := 1; i < len(configs); i++ {
		if configs[i] == nil {
			continue
		}
		mergeInto(result, configs[i])
	}

	result.ApplyDefaults()
	return result
}

// mergeInto merges src into dst, with non-zero values from src taking precedence
func mergeInto(dst, src *Config) {
	// Merge Format
	if src.Format.Indent != 0 {
		dst.Format.Indent = src.Format.Indent
	}
	if src.Format.UppercaseKeywords {
		dst.Format.UppercaseKeywords = src.Format.UppercaseKeywords
	}
	if src.Format.MaxLineLength != 0 {
		dst.Format.MaxLineLength = src.Format.MaxLineLength
	}
	if src.Format.Compact {
		dst.Format.Compact = src.Format.Compact
	}

	// Merge Validation
	if src.Validation.Dialect != "" {
		dst.Validation.Dialect = src.Validation.Dialect
	}
	if src.Validation.StrictMode {
		dst.Validation.StrictMode = src.Validation.StrictMode
	}
	if src.Validation.Recursive {
		dst.Validation.Recursive = src.Validation.Recursive
	}
	if src.Validation.Pattern != "" {
		dst.Validation.Pattern = src.Validation.Pattern
	}
	if src.Validation.Security.MaxFileSize != 0 {
		dst.Validation.Security.MaxFileSize = src.Validation.Security.MaxFileSize
	}

	// Merge Output
	if src.Output.Format != "" {
		dst.Output.Format = src.Output.Format
	}
	if src.Output.Verbose {
		dst.Output.Verbose = src.Output.Verbose
	}

	// Merge Analyze
	if src.Analyze.Security {
		dst.Analyze.Security = src.Analyze.Security
	}
	if src.Analyze.Performance {
		dst.Analyze.Performance = src.Analyze.Performance
	}
	if src.Analyze.Complexity {
		dst.Analyze.Complexity = src.Analyze.Complexity
	}
	if src.Analyze.All {
		dst.Analyze.All = src.Analyze.All
	}

	// Merge LSP
	if src.LSP.RateLimitRequests != 0 {
		dst.LSP.RateLimitRequests = src.LSP.RateLimitRequests
	}
	if src.LSP.RateLimitWindow != 0 {
		dst.LSP.RateLimitWindow = src.LSP.RateLimitWindow
	}
	if src.LSP.RequestTimeout != 0 {
		dst.LSP.RequestTimeout = src.LSP.RequestTimeout
	}
	if src.LSP.MaxDocumentSize != 0 {
		dst.LSP.MaxDocumentSize = src.LSP.MaxDocumentSize
	}
	if src.LSP.MaxContentLength != 0 {
		dst.LSP.MaxContentLength = src.LSP.MaxContentLength
	}
	if src.LSP.TraceServer != "" {
		dst.LSP.TraceServer = src.LSP.TraceServer
	}

	// Merge Server
	if src.Server.LogLevel != "" {
		dst.Server.LogLevel = src.Server.LogLevel
	}
	if src.Server.LogFile != "" {
		dst.Server.LogFile = src.Server.LogFile
	}
	if src.Server.MetricsEnabled {
		dst.Server.MetricsEnabled = src.Server.MetricsEnabled
	}
	if src.Server.ShutdownTimeout != 0 {
		dst.Server.ShutdownTimeout = src.Server.ShutdownTimeout
	}

	// Update source to indicate merged config
	if src.Source != "" {
		if dst.Source == "default" {
			dst.Source = src.Source
		} else {
			dst.Source = fmt.Sprintf("%s+%s", dst.Source, src.Source)
		}
	}
}

// LoadWithDefaults loads configuration from multiple sources with the following precedence:
// 1. Default configuration (lowest priority)
// 2. Configuration file (if provided and exists)
// 3. Environment variables (if enabled)
// The result is validated before being returned.
func LoadWithDefaults(configFile string, useEnv bool) (*Config, error) {
	configs := []*Config{DefaultConfig()}

	// Try to load from file if provided
	if configFile != "" {
		fileConfig, err := LoadFromFile(configFile)
		if err != nil {
			// Return error if file was explicitly specified but can't be loaded
			return nil, err
		}
		configs = append(configs, fileConfig)
	}

	// Load from environment if enabled
	if useEnv {
		envConfig, err := LoadFromEnvironment("GOSQLX")
		if err != nil {
			return nil, err
		}
		configs = append(configs, envConfig)
	}

	result := Merge(configs...)
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("merged config validation failed: %w", err)
	}

	return result, nil
}

// GetDefaultConfigPaths returns common configuration file paths to search.
// The paths are returned in order of precedence (highest to lowest):
// 1. Current directory
// 2. User config directory (~/.config/gosqlx/)
// 3. System config directory (/etc/gosqlx/)
func GetDefaultConfigPaths() []string {
	paths := []string{
		"gosqlx.yaml",
		"gosqlx.yml",
		"gosqlx.json",
		".gosqlx.yaml",
		".gosqlx.yml",
	}

	// Add user config directory
	if homeDir, err := os.UserHomeDir(); err == nil {
		userConfigDir := filepath.Join(homeDir, ".config", "gosqlx")
		paths = append(paths,
			filepath.Join(userConfigDir, "config.yaml"),
			filepath.Join(userConfigDir, "config.yml"),
			filepath.Join(userConfigDir, "config.json"),
		)
	}

	// Add system config directory (Unix-like systems)
	paths = append(paths,
		"/etc/gosqlx/config.yaml",
		"/etc/gosqlx/config.yml",
		"/etc/gosqlx/config.json",
	)

	return paths
}
