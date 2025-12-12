package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the complete GoSQLX CLI configuration.
//
// Configuration files use YAML format and are loaded from:
//  1. Current directory: .gosqlx.yml
//  2. Home directory: ~/.gosqlx.yml
//  3. System: /etc/gosqlx.yml
//
// CLI flags always override configuration file settings.
//
// Example configuration file:
//
//	format:
//	  indent: 2
//	  uppercase_keywords: true
//	  max_line_length: 80
//	  compact: false
//
//	validate:
//	  dialect: postgresql
//	  strict_mode: false
//	  recursive: false
//	  pattern: "*.sql"
//	  security:
//	    max_file_size: 10485760
//
//	output:
//	  format: auto
//	  verbose: false
//
//	analyze:
//	  security: true
//	  performance: true
//	  complexity: true
//	  all: false
type Config struct {
	Format     FormatConfig     `yaml:"format"`
	Validation ValidationConfig `yaml:"validate"`
	Output     OutputConfig     `yaml:"output"`
	Analyze    AnalyzeConfig    `yaml:"analyze"`
}

// FormatConfig holds SQL formatting options.
//
// Controls how SQL is formatted by the format command.
//
// Fields:
//   - Indent: Number of spaces for indentation (0-8, default: 2)
//   - UppercaseKeywords: Convert SQL keywords to uppercase (default: true)
//   - MaxLineLength: Maximum line length for wrapping (0-500, default: 80)
//   - Compact: Use compact format with minimal whitespace (default: false)
type FormatConfig struct {
	Indent            int  `yaml:"indent"`
	UppercaseKeywords bool `yaml:"uppercase_keywords"`
	MaxLineLength     int  `yaml:"max_line_length"`
	Compact           bool `yaml:"compact"`
}

// ValidationConfig holds SQL validation options.
//
// Controls validation behavior including dialect selection and security limits.
//
// Fields:
//   - Dialect: SQL dialect for validation (postgresql, mysql, sqlserver, oracle, sqlite, generic)
//   - StrictMode: Enable strict validation rules (default: false)
//   - Recursive: Recursively process directories (default: false)
//   - Pattern: File pattern for recursive processing (default: "*.sql")
//   - Security: Security-related limits (file size, etc.)
type ValidationConfig struct {
	Dialect    string         `yaml:"dialect"`
	StrictMode bool           `yaml:"strict_mode"`
	Recursive  bool           `yaml:"recursive"`
	Pattern    string         `yaml:"pattern"`
	Security   SecurityConfig `yaml:"security"`
}

// SecurityConfig holds security-related limits for file operations.
//
// Prevents resource exhaustion and security vulnerabilities.
//
// Fields:
//   - MaxFileSize: Maximum allowed file size in bytes (default: 10MB)
//
// Example:
//
//	security:
//	  max_file_size: 20971520  # 20MB
type SecurityConfig struct {
	MaxFileSize int64 `yaml:"max_file_size"` // Maximum file size in bytes
}

// OutputConfig holds output formatting options.
//
// Controls output format and verbosity for all commands.
//
// Fields:
//   - Format: Output format (json, yaml, table, tree, auto) (default: auto)
//   - Verbose: Enable detailed output for debugging (default: false)
type OutputConfig struct {
	Format  string `yaml:"format"` // json, yaml, table
	Verbose bool   `yaml:"verbose"`
}

// AnalyzeConfig holds SQL analysis options.
//
// Controls which analysis features are enabled by default.
//
// Fields:
//   - Security: Perform security vulnerability analysis (default: true)
//   - Performance: Perform performance analysis (default: true)
//   - Complexity: Calculate complexity metrics (default: true)
//   - All: Enable comprehensive analysis (default: false)
type AnalyzeConfig struct {
	Security    bool `yaml:"security"`
	Performance bool `yaml:"performance"`
	Complexity  bool `yaml:"complexity"`
	All         bool `yaml:"all"`
}

// DefaultConfig returns a configuration with sensible defaults.
//
// This function creates a Config instance with production-ready defaults
// suitable for most use cases. These defaults balance performance, code quality,
// and compatibility.
//
// Default values:
//   - Format: 2-space indentation, uppercase keywords, 80-char line length
//   - Validation: PostgreSQL dialect, non-strict mode, *.sql pattern
//   - Security: 10MB max file size
//   - Output: Auto format selection, non-verbose
//   - Analysis: All features enabled except comprehensive mode
//
// Returns:
//   - *Config with default values initialized
//
// Usage:
//
//	cfg := config.DefaultConfig()
//	cfg.Format.Indent = 4  // Customize as needed
//	cfg.Save(".gosqlx.yml")
func DefaultConfig() *Config {
	return &Config{
		Format: FormatConfig{
			Indent:            2,
			UppercaseKeywords: true,
			MaxLineLength:     80,
			Compact:           false,
		},
		Validation: ValidationConfig{
			Dialect:    "postgresql",
			StrictMode: false,
			Recursive:  false,
			Pattern:    "*.sql",
			Security: SecurityConfig{
				MaxFileSize: 10 * 1024 * 1024, // 10MB default
			},
		},
		Output: OutputConfig{
			Format:  "auto",
			Verbose: false,
		},
		Analyze: AnalyzeConfig{
			Security:    true,
			Performance: true,
			Complexity:  true,
			All:         false,
		},
	}
}

// Load reads a configuration file from the specified path.
//
// This function loads and parses a YAML configuration file, validates the
// configuration values, and returns a Config instance.
//
// The path is automatically expanded if it starts with ~ (home directory).
//
// Parameters:
//   - path: File path to the configuration file (absolute or relative)
//
// Returns:
//   - *Config: Loaded and validated configuration
//   - error: File reading, parsing, or validation error
//
// Possible errors:
//   - File not found or inaccessible
//   - Invalid YAML syntax
//   - Configuration validation failure (invalid values)
//   - Home directory lookup failure (for ~ expansion)
//
// Example:
//
//	cfg, err := config.Load(".gosqlx.yml")
//	if err != nil {
//	    log.Fatalf("Failed to load config: %v", err)
//	}
//	fmt.Printf("Using dialect: %s\n", cfg.Validation.Dialect)
func Load(path string) (*Config, error) {
	// Expand home directory if present
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, path[1:])
	}

	// G304: Path is either from filepath.Join or user config, acceptable risk
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate configuration values after unmarshaling
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// LoadDefault tries to load configuration from standard locations with precedence.
//
// This function searches for configuration files in multiple standard locations
// and loads the first one found. If no configuration file exists, it returns
// a default configuration.
//
// Search order (first found wins):
//  1. Current directory: .gosqlx.yml
//  2. Home directory: ~/.gosqlx.yml
//  3. System-wide: /etc/gosqlx.yml
//  4. Built-in defaults (if no file found)
//
// This allows for flexible configuration strategies:
//   - Project-specific config in current directory
//   - User-specific config in home directory
//   - System-wide config for all users
//   - Automatic fallback to sensible defaults
//
// Returns:
//   - *Config: Loaded configuration or defaults
//   - error: Always returns a valid Config (errors are logged but not fatal)
//
// Example:
//
//	cfg, err := config.LoadDefault()
//	// cfg is always non-nil, even if err != nil
//	// err indicates which config was loaded or if defaults were used
func LoadDefault() (*Config, error) {
	searchPaths := []string{
		".gosqlx.yml",
		"~/.gosqlx.yml",
		"/etc/gosqlx.yml",
	}

	for _, path := range searchPaths {
		// Expand home directory
		expandedPath := path
		if len(path) > 0 && path[0] == '~' {
			home, err := os.UserHomeDir()
			if err != nil {
				continue
			}
			expandedPath = filepath.Join(home, path[1:])
		}

		// Check if file exists
		if _, err := os.Stat(expandedPath); err == nil {
			config, err := Load(expandedPath)
			if err != nil {
				// Log error but continue searching
				continue
			}
			return config, nil
		}
	}

	// No config file found, return defaults
	return DefaultConfig(), nil
}

// Save writes the configuration to the specified path
func (c *Config) Save(path string) error {
	// Expand home directory if present
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, path[1:])
	}

	// Marshal to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	// G306: Use 0600 for better security (owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate format settings
	if c.Format.Indent < 0 || c.Format.Indent > 8 {
		return fmt.Errorf("format.indent must be between 0 and 8, got %d", c.Format.Indent)
	}
	if c.Format.MaxLineLength < 0 || c.Format.MaxLineLength > 500 {
		return fmt.Errorf("format.max_line_length must be between 0 and 500, got %d", c.Format.MaxLineLength)
	}

	// Validate dialect
	validDialects := []string{"postgresql", "mysql", "sqlserver", "oracle", "sqlite", "generic"}
	dialectValid := false
	for _, d := range validDialects {
		if c.Validation.Dialect == d {
			dialectValid = true
			break
		}
	}
	if !dialectValid {
		return fmt.Errorf("validate.dialect must be one of: %v, got '%s'", validDialects, c.Validation.Dialect)
	}

	// Validate output format
	validFormats := []string{"json", "yaml", "table", "tree", "auto"}
	formatValid := false
	for _, f := range validFormats {
		if c.Output.Format == f {
			formatValid = true
			break
		}
	}
	if !formatValid {
		return fmt.Errorf("output.format must be one of: %v, got '%s'", validFormats, c.Output.Format)
	}

	return nil
}

// Merge applies settings from another config, with the other config taking precedence
func (c *Config) Merge(other *Config) {
	// This allows CLI flags to override config file settings
	// Only non-zero values from 'other' are applied

	// Format settings
	if other.Format.Indent != 0 {
		c.Format.Indent = other.Format.Indent
	}
	if other.Format.MaxLineLength != 0 {
		c.Format.MaxLineLength = other.Format.MaxLineLength
	}
	// Booleans need special handling since false is a valid value
	// We'd need a way to detect if a flag was explicitly set
	// For now, we just copy the values
	c.Format.UppercaseKeywords = other.Format.UppercaseKeywords
	c.Format.Compact = other.Format.Compact

	// Validation settings
	if other.Validation.Dialect != "" {
		c.Validation.Dialect = other.Validation.Dialect
	}
	if other.Validation.Pattern != "" && other.Validation.Pattern != "*.sql" {
		c.Validation.Pattern = other.Validation.Pattern
	}
	c.Validation.StrictMode = other.Validation.StrictMode
	c.Validation.Recursive = other.Validation.Recursive

	// Output settings
	if other.Output.Format != "" && other.Output.Format != "auto" {
		c.Output.Format = other.Output.Format
	}
	c.Output.Verbose = other.Output.Verbose

	// Analyze settings
	c.Analyze.Security = other.Analyze.Security
	c.Analyze.Performance = other.Analyze.Performance
	c.Analyze.Complexity = other.Analyze.Complexity
	c.Analyze.All = other.Analyze.All
}
