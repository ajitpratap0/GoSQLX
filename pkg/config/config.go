package config

import (
	"fmt"
	"time"
)

// Config represents unified GoSQLX configuration that can be shared across
// CLI, LSP server, and VSCode extension. It supports loading from files,
// environment variables, and LSP initialization options.
type Config struct {
	Format     FormatConfig     `yaml:"format" json:"format"`
	Validation ValidationConfig `yaml:"validation" json:"validation"`
	Output     OutputConfig     `yaml:"output" json:"output"`
	Analyze    AnalyzeConfig    `yaml:"analyze" json:"analyze"`
	LSP        LSPConfig        `yaml:"lsp" json:"lsp"`
	Server     ServerConfig     `yaml:"server" json:"server"`
	Source     string           `yaml:"-" json:"-"` // where config came from (file path, "environment", "lsp", etc.)
}

// FormatConfig holds SQL formatting options
type FormatConfig struct {
	Indent            int  `yaml:"indent" json:"indent"`                        // Number of spaces for indentation (default: 2)
	UppercaseKeywords bool `yaml:"uppercase_keywords" json:"uppercaseKeywords"` // Convert SQL keywords to uppercase (default: true)
	MaxLineLength     int  `yaml:"max_line_length" json:"maxLineLength"`        // Maximum line length before wrapping (default: 120)
	Compact           bool `yaml:"compact" json:"compact"`                      // Use compact formatting (default: false)
}

// ValidationConfig holds SQL validation options
type ValidationConfig struct {
	Dialect    string         `yaml:"dialect" json:"dialect"`        // SQL dialect: postgresql, mysql, sqlserver, oracle, sqlite (default: "postgresql")
	StrictMode bool           `yaml:"strict_mode" json:"strictMode"` // Enable strict validation mode (default: false)
	Recursive  bool           `yaml:"recursive" json:"recursive"`    // Recursively validate files in directories (default: false)
	Pattern    string         `yaml:"pattern" json:"pattern"`        // File pattern for recursive validation (default: "*.sql")
	Security   SecurityConfig `yaml:"security" json:"security"`      // Security validation settings
}

// SecurityConfig holds security validation settings
type SecurityConfig struct {
	MaxFileSize int64 `yaml:"max_file_size" json:"maxFileSize"` // Maximum file size in bytes (default: 10MB)
}

// OutputConfig holds output formatting options
type OutputConfig struct {
	Format  string `yaml:"format" json:"format"`   // Output format: text, json, yaml (default: "text")
	Verbose bool   `yaml:"verbose" json:"verbose"` // Enable verbose output (default: false)
}

// AnalyzeConfig holds analysis options
type AnalyzeConfig struct {
	Security    bool `yaml:"security" json:"security"`       // Enable security analysis (default: false)
	Performance bool `yaml:"performance" json:"performance"` // Enable performance analysis (default: false)
	Complexity  bool `yaml:"complexity" json:"complexity"`   // Enable complexity analysis (default: false)
	All         bool `yaml:"all" json:"all"`                 // Enable all analysis types (default: false)
}

// LSPConfig holds LSP server-specific settings
type LSPConfig struct {
	RateLimitRequests int           `yaml:"rate_limit_requests" json:"rateLimitRequests"` // Max requests per window (default: 100)
	RateLimitWindow   time.Duration `yaml:"rate_limit_window" json:"rateLimitWindow"`     // Rate limit time window (default: 1s)
	RequestTimeout    time.Duration `yaml:"request_timeout" json:"requestTimeout"`        // Request timeout (default: 30s)
	MaxDocumentSize   int           `yaml:"max_document_size" json:"maxDocumentSize"`     // Max document size in bytes (default: 1MB)
	MaxContentLength  int           `yaml:"max_content_length" json:"maxContentLength"`   // Max content length (default: 10MB)
	TraceServer       string        `yaml:"trace_server" json:"traceServer"`              // LSP trace level: off, messages, verbose (default: "off")
}

// ServerConfig holds general server settings
type ServerConfig struct {
	LogLevel        string        `yaml:"log_level" json:"logLevel"`               // Log level: debug, info, warn, error (default: "info")
	LogFile         string        `yaml:"log_file" json:"logFile"`                 // Log file path (default: "" for stderr)
	MetricsEnabled  bool          `yaml:"metrics_enabled" json:"metricsEnabled"`   // Enable metrics collection (default: true)
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdownTimeout"` // Graceful shutdown timeout (default: 5s)
}

// DefaultConfig returns a configuration with sensible default values
func DefaultConfig() *Config {
	return &Config{
		Format: FormatConfig{
			Indent:            2,
			UppercaseKeywords: true,
			MaxLineLength:     120,
			Compact:           false,
		},
		Validation: ValidationConfig{
			Dialect:    "postgresql",
			StrictMode: false,
			Recursive:  false,
			Pattern:    "*.sql",
			Security: SecurityConfig{
				MaxFileSize: 10 * 1024 * 1024, // 10MB
			},
		},
		Output: OutputConfig{
			Format:  "text",
			Verbose: false,
		},
		Analyze: AnalyzeConfig{
			Security:    false,
			Performance: false,
			Complexity:  false,
			All:         false,
		},
		LSP: LSPConfig{
			RateLimitRequests: 100,
			RateLimitWindow:   time.Second,
			RequestTimeout:    30 * time.Second,
			MaxDocumentSize:   1024 * 1024,      // 1MB
			MaxContentLength:  10 * 1024 * 1024, // 10MB
			TraceServer:       "off",
		},
		Server: ServerConfig{
			LogLevel:        "info",
			LogFile:         "",
			MetricsEnabled:  true,
			ShutdownTimeout: 5 * time.Second,
		},
		Source: "default",
	}
}

// Validate validates the configuration and returns an error if any settings are invalid
func (c *Config) Validate() error {
	// Validate Format settings
	if c.Format.Indent < 0 {
		return fmt.Errorf("format.indent must be non-negative, got %d", c.Format.Indent)
	}
	if c.Format.MaxLineLength < 0 {
		return fmt.Errorf("format.max_line_length must be non-negative, got %d", c.Format.MaxLineLength)
	}

	// Validate Validation settings
	validDialects := map[string]bool{
		"postgresql": true,
		"mysql":      true,
		"sqlserver":  true,
		"oracle":     true,
		"sqlite":     true,
	}
	if c.Validation.Dialect != "" && !validDialects[c.Validation.Dialect] {
		return fmt.Errorf("validation.dialect must be one of: postgresql, mysql, sqlserver, oracle, sqlite; got %q", c.Validation.Dialect)
	}
	if c.Validation.Security.MaxFileSize < 0 {
		return fmt.Errorf("validation.security.max_file_size must be non-negative, got %d", c.Validation.Security.MaxFileSize)
	}

	// Validate Output settings
	validFormats := map[string]bool{
		"text": true,
		"json": true,
		"yaml": true,
	}
	if c.Output.Format != "" && !validFormats[c.Output.Format] {
		return fmt.Errorf("output.format must be one of: text, json, yaml; got %q", c.Output.Format)
	}

	// Validate LSP settings
	if c.LSP.RateLimitRequests < 0 {
		return fmt.Errorf("lsp.rate_limit_requests must be non-negative, got %d", c.LSP.RateLimitRequests)
	}
	if c.LSP.RateLimitWindow < 0 {
		return fmt.Errorf("lsp.rate_limit_window must be non-negative, got %v", c.LSP.RateLimitWindow)
	}
	if c.LSP.RequestTimeout < 0 {
		return fmt.Errorf("lsp.request_timeout must be non-negative, got %v", c.LSP.RequestTimeout)
	}
	if c.LSP.MaxDocumentSize < 0 {
		return fmt.Errorf("lsp.max_document_size must be non-negative, got %d", c.LSP.MaxDocumentSize)
	}
	if c.LSP.MaxContentLength < 0 {
		return fmt.Errorf("lsp.max_content_length must be non-negative, got %d", c.LSP.MaxContentLength)
	}
	validTraceLevels := map[string]bool{
		"off":      true,
		"messages": true,
		"verbose":  true,
	}
	if c.LSP.TraceServer != "" && !validTraceLevels[c.LSP.TraceServer] {
		return fmt.Errorf("lsp.trace_server must be one of: off, messages, verbose; got %q", c.LSP.TraceServer)
	}

	// Validate Server settings
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if c.Server.LogLevel != "" && !validLogLevels[c.Server.LogLevel] {
		return fmt.Errorf("server.log_level must be one of: debug, info, warn, error; got %q", c.Server.LogLevel)
	}
	if c.Server.ShutdownTimeout < 0 {
		return fmt.Errorf("server.shutdown_timeout must be non-negative, got %v", c.Server.ShutdownTimeout)
	}

	return nil
}

// Clone creates a deep copy of the configuration
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	clone := *c
	return &clone
}

// ApplyDefaults fills in any zero values with defaults
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig()

	// Apply Format defaults
	if c.Format.Indent == 0 {
		c.Format.Indent = defaults.Format.Indent
	}
	if c.Format.MaxLineLength == 0 {
		c.Format.MaxLineLength = defaults.Format.MaxLineLength
	}

	// Apply Validation defaults
	if c.Validation.Dialect == "" {
		c.Validation.Dialect = defaults.Validation.Dialect
	}
	if c.Validation.Pattern == "" {
		c.Validation.Pattern = defaults.Validation.Pattern
	}
	if c.Validation.Security.MaxFileSize == 0 {
		c.Validation.Security.MaxFileSize = defaults.Validation.Security.MaxFileSize
	}

	// Apply Output defaults
	if c.Output.Format == "" {
		c.Output.Format = defaults.Output.Format
	}

	// Apply LSP defaults
	if c.LSP.RateLimitRequests == 0 {
		c.LSP.RateLimitRequests = defaults.LSP.RateLimitRequests
	}
	if c.LSP.RateLimitWindow == 0 {
		c.LSP.RateLimitWindow = defaults.LSP.RateLimitWindow
	}
	if c.LSP.RequestTimeout == 0 {
		c.LSP.RequestTimeout = defaults.LSP.RequestTimeout
	}
	if c.LSP.MaxDocumentSize == 0 {
		c.LSP.MaxDocumentSize = defaults.LSP.MaxDocumentSize
	}
	if c.LSP.MaxContentLength == 0 {
		c.LSP.MaxContentLength = defaults.LSP.MaxContentLength
	}
	if c.LSP.TraceServer == "" {
		c.LSP.TraceServer = defaults.LSP.TraceServer
	}

	// Apply Server defaults
	if c.Server.LogLevel == "" {
		c.Server.LogLevel = defaults.Server.LogLevel
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = defaults.Server.ShutdownTimeout
	}
}
