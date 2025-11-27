package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Validate Format defaults
	if cfg.Format.Indent != 2 {
		t.Errorf("expected indent=2, got %d", cfg.Format.Indent)
	}
	if !cfg.Format.UppercaseKeywords {
		t.Error("expected uppercase_keywords=true")
	}
	if cfg.Format.MaxLineLength != 120 {
		t.Errorf("expected max_line_length=120, got %d", cfg.Format.MaxLineLength)
	}

	// Validate Validation defaults
	if cfg.Validation.Dialect != "postgresql" {
		t.Errorf("expected dialect=postgresql, got %s", cfg.Validation.Dialect)
	}
	if cfg.Validation.Pattern != "*.sql" {
		t.Errorf("expected pattern=*.sql, got %s", cfg.Validation.Pattern)
	}
	if cfg.Validation.Security.MaxFileSize != 10*1024*1024 {
		t.Errorf("expected max_file_size=10MB, got %d", cfg.Validation.Security.MaxFileSize)
	}

	// Validate Output defaults
	if cfg.Output.Format != "text" {
		t.Errorf("expected output format=text, got %s", cfg.Output.Format)
	}

	// Validate LSP defaults
	if cfg.LSP.RateLimitRequests != 100 {
		t.Errorf("expected rate_limit_requests=100, got %d", cfg.LSP.RateLimitRequests)
	}
	if cfg.LSP.RequestTimeout != 30*time.Second {
		t.Errorf("expected request_timeout=30s, got %v", cfg.LSP.RequestTimeout)
	}
	if cfg.LSP.TraceServer != "off" {
		t.Errorf("expected trace_server=off, got %s", cfg.LSP.TraceServer)
	}

	// Validate Server defaults
	if cfg.Server.LogLevel != "info" {
		t.Errorf("expected log_level=info, got %s", cfg.Server.LogLevel)
	}
	if !cfg.Server.MetricsEnabled {
		t.Error("expected metrics_enabled=true")
	}

	// Validate source
	if cfg.Source != "default" {
		t.Errorf("expected source=default, got %s", cfg.Source)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		modifier  func(*Config)
		wantError bool
	}{
		{
			name: "valid config",
			modifier: func(c *Config) {
				// No changes - should be valid
			},
			wantError: false,
		},
		{
			name: "negative indent",
			modifier: func(c *Config) {
				c.Format.Indent = -1
			},
			wantError: true,
		},
		{
			name: "invalid dialect",
			modifier: func(c *Config) {
				c.Validation.Dialect = "invalid"
			},
			wantError: true,
		},
		{
			name: "invalid output format",
			modifier: func(c *Config) {
				c.Output.Format = "invalid"
			},
			wantError: true,
		},
		{
			name: "invalid trace server",
			modifier: func(c *Config) {
				c.LSP.TraceServer = "invalid"
			},
			wantError: true,
		},
		{
			name: "invalid log level",
			modifier: func(c *Config) {
				c.Server.LogLevel = "invalid"
			},
			wantError: true,
		},
		{
			name: "negative max file size",
			modifier: func(c *Config) {
				c.Validation.Security.MaxFileSize = -1
			},
			wantError: true,
		},
		{
			name: "negative rate limit",
			modifier: func(c *Config) {
				c.LSP.RateLimitRequests = -1
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modifier(cfg)
			err := cfg.Validate()

			if tt.wantError && err == nil {
				t.Error("expected validation error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestConfigClone(t *testing.T) {
	original := DefaultConfig()
	original.Format.Indent = 4
	original.Validation.Dialect = "mysql"
	original.Server.LogLevel = "debug"

	clone := original.Clone()

	// Verify clone has same values
	if clone.Format.Indent != 4 {
		t.Error("clone has different indent value")
	}
	if clone.Validation.Dialect != "mysql" {
		t.Error("clone has different dialect value")
	}

	// Verify modifying clone doesn't affect original
	clone.Format.Indent = 8
	if original.Format.Indent != 4 {
		t.Error("modifying clone affected original")
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	cfg := &Config{}

	// Start with all zero values
	if cfg.Format.Indent != 0 {
		t.Error("expected zero indent before applying defaults")
	}

	cfg.ApplyDefaults()

	// Verify defaults were applied
	if cfg.Format.Indent != 2 {
		t.Errorf("expected indent=2 after applying defaults, got %d", cfg.Format.Indent)
	}
	if cfg.Validation.Dialect != "postgresql" {
		t.Errorf("expected dialect=postgresql after applying defaults, got %s", cfg.Validation.Dialect)
	}
	if cfg.LSP.TraceServer != "off" {
		t.Errorf("expected trace_server=off after applying defaults, got %s", cfg.LSP.TraceServer)
	}
}

func TestConfigMerge(t *testing.T) {
	base := DefaultConfig()
	base.Format.Indent = 2
	base.Validation.Dialect = "postgresql"
	base.Server.LogLevel = "info"

	override := &Config{
		Format: FormatConfig{
			Indent: 4, // Override
		},
		Server: ServerConfig{
			LogLevel: "debug", // Override
		},
	}

	merged := Merge(base, override)

	// Verify overrides took effect
	if merged.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", merged.Format.Indent)
	}
	if merged.Server.LogLevel != "debug" {
		t.Errorf("expected log_level=debug, got %s", merged.Server.LogLevel)
	}

	// Verify non-overridden values remain
	if merged.Validation.Dialect != "postgresql" {
		t.Errorf("expected dialect=postgresql, got %s", merged.Validation.Dialect)
	}
}

func TestConfigDialects(t *testing.T) {
	validDialects := []string{"postgresql", "mysql", "sqlserver", "oracle", "sqlite"}

	for _, dialect := range validDialects {
		t.Run(dialect, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Validation.Dialect = dialect

			if err := cfg.Validate(); err != nil {
				t.Errorf("dialect %s should be valid but got error: %v", dialect, err)
			}
		})
	}
}

func TestConfigOutputFormats(t *testing.T) {
	validFormats := []string{"text", "json", "yaml"}

	for _, format := range validFormats {
		t.Run(format, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Output.Format = format

			if err := cfg.Validate(); err != nil {
				t.Errorf("format %s should be valid but got error: %v", format, err)
			}
		})
	}
}

func TestConfigTraceLevels(t *testing.T) {
	validLevels := []string{"off", "messages", "verbose"}

	for _, level := range validLevels {
		t.Run(level, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.LSP.TraceServer = level

			if err := cfg.Validate(); err != nil {
				t.Errorf("trace level %s should be valid but got error: %v", level, err)
			}
		})
	}
}

func TestConfigLogLevels(t *testing.T) {
	validLevels := []string{"debug", "info", "warn", "error"}

	for _, level := range validLevels {
		t.Run(level, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Server.LogLevel = level

			if err := cfg.Validate(); err != nil {
				t.Errorf("log level %s should be valid but got error: %v", level, err)
			}
		})
	}
}
