package config

import (
	"testing"
	"time"
)

func TestLoadFromLSPInitOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    interface{}
		want    func(*Config) bool
		wantErr bool
	}{
		{
			name: "nil options",
			opts: nil,
			want: func(c *Config) bool {
				return c.Format.Indent == 2 // default
			},
			wantErr: false,
		},
		{
			name: "valid options",
			opts: map[string]interface{}{
				"format": map[string]interface{}{
					"indent":            float64(4),
					"uppercaseKeywords": true,
					"maxLineLength":     float64(80),
				},
				"validation": map[string]interface{}{
					"dialect": "mysql",
				},
			},
			want: func(c *Config) bool {
				return c.Format.Indent == 4 &&
					c.Format.UppercaseKeywords &&
					c.Format.MaxLineLength == 80 &&
					c.Validation.Dialect == "mysql"
			},
			wantErr: false,
		},
		{
			name: "partial options",
			opts: map[string]interface{}{
				"format": map[string]interface{}{
					"indent": float64(4),
				},
			},
			want: func(c *Config) bool {
				return c.Format.Indent == 4 &&
					c.Validation.Dialect == "postgresql" // default
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadFromLSPInitOptions(tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadFromLSPInitOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !tt.want(cfg) {
				t.Error("config does not match expected values")
			}

			if !tt.wantErr && cfg.Source != "lsp" {
				t.Errorf("expected source=lsp, got %s", cfg.Source)
			}
		})
	}
}

func TestToLSPSettings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Format.Indent = 4
	cfg.Validation.Dialect = "mysql"
	cfg.LSP.TraceServer = "verbose"
	cfg.Server.LogLevel = "debug"

	settings := ToLSPSettings(cfg)

	// Check format settings
	if format, ok := settings["format"].(map[string]interface{}); ok {
		if indent, ok := format["indent"].(int); !ok || indent != 4 {
			t.Errorf("expected format.indent=4, got %v", format["indent"])
		}
		if keywords, ok := format["uppercaseKeywords"].(bool); !ok || !keywords {
			t.Error("expected format.uppercaseKeywords=true")
		}
	} else {
		t.Error("expected format settings in output")
	}

	// Check validation settings
	if validation, ok := settings["validation"].(map[string]interface{}); ok {
		if dialect, ok := validation["dialect"].(string); !ok || dialect != "mysql" {
			t.Errorf("expected validation.dialect=mysql, got %v", validation["dialect"])
		}
	} else {
		t.Error("expected validation settings in output")
	}

	// Check LSP settings
	if lsp, ok := settings["lsp"].(map[string]interface{}); ok {
		if trace, ok := lsp["traceServer"].(string); !ok || trace != "verbose" {
			t.Errorf("expected lsp.traceServer=verbose, got %v", lsp["traceServer"])
		}
	} else {
		t.Error("expected lsp settings in output")
	}

	// Check server settings
	if server, ok := settings["server"].(map[string]interface{}); ok {
		if level, ok := server["logLevel"].(string); !ok || level != "debug" {
			t.Errorf("expected server.logLevel=debug, got %v", server["logLevel"])
		}
	} else {
		t.Error("expected server settings in output")
	}
}

func TestToLSPSettings_Nil(t *testing.T) {
	settings := ToLSPSettings(nil)

	// Should return default settings
	if format, ok := settings["format"].(map[string]interface{}); ok {
		if indent, ok := format["indent"].(int); !ok || indent != 2 {
			t.Errorf("expected default indent=2, got %v", format["indent"])
		}
	} else {
		t.Error("expected format settings in output")
	}
}

func TestFromLSPSettings(t *testing.T) {
	settings := map[string]interface{}{
		"format": map[string]interface{}{
			"indent":            float64(4),
			"uppercaseKeywords": false,
			"maxLineLength":     float64(100),
			"compact":           true,
		},
		"validation": map[string]interface{}{
			"dialect":    "mysql",
			"strictMode": true,
			"recursive":  true,
			"pattern":    "*.mysql",
			"security": map[string]interface{}{
				"maxFileSize": float64(5242880),
			},
		},
		"output": map[string]interface{}{
			"format":  "json",
			"verbose": true,
		},
		"analyze": map[string]interface{}{
			"security":    true,
			"performance": true,
			"complexity":  true,
			"all":         true,
		},
		"lsp": map[string]interface{}{
			"rateLimitRequests": float64(200),
			"rateLimitWindow":   "2s",
			"requestTimeout":    "60s",
			"maxDocumentSize":   float64(2097152),
			"maxContentLength":  float64(20971520),
			"traceServer":       "verbose",
		},
		"server": map[string]interface{}{
			"logLevel":        "debug",
			"logFile":         "/tmp/lsp.log",
			"metricsEnabled":  false,
			"shutdownTimeout": "10s",
		},
	}

	cfg, err := FromLSPSettings(settings)
	if err != nil {
		t.Fatalf("FromLSPSettings() error = %v", err)
	}

	// Verify all settings were parsed correctly
	if cfg.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", cfg.Format.Indent)
	}
	if cfg.Format.UppercaseKeywords {
		t.Error("expected uppercaseKeywords=false")
	}
	if cfg.Format.MaxLineLength != 100 {
		t.Errorf("expected maxLineLength=100, got %d", cfg.Format.MaxLineLength)
	}
	if !cfg.Format.Compact {
		t.Error("expected compact=true")
	}

	if cfg.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect=mysql, got %s", cfg.Validation.Dialect)
	}
	if !cfg.Validation.StrictMode {
		t.Error("expected strictMode=true")
	}
	if !cfg.Validation.Recursive {
		t.Error("expected recursive=true")
	}
	if cfg.Validation.Pattern != "*.mysql" {
		t.Errorf("expected pattern=*.mysql, got %s", cfg.Validation.Pattern)
	}
	if cfg.Validation.Security.MaxFileSize != 5242880 {
		t.Errorf("expected maxFileSize=5242880, got %d", cfg.Validation.Security.MaxFileSize)
	}

	if cfg.Output.Format != "json" {
		t.Errorf("expected format=json, got %s", cfg.Output.Format)
	}
	if !cfg.Output.Verbose {
		t.Error("expected verbose=true")
	}

	if !cfg.Analyze.Security || !cfg.Analyze.Performance || !cfg.Analyze.Complexity || !cfg.Analyze.All {
		t.Error("expected all analyze options=true")
	}

	if cfg.LSP.RateLimitRequests != 200 {
		t.Errorf("expected rateLimitRequests=200, got %d", cfg.LSP.RateLimitRequests)
	}
	if cfg.LSP.RateLimitWindow != 2*time.Second {
		t.Errorf("expected rateLimitWindow=2s, got %v", cfg.LSP.RateLimitWindow)
	}
	if cfg.LSP.RequestTimeout != 60*time.Second {
		t.Errorf("expected requestTimeout=60s, got %v", cfg.LSP.RequestTimeout)
	}
	if cfg.LSP.MaxDocumentSize != 2097152 {
		t.Errorf("expected maxDocumentSize=2097152, got %d", cfg.LSP.MaxDocumentSize)
	}
	if cfg.LSP.MaxContentLength != 20971520 {
		t.Errorf("expected maxContentLength=20971520, got %d", cfg.LSP.MaxContentLength)
	}
	if cfg.LSP.TraceServer != "verbose" {
		t.Errorf("expected traceServer=verbose, got %s", cfg.LSP.TraceServer)
	}

	if cfg.Server.LogLevel != "debug" {
		t.Errorf("expected logLevel=debug, got %s", cfg.Server.LogLevel)
	}
	if cfg.Server.LogFile != "/tmp/lsp.log" {
		t.Errorf("expected logFile=/tmp/lsp.log, got %s", cfg.Server.LogFile)
	}
	if cfg.Server.MetricsEnabled {
		t.Error("expected metricsEnabled=false")
	}
	if cfg.Server.ShutdownTimeout != 10*time.Second {
		t.Errorf("expected shutdownTimeout=10s, got %v", cfg.Server.ShutdownTimeout)
	}

	if cfg.Source != "lsp-settings" {
		t.Errorf("expected source=lsp-settings, got %s", cfg.Source)
	}
}

func TestMergeLSPConfig(t *testing.T) {
	base := DefaultConfig()
	base.Format.Indent = 2
	base.Validation.Dialect = "postgresql"

	changes := map[string]interface{}{
		"format": map[string]interface{}{
			"indent": float64(4),
		},
		"lsp": map[string]interface{}{
			"traceServer": "verbose",
		},
	}

	merged, err := MergeLSPConfig(base, changes)
	if err != nil {
		t.Fatalf("MergeLSPConfig() error = %v", err)
	}

	if merged.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", merged.Format.Indent)
	}
	if merged.Validation.Dialect != "postgresql" {
		t.Errorf("expected dialect=postgresql (unchanged), got %s", merged.Validation.Dialect)
	}
	if merged.LSP.TraceServer != "verbose" {
		t.Errorf("expected traceServer=verbose, got %s", merged.LSP.TraceServer)
	}
}

func TestMergeLSPConfig_NilBase(t *testing.T) {
	changes := map[string]interface{}{
		"format": map[string]interface{}{
			"indent": float64(4),
		},
	}

	merged, err := MergeLSPConfig(nil, changes)
	if err != nil {
		t.Fatalf("MergeLSPConfig() error = %v", err)
	}

	if merged.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", merged.Format.Indent)
	}
}

func TestToLSPInitializationOptions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Format.Indent = 4
	cfg.Validation.Dialect = "mysql"
	cfg.LSP.TraceServer = "verbose"

	opts := ToLSPInitializationOptions(cfg)

	// Check format settings (minimal set)
	if format, ok := opts["format"].(map[string]interface{}); ok {
		if indent, ok := format["indent"].(int); !ok || indent != 4 {
			t.Errorf("expected format.indent=4, got %v", format["indent"])
		}
	} else {
		t.Error("expected format settings in output")
	}

	// Check validation settings (minimal set)
	if validation, ok := opts["validation"].(map[string]interface{}); ok {
		if dialect, ok := validation["dialect"].(string); !ok || dialect != "mysql" {
			t.Errorf("expected validation.dialect=mysql, got %v", validation["dialect"])
		}
	} else {
		t.Error("expected validation settings in output")
	}

	// Check trace settings
	if trace, ok := opts["trace"].(map[string]interface{}); ok {
		if server, ok := trace["server"].(string); !ok || server != "verbose" {
			t.Errorf("expected trace.server=verbose, got %v", trace["server"])
		}
	} else {
		t.Error("expected trace settings in output")
	}

	// Should NOT include server-internal settings
	if _, ok := opts["server"]; ok {
		t.Error("initialization options should not include server settings")
	}
}

func TestGetLSPConfigSections(t *testing.T) {
	sections := GetLSPConfigSections()

	if len(sections) == 0 {
		t.Error("expected at least one config section")
	}

	// Check for expected sections
	expectedSections := map[string]bool{
		"gosqlx.format":     false,
		"gosqlx.validation": false,
		"gosqlx.lsp":        false,
	}

	for _, section := range sections {
		if _, ok := expectedSections[section.Section]; ok {
			expectedSections[section.Section] = true
		}

		// Verify section has required fields
		if section.Section == "" {
			t.Error("section should have a name")
		}
		if section.Properties == nil {
			t.Errorf("section %s should have properties", section.Section)
		}
		if section.DefaultValue == nil {
			t.Errorf("section %s should have default value", section.Section)
		}
	}

	// Verify all expected sections were found
	for section, found := range expectedSections {
		if !found {
			t.Errorf("expected section %s not found", section)
		}
	}
}

func TestValidateLSPValue(t *testing.T) {
	tests := []struct {
		name    string
		section string
		key     string
		value   interface{}
		wantErr bool
	}{
		{
			name:    "valid indent",
			section: "gosqlx.format",
			key:     "indent",
			value:   4,
			wantErr: false,
		},
		{
			name:    "invalid indent type",
			section: "gosqlx.format",
			key:     "indent",
			value:   "not a number",
			wantErr: true,
		},
		{
			name:    "valid dialect",
			section: "gosqlx.validation",
			key:     "dialect",
			value:   "mysql",
			wantErr: false,
		},
		{
			name:    "invalid dialect",
			section: "gosqlx.validation",
			key:     "dialect",
			value:   "invalid",
			wantErr: true,
		},
		{
			name:    "valid trace level",
			section: "gosqlx.lsp",
			key:     "traceServer",
			value:   "verbose",
			wantErr: false,
		},
		{
			name:    "invalid trace level",
			section: "gosqlx.lsp",
			key:     "traceServer",
			value:   "invalid",
			wantErr: true,
		},
		{
			name:    "valid log level",
			section: "gosqlx.server",
			key:     "logLevel",
			value:   "debug",
			wantErr: false,
		},
		{
			name:    "invalid log level",
			section: "gosqlx.server",
			key:     "logLevel",
			value:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLSPValue(tt.section, tt.key, tt.value)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLSPValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTypeConversion(t *testing.T) {
	// Test toInt
	t.Run("toInt", func(t *testing.T) {
		tests := []struct {
			input interface{}
			want  int
			ok    bool
		}{
			{int(42), 42, true},
			{int64(42), 42, true},
			{float64(42.0), 42, true},
			{float32(42.0), 42, true},
			{"not a number", 0, false},
		}

		for _, tt := range tests {
			got, ok := toInt(tt.input)
			if ok != tt.ok {
				t.Errorf("toInt(%v) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("toInt(%v) = %v, want %v", tt.input, got, tt.want)
			}
		}
	})

	// Test toInt64
	t.Run("toInt64", func(t *testing.T) {
		tests := []struct {
			input interface{}
			want  int64
			ok    bool
		}{
			{int64(42), 42, true},
			{int(42), 42, true},
			{float64(42.0), 42, true},
			{float32(42.0), 42, true},
			{"not a number", 0, false},
		}

		for _, tt := range tests {
			got, ok := toInt64(tt.input)
			if ok != tt.ok {
				t.Errorf("toInt64(%v) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("toInt64(%v) = %v, want %v", tt.input, got, tt.want)
			}
		}
	})
}
