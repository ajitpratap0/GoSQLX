package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// LoadFromLSPInitOptions loads configuration from LSP initialization options.
// The opts parameter should be the initializationOptions field from the LSP
// initialize request, typically sent by the VSCode extension.
//
// Example initializationOptions structure:
//
//	{
//	  "format": {
//	    "indent": 2,
//	    "uppercaseKeywords": true
//	  },
//	  "validation": {
//	    "dialect": "postgresql"
//	  }
//	}
func LoadFromLSPInitOptions(opts interface{}) (*Config, error) {
	config := DefaultConfig()

	if opts == nil {
		config.Source = "lsp"
		return config, nil
	}

	// Convert opts to JSON and back to get proper structure
	data, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal LSP init options: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse LSP init options: %w", err)
	}

	config.Source = "lsp"
	config.ApplyDefaults()

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid LSP config: %w", err)
	}

	return config, nil
}

// ToLSPSettings converts a Config to VSCode settings format.
// This returns a map suitable for use in LSP configuration responses
// or for serializing to VSCode settings.json.
//
// The returned map uses camelCase keys to match VSCode conventions.
func ToLSPSettings(c *Config) map[string]interface{} {
	if c == nil {
		c = DefaultConfig()
	}

	return map[string]interface{}{
		"format": map[string]interface{}{
			"indent":            c.Format.Indent,
			"uppercaseKeywords": BoolValue(c.Format.UppercaseKeywords),
			"maxLineLength":     c.Format.MaxLineLength,
			"compact":           BoolValue(c.Format.Compact),
		},
		"validation": map[string]interface{}{
			"dialect":    c.Validation.Dialect,
			"strictMode": BoolValue(c.Validation.StrictMode),
			"recursive":  BoolValue(c.Validation.Recursive),
			"pattern":    c.Validation.Pattern,
			"security": map[string]interface{}{
				"maxFileSize": c.Validation.Security.MaxFileSize,
			},
		},
		"output": map[string]interface{}{
			"format":  c.Output.Format,
			"verbose": BoolValue(c.Output.Verbose),
		},
		"analyze": map[string]interface{}{
			"security":    BoolValue(c.Analyze.Security),
			"performance": BoolValue(c.Analyze.Performance),
			"complexity":  BoolValue(c.Analyze.Complexity),
			"all":         BoolValue(c.Analyze.All),
		},
		"lsp": map[string]interface{}{
			"rateLimitRequests": c.LSP.RateLimitRequests,
			"rateLimitWindow":   c.LSP.RateLimitWindow.String(),
			"requestTimeout":    c.LSP.RequestTimeout.String(),
			"maxDocumentSize":   c.LSP.MaxDocumentSize,
			"maxContentLength":  c.LSP.MaxContentLength,
			"traceServer":       c.LSP.TraceServer,
		},
		"server": map[string]interface{}{
			"logLevel":        c.Server.LogLevel,
			"logFile":         c.Server.LogFile,
			"metricsEnabled":  BoolValue(c.Server.MetricsEnabled),
			"shutdownTimeout": c.Server.ShutdownTimeout.String(),
		},
	}
}

// FromLSPSettings creates a Config from VSCode settings format.
// This is the inverse of ToLSPSettings and can parse settings from
// VSCode's settings.json or workspace configuration.
func FromLSPSettings(settings map[string]interface{}) (*Config, error) {
	config := DefaultConfig()

	if format, ok := settings["format"].(map[string]interface{}); ok {
		if v, ok := format["indent"].(float64); ok {
			config.Format.Indent = int(v)
		}
		if v, ok := format["uppercaseKeywords"].(bool); ok {
			config.Format.UppercaseKeywords = Bool(v)
		}
		if v, ok := format["maxLineLength"].(float64); ok {
			config.Format.MaxLineLength = int(v)
		}
		if v, ok := format["compact"].(bool); ok {
			config.Format.Compact = Bool(v)
		}
	}

	if validation, ok := settings["validation"].(map[string]interface{}); ok {
		if v, ok := validation["dialect"].(string); ok {
			config.Validation.Dialect = v
		}
		if v, ok := validation["strictMode"].(bool); ok {
			config.Validation.StrictMode = Bool(v)
		}
		if v, ok := validation["recursive"].(bool); ok {
			config.Validation.Recursive = Bool(v)
		}
		if v, ok := validation["pattern"].(string); ok {
			config.Validation.Pattern = v
		}
		if security, ok := validation["security"].(map[string]interface{}); ok {
			if v, ok := security["maxFileSize"].(float64); ok {
				config.Validation.Security.MaxFileSize = int64(v)
			}
		}
	}

	if output, ok := settings["output"].(map[string]interface{}); ok {
		if v, ok := output["format"].(string); ok {
			config.Output.Format = v
		}
		if v, ok := output["verbose"].(bool); ok {
			config.Output.Verbose = Bool(v)
		}
	}

	if analyze, ok := settings["analyze"].(map[string]interface{}); ok {
		if v, ok := analyze["security"].(bool); ok {
			config.Analyze.Security = Bool(v)
		}
		if v, ok := analyze["performance"].(bool); ok {
			config.Analyze.Performance = Bool(v)
		}
		if v, ok := analyze["complexity"].(bool); ok {
			config.Analyze.Complexity = Bool(v)
		}
		if v, ok := analyze["all"].(bool); ok {
			config.Analyze.All = Bool(v)
		}
	}

	if lsp, ok := settings["lsp"].(map[string]interface{}); ok {
		if v, ok := lsp["rateLimitRequests"].(float64); ok {
			config.LSP.RateLimitRequests = int(v)
		}
		if v, ok := lsp["rateLimitWindow"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				config.LSP.RateLimitWindow = d
			}
		}
		if v, ok := lsp["requestTimeout"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				config.LSP.RequestTimeout = d
			}
		}
		if v, ok := lsp["maxDocumentSize"].(float64); ok {
			config.LSP.MaxDocumentSize = int(v)
		}
		if v, ok := lsp["maxContentLength"].(float64); ok {
			config.LSP.MaxContentLength = int(v)
		}
		if v, ok := lsp["traceServer"].(string); ok {
			config.LSP.TraceServer = v
		}
	}

	if server, ok := settings["server"].(map[string]interface{}); ok {
		if v, ok := server["logLevel"].(string); ok {
			config.Server.LogLevel = v
		}
		if v, ok := server["logFile"].(string); ok {
			config.Server.LogFile = v
		}
		if v, ok := server["metricsEnabled"].(bool); ok {
			config.Server.MetricsEnabled = Bool(v)
		}
		if v, ok := server["shutdownTimeout"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				config.Server.ShutdownTimeout = d
			}
		}
	}

	config.Source = "lsp-settings"
	config.ApplyDefaults()

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid LSP settings config: %w", err)
	}

	return config, nil
}

// MergeLSPConfig merges LSP-specific configuration changes into an existing config.
// This is useful for handling workspace configuration changes in the LSP server.
// Only non-nil/non-zero values from changes are applied.
func MergeLSPConfig(base *Config, changes interface{}) (*Config, error) {
	if base == nil {
		base = DefaultConfig()
	}

	result := base.Clone()

	// Handle different input types
	switch v := changes.(type) {
	case map[string]interface{}:
		changeConfig, err := FromLSPSettings(v)
		if err != nil {
			return nil, err
		}
		mergeInto(result, changeConfig)

	case *Config:
		if v != nil {
			mergeInto(result, v)
		}

	default:
		// Try to convert via JSON
		data, err := json.Marshal(changes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse LSP config changes: %w", err)
		}

		var changeConfig Config
		if err := json.Unmarshal(data, &changeConfig); err != nil {
			return nil, fmt.Errorf("unable to parse LSP config changes: %w", err)
		}
		mergeInto(result, &changeConfig)
	}

	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("merged LSP config validation failed: %w", err)
	}

	return result, nil
}

// ToLSPInitializationOptions creates a minimal initialization options object
// suitable for sending to an LSP server. This includes only the most commonly
// needed settings and excludes server-internal configuration.
func ToLSPInitializationOptions(c *Config) map[string]interface{} {
	if c == nil {
		c = DefaultConfig()
	}

	return map[string]interface{}{
		"format": map[string]interface{}{
			"indent":            c.Format.Indent,
			"uppercaseKeywords": c.Format.UppercaseKeywords,
			"maxLineLength":     c.Format.MaxLineLength,
		},
		"validation": map[string]interface{}{
			"dialect":    c.Validation.Dialect,
			"strictMode": c.Validation.StrictMode,
		},
		"trace": map[string]interface{}{
			"server": c.LSP.TraceServer,
		},
	}
}

// LSPConfigSection represents a section of LSP configuration that can be
// registered with the VSCode extension for dynamic configuration updates.
type LSPConfigSection struct {
	Section      string                 `json:"section"`
	Properties   map[string]interface{} `json:"properties"`
	Description  string                 `json:"description,omitempty"`
	DefaultValue interface{}            `json:"defaultValue,omitempty"`
}

// GetLSPConfigSections returns all configuration sections for registration
// with the LSP workspace/configuration capability. This allows the VSCode
// extension to provide configuration UI and validation.
func GetLSPConfigSections() []LSPConfigSection {
	defaults := DefaultConfig()

	return []LSPConfigSection{
		{
			Section:      "gosqlx.format",
			Description:  "SQL formatting options",
			DefaultValue: ToLSPSettings(defaults)["format"],
			Properties: map[string]interface{}{
				"indent":            "Number of spaces for indentation",
				"uppercaseKeywords": "Convert SQL keywords to uppercase",
				"maxLineLength":     "Maximum line length before wrapping",
				"compact":           "Use compact formatting",
			},
		},
		{
			Section:      "gosqlx.validation",
			Description:  "SQL validation options",
			DefaultValue: ToLSPSettings(defaults)["validation"],
			Properties: map[string]interface{}{
				"dialect":    "SQL dialect (postgresql, mysql, sqlserver, oracle, sqlite)",
				"strictMode": "Enable strict validation mode",
			},
		},
		{
			Section:      "gosqlx.lsp",
			Description:  "LSP server configuration",
			DefaultValue: ToLSPSettings(defaults)["lsp"],
			Properties: map[string]interface{}{
				"traceServer": "LSP trace level (off, messages, verbose)",
			},
		},
	}
}

// ValidateLSPValue validates a single configuration value for LSP.
// This is useful for providing real-time validation in the VSCode extension.
func ValidateLSPValue(section, key string, value interface{}) error {
	// Create a temporary config with the value
	config := DefaultConfig()

	switch section {
	case "gosqlx.format":
		switch key {
		case "indent":
			if v, ok := toInt(value); ok {
				config.Format.Indent = v
			} else {
				return fmt.Errorf("indent must be an integer")
			}
		case "maxLineLength":
			if v, ok := toInt(value); ok {
				config.Format.MaxLineLength = v
			} else {
				return fmt.Errorf("maxLineLength must be an integer")
			}
		}

	case "gosqlx.validation":
		switch key {
		case "dialect":
			if v, ok := value.(string); ok {
				config.Validation.Dialect = v
			} else {
				return fmt.Errorf("dialect must be a string")
			}
		case "security.maxFileSize":
			if v, ok := toInt64(value); ok {
				config.Validation.Security.MaxFileSize = v
			} else {
				return fmt.Errorf("security.maxFileSize must be an integer")
			}
		}

	case "gosqlx.lsp":
		switch key {
		case "traceServer":
			if v, ok := value.(string); ok {
				config.LSP.TraceServer = v
			} else {
				return fmt.Errorf("traceServer must be a string")
			}
		case "rateLimitRequests":
			if v, ok := toInt(value); ok {
				config.LSP.RateLimitRequests = v
			} else {
				return fmt.Errorf("rateLimitRequests must be an integer")
			}
		}

	case "gosqlx.server":
		if key == "logLevel" {
			if v, ok := value.(string); ok {
				config.Server.LogLevel = v
			} else {
				return fmt.Errorf("logLevel must be a string")
			}
		}
	}

	// Validate the entire config
	return config.Validate()
}

// Helper functions for type conversion

func toInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	case float32:
		return int(val), true
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Int || rv.Kind() == reflect.Int64 {
			return int(rv.Int()), true
		}
		if rv.Kind() == reflect.Float64 || rv.Kind() == reflect.Float32 {
			return int(rv.Float()), true
		}
		return 0, false
	}
}

func toInt64(v interface{}) (int64, bool) {
	switch val := v.(type) {
	case int64:
		return val, true
	case int:
		return int64(val), true
	case float64:
		return int64(val), true
	case float32:
		return int64(val), true
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Int || rv.Kind() == reflect.Int64 {
			return rv.Int(), true
		}
		if rv.Kind() == reflect.Float64 || rv.Kind() == reflect.Float32 {
			return int64(rv.Float()), true
		}
		return 0, false
	}
}
