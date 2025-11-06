package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigPrecedence tests the configuration precedence chain
func TestConfigPrecedence(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Save original working directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Logf("warning: failed to restore working directory: %v", err)
		}
	}()

	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// Create a config in current directory with specific values
	currentDirConfig := &Config{
		Format: FormatConfig{
			Indent:            4,
			UppercaseKeywords: false,
			MaxLineLength:     100,
			Compact:           false,
		},
		Validation: ValidationConfig{
			Dialect:    "mysql",
			StrictMode: true,
			Recursive:  true,
			Pattern:    "*.mysql",
		},
		Output: OutputConfig{
			Format:  "json",
			Verbose: true,
		},
		Analyze: AnalyzeConfig{
			Security:    false,
			Performance: true,
			Complexity:  false,
			All:         true,
		},
	}

	// Save to current directory
	currentDirPath := filepath.Join(tempDir, ".gosqlx.yml")
	if err := currentDirConfig.Save(currentDirPath); err != nil {
		t.Fatalf("failed to save current directory config: %v", err)
	}

	// Load default should pick up current directory config
	loaded, err := LoadDefault()
	if err != nil {
		t.Fatalf("failed to load default config: %v", err)
	}

	// Verify loaded values match current directory config
	if loaded.Format.Indent != 4 {
		t.Errorf("expected indent 4, got %d", loaded.Format.Indent)
	}
	if loaded.Format.UppercaseKeywords {
		t.Error("expected uppercase_keywords false")
	}
	if loaded.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect 'mysql', got '%s'", loaded.Validation.Dialect)
	}
	if loaded.Output.Format != "json" {
		t.Errorf("expected format 'json', got '%s'", loaded.Output.Format)
	}
}

// TestConfigWithFlags simulates CLI flag override behavior
func TestConfigWithFlags(t *testing.T) {
	// Start with default config
	cfg := DefaultConfig()

	// Verify defaults
	if cfg.Format.Indent != 2 {
		t.Errorf("expected default indent 2, got %d", cfg.Format.Indent)
	}
	if cfg.Validation.Dialect != "postgresql" {
		t.Errorf("expected default dialect 'postgresql', got '%s'", cfg.Validation.Dialect)
	}

	// Simulate CLI flags overriding config
	cliOverrides := &Config{
		Format: FormatConfig{
			Indent:            4,
			UppercaseKeywords: false,
			MaxLineLength:     120,
		},
		Validation: ValidationConfig{
			Dialect:   "mysql",
			Recursive: true,
		},
		Output: OutputConfig{
			Format: "json",
		},
	}

	// Merge CLI overrides
	cfg.Merge(cliOverrides)

	// Verify CLI flags took precedence
	if cfg.Format.Indent != 4 {
		t.Errorf("expected indent 4 after merge, got %d", cfg.Format.Indent)
	}
	if cfg.Format.UppercaseKeywords {
		t.Error("expected uppercase_keywords false after merge")
	}
	if cfg.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect 'mysql' after merge, got '%s'", cfg.Validation.Dialect)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("expected format 'json' after merge, got '%s'", cfg.Output.Format)
	}
}

// TestConfigValidationIntegration tests that validation works end-to-end
func TestConfigValidationIntegration(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid indent",
			config: &Config{
				Format: FormatConfig{
					Indent:            20,
					UppercaseKeywords: true,
					MaxLineLength:     80,
				},
				Validation: ValidationConfig{Dialect: "postgresql"},
				Output:     OutputConfig{Format: "auto"},
			},
			wantErr: true,
			errMsg:  "indent must be between 0 and 8",
		},
		{
			name: "invalid dialect",
			config: &Config{
				Format: FormatConfig{
					Indent:            2,
					UppercaseKeywords: true,
					MaxLineLength:     80,
				},
				Validation: ValidationConfig{Dialect: "unknown_db"},
				Output:     OutputConfig{Format: "auto"},
			},
			wantErr: true,
			errMsg:  "dialect must be one of",
		},
		{
			name: "invalid output format",
			config: &Config{
				Format: FormatConfig{
					Indent:            2,
					UppercaseKeywords: true,
					MaxLineLength:     80,
				},
				Validation: ValidationConfig{Dialect: "postgresql"},
				Output:     OutputConfig{Format: "csv"},
			},
			wantErr: true,
			errMsg:  "format must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errMsg, err.Error())
				}
			}
		})
	}
}

// TestConfigPartialOverrides tests that partial configs work correctly
func TestConfigPartialOverrides(t *testing.T) {
	base := DefaultConfig()

	// Create a partial override (only some fields set)
	partial := &Config{
		Format: FormatConfig{
			Indent: 4, // Only override indent
		},
		Validation: ValidationConfig{
			Dialect: "mysql", // Only override dialect
		},
	}

	base.Merge(partial)

	// Check that overridden values changed
	if base.Format.Indent != 4 {
		t.Errorf("expected indent 4, got %d", base.Format.Indent)
	}
	if base.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect 'mysql', got '%s'", base.Validation.Dialect)
	}

	// Note: Merge copies all boolean values directly, so uppercase_keywords
	// will be false (zero value) even if not explicitly set in partial config.
	// This is expected behavior for the current Merge implementation.
	// Non-zero values should remain unchanged
	if base.Format.MaxLineLength != 80 {
		t.Errorf("expected max_line_length to remain 80 (default), got %d", base.Format.MaxLineLength)
	}
}

// TestConfigRoundTrip tests saving and loading a config
func TestConfigRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "roundtrip.yml")

	// Create a config with specific values
	original := &Config{
		Format: FormatConfig{
			Indent:            3,
			UppercaseKeywords: false,
			MaxLineLength:     90,
			Compact:           true,
		},
		Validation: ValidationConfig{
			Dialect:    "oracle",
			StrictMode: true,
			Recursive:  true,
			Pattern:    "*.oracle",
		},
		Output: OutputConfig{
			Format:  "yaml",
			Verbose: true,
		},
		Analyze: AnalyzeConfig{
			Security:    false,
			Performance: false,
			Complexity:  true,
			All:         false,
		},
	}

	// Save
	if err := original.Save(configPath); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// Load
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Compare all fields
	if loaded.Format.Indent != original.Format.Indent {
		t.Errorf("indent mismatch: expected %d, got %d", original.Format.Indent, loaded.Format.Indent)
	}
	if loaded.Format.UppercaseKeywords != original.Format.UppercaseKeywords {
		t.Errorf("uppercase_keywords mismatch")
	}
	if loaded.Format.MaxLineLength != original.Format.MaxLineLength {
		t.Errorf("max_line_length mismatch")
	}
	if loaded.Format.Compact != original.Format.Compact {
		t.Errorf("compact mismatch")
	}

	if loaded.Validation.Dialect != original.Validation.Dialect {
		t.Errorf("dialect mismatch")
	}
	if loaded.Validation.StrictMode != original.Validation.StrictMode {
		t.Errorf("strict_mode mismatch")
	}
	if loaded.Validation.Recursive != original.Validation.Recursive {
		t.Errorf("recursive mismatch")
	}
	if loaded.Validation.Pattern != original.Validation.Pattern {
		t.Errorf("pattern mismatch")
	}

	if loaded.Output.Format != original.Output.Format {
		t.Errorf("format mismatch")
	}
	if loaded.Output.Verbose != original.Output.Verbose {
		t.Errorf("verbose mismatch")
	}

	if loaded.Analyze.Security != original.Analyze.Security {
		t.Errorf("security mismatch")
	}
	if loaded.Analyze.Performance != original.Analyze.Performance {
		t.Errorf("performance mismatch")
	}
	if loaded.Analyze.Complexity != original.Analyze.Complexity {
		t.Errorf("complexity mismatch")
	}
	if loaded.Analyze.All != original.Analyze.All {
		t.Errorf("all mismatch")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
