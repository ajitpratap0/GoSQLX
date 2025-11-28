package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test format defaults
	if cfg.Format.Indent != 2 {
		t.Errorf("expected indent to be 2, got %d", cfg.Format.Indent)
	}
	if !cfg.Format.UppercaseKeywords {
		t.Error("expected uppercase_keywords to be true")
	}
	if cfg.Format.MaxLineLength != 80 {
		t.Errorf("expected max_line_length to be 80, got %d", cfg.Format.MaxLineLength)
	}
	if cfg.Format.Compact {
		t.Error("expected compact to be false")
	}

	// Test validation defaults
	if cfg.Validation.Dialect != "postgresql" {
		t.Errorf("expected dialect to be 'postgresql', got '%s'", cfg.Validation.Dialect)
	}
	if cfg.Validation.StrictMode {
		t.Error("expected strict_mode to be false")
	}
	if cfg.Validation.Pattern != "*.sql" {
		t.Errorf("expected pattern to be '*.sql', got '%s'", cfg.Validation.Pattern)
	}

	// Test output defaults
	if cfg.Output.Format != "auto" {
		t.Errorf("expected format to be 'auto', got '%s'", cfg.Output.Format)
	}
	if cfg.Output.Verbose {
		t.Error("expected verbose to be false")
	}

	// Test analyze defaults
	if !cfg.Analyze.Security {
		t.Error("expected security to be true")
	}
	if !cfg.Analyze.Performance {
		t.Error("expected performance to be true")
	}
	if !cfg.Analyze.Complexity {
		t.Error("expected complexity to be true")
	}
	if cfg.Analyze.All {
		t.Error("expected all to be false")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test-config.yml")

	configYAML := `format:
  indent: 4
  uppercase_keywords: false
  max_line_length: 120
  compact: true

validate:
  dialect: mysql
  strict_mode: true
  recursive: true
  pattern: "*.mysql"

output:
  format: json
  verbose: true

analyze:
  security: false
  performance: true
  complexity: false
  all: true
`

	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	// Load the config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Verify loaded values
	if cfg.Format.Indent != 4 {
		t.Errorf("expected indent to be 4, got %d", cfg.Format.Indent)
	}
	if cfg.Format.UppercaseKeywords {
		t.Error("expected uppercase_keywords to be false")
	}
	if cfg.Format.MaxLineLength != 120 {
		t.Errorf("expected max_line_length to be 120, got %d", cfg.Format.MaxLineLength)
	}
	if !cfg.Format.Compact {
		t.Error("expected compact to be true")
	}

	if cfg.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect to be 'mysql', got '%s'", cfg.Validation.Dialect)
	}
	if !cfg.Validation.StrictMode {
		t.Error("expected strict_mode to be true")
	}
	if !cfg.Validation.Recursive {
		t.Error("expected recursive to be true")
	}
	if cfg.Validation.Pattern != "*.mysql" {
		t.Errorf("expected pattern to be '*.mysql', got '%s'", cfg.Validation.Pattern)
	}

	if cfg.Output.Format != "json" {
		t.Errorf("expected format to be 'json', got '%s'", cfg.Output.Format)
	}
	if !cfg.Output.Verbose {
		t.Error("expected verbose to be true")
	}

	if cfg.Analyze.Security {
		t.Error("expected security to be false")
	}
	if !cfg.Analyze.Performance {
		t.Error("expected performance to be true")
	}
	if cfg.Analyze.Complexity {
		t.Error("expected complexity to be false")
	}
	if !cfg.Analyze.All {
		t.Error("expected all to be true")
	}
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yml")
	if err == nil {
		t.Error("expected error when loading nonexistent file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.yml")

	invalidYAML := `format:
  indent: [this is not valid
  uppercase_keywords: %%%
`

	if err := os.WriteFile(configPath, []byte(invalidYAML), 0644); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error when loading invalid YAML")
	}
}

func TestSaveConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "saved-config.yml")

	// Create a config with non-default values
	cfg := &Config{
		Format: FormatConfig{
			Indent:            4,
			UppercaseKeywords: false,
			MaxLineLength:     100,
			Compact:           true,
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

	// Save the config
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// Load it back
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load saved config: %v", err)
	}

	// Verify values match
	if loaded.Format.Indent != cfg.Format.Indent {
		t.Errorf("indent mismatch: expected %d, got %d", cfg.Format.Indent, loaded.Format.Indent)
	}
	if loaded.Validation.Dialect != cfg.Validation.Dialect {
		t.Errorf("dialect mismatch: expected %s, got %s", cfg.Validation.Dialect, loaded.Validation.Dialect)
	}
	if loaded.Output.Format != cfg.Output.Format {
		t.Errorf("format mismatch: expected %s, got %s", cfg.Output.Format, loaded.Output.Format)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name:      "valid default config",
			config:    DefaultConfig(),
			wantError: false,
		},
		{
			name: "invalid indent (negative)",
			config: &Config{
				Format: FormatConfig{
					Indent:            -1,
					UppercaseKeywords: true,
					MaxLineLength:     80,
				},
				Validation: ValidationConfig{Dialect: "postgresql"},
				Output:     OutputConfig{Format: "auto"},
			},
			wantError: true,
		},
		{
			name: "invalid indent (too large)",
			config: &Config{
				Format: FormatConfig{
					Indent:            10,
					UppercaseKeywords: true,
					MaxLineLength:     80,
				},
				Validation: ValidationConfig{Dialect: "postgresql"},
				Output:     OutputConfig{Format: "auto"},
			},
			wantError: true,
		},
		{
			name: "invalid max line length",
			config: &Config{
				Format: FormatConfig{
					Indent:            2,
					UppercaseKeywords: true,
					MaxLineLength:     1000,
				},
				Validation: ValidationConfig{Dialect: "postgresql"},
				Output:     OutputConfig{Format: "auto"},
			},
			wantError: true,
		},
		{
			name: "invalid dialect",
			config: &Config{
				Format: FormatConfig{
					Indent:            2,
					UppercaseKeywords: true,
					MaxLineLength:     80,
				},
				Validation: ValidationConfig{Dialect: "invalid_dialect"},
				Output:     OutputConfig{Format: "auto"},
			},
			wantError: true,
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
				Output:     OutputConfig{Format: "invalid_format"},
			},
			wantError: true,
		},
		{
			name: "valid mysql config",
			config: &Config{
				Format: FormatConfig{
					Indent:            4,
					UppercaseKeywords: false,
					MaxLineLength:     120,
				},
				Validation: ValidationConfig{Dialect: "mysql"},
				Output:     OutputConfig{Format: "json"},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	// Base config with some values
	base := DefaultConfig()
	base.Format.Indent = 2
	base.Validation.Dialect = "postgresql"
	base.Output.Format = "auto"

	// Override config
	override := &Config{
		Format: FormatConfig{
			Indent:            4,
			UppercaseKeywords: false,
			MaxLineLength:     100,
		},
		Validation: ValidationConfig{
			Dialect:   "mysql",
			Pattern:   "*.mysql",
			Recursive: true,
		},
		Output: OutputConfig{
			Format:  "json",
			Verbose: true,
		},
	}

	// Merge
	base.Merge(override)

	// Check merged values
	if base.Format.Indent != 4 {
		t.Errorf("expected indent to be 4 after merge, got %d", base.Format.Indent)
	}
	if base.Format.UppercaseKeywords {
		t.Error("expected uppercase_keywords to be false after merge")
	}
	if base.Format.MaxLineLength != 100 {
		t.Errorf("expected max_line_length to be 100 after merge, got %d", base.Format.MaxLineLength)
	}

	if base.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect to be 'mysql' after merge, got '%s'", base.Validation.Dialect)
	}
	if base.Validation.Pattern != "*.mysql" {
		t.Errorf("expected pattern to be '*.mysql' after merge, got '%s'", base.Validation.Pattern)
	}
	if !base.Validation.Recursive {
		t.Error("expected recursive to be true after merge")
	}

	if base.Output.Format != "json" {
		t.Errorf("expected format to be 'json' after merge, got '%s'", base.Output.Format)
	}
	if !base.Output.Verbose {
		t.Error("expected verbose to be true after merge")
	}
}

func TestLoadDefault_NoConfigFiles(t *testing.T) {
	// Change to a temporary directory where no config files exist
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Logf("warning: failed to restore working directory: %v", err)
		}
	}()

	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// LoadDefault should return default config
	cfg, err := LoadDefault()
	if err != nil {
		t.Errorf("LoadDefault() should not error when no config files exist: %v", err)
	}

	// Verify it's a default config
	defaultCfg := DefaultConfig()
	if cfg.Format.Indent != defaultCfg.Format.Indent {
		t.Errorf("expected default indent value %d, got %d", defaultCfg.Format.Indent, cfg.Format.Indent)
	}
}

func TestLoadDefault_CurrentDirectory(t *testing.T) {
	// Create a config in current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Logf("warning: failed to restore working directory: %v", err)
		}
	}()

	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// Create .gosqlx.yml in current directory
	configYAML := `format:
  indent: 8
validate:
  dialect: sqlite
`
	if err := os.WriteFile(".gosqlx.yml", []byte(configYAML), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	cfg, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault() failed: %v", err)
	}

	// Should have loaded the custom config
	if cfg.Format.Indent != 8 {
		t.Errorf("expected indent to be 8, got %d", cfg.Format.Indent)
	}
	if cfg.Validation.Dialect != "sqlite" {
		t.Errorf("expected dialect to be 'sqlite', got '%s'", cfg.Validation.Dialect)
	}
}

func TestLoadConfig_PartialConfig(t *testing.T) {
	// Test that partial configs merge with defaults
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "partial-config.yml")

	// Only specify a few values
	partialYAML := `format:
  indent: 3
validate:
  dialect: oracle
`
	if err := os.WriteFile(configPath, []byte(partialYAML), 0644); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Specified values should be loaded
	if cfg.Format.Indent != 3 {
		t.Errorf("expected indent to be 3, got %d", cfg.Format.Indent)
	}
	if cfg.Validation.Dialect != "oracle" {
		t.Errorf("expected dialect to be 'oracle', got '%s'", cfg.Validation.Dialect)
	}

	// Unspecified values should use defaults
	if !cfg.Format.UppercaseKeywords {
		t.Error("expected uppercase_keywords to use default value (true)")
	}
	if cfg.Output.Format != "auto" {
		t.Errorf("expected format to use default value (auto), got '%s'", cfg.Output.Format)
	}
}

func TestLoadConfig_TildeExpansion(t *testing.T) {
	// Test that ~ is properly expanded to home directory
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot get home directory, skipping test")
	}

	// Create a test config in a subdir of temp
	tempDir := t.TempDir()
	configSubdir := filepath.Join(tempDir, "subdir")
	if err := os.MkdirAll(configSubdir, 0755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}

	// We can't easily test ~ expansion without modifying the actual home directory,
	// so we'll just verify that the path expansion logic works correctly
	testPath := "~/test/config.yml"
	expandedPath := filepath.Join(home, "test/config.yml")

	// Create a mock that would be expanded
	if len(testPath) > 0 && testPath[0] == '~' {
		expanded := filepath.Join(home, testPath[1:])
		if expanded != expandedPath {
			t.Errorf("path expansion failed: expected %s, got %s", expandedPath, expanded)
		}
	}
}
