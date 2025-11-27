package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromFile_YAML(t *testing.T) {
	// Create temporary YAML config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write minimal YAML with just the values we want to override
	yamlContent := `
format:
  indent: 4
validation:
  dialect: mysql
server:
  log_level: debug
`

	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Load and verify
	loaded, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loaded.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", loaded.Format.Indent)
	}
	if loaded.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect=mysql, got %s", loaded.Validation.Dialect)
	}
	if loaded.Server.LogLevel != "debug" {
		t.Errorf("expected log_level=debug, got %s", loaded.Server.LogLevel)
	}
	if loaded.Source != configPath {
		t.Errorf("expected source=%s, got %s", configPath, loaded.Source)
	}
}

func TestLoadFromFile_JSON(t *testing.T) {
	// Create temporary JSON config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// Write minimal JSON with just the values we want to override
	jsonContent := `{
  "format": {
    "indent": 4
  },
  "validation": {
    "dialect": "mysql"
  }
}`

	if err := os.WriteFile(configPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Load and verify
	loaded, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loaded.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", loaded.Format.Indent)
	}
	if loaded.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect=mysql, got %s", loaded.Validation.Dialect)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFromFile_InvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.txt")

	if err := os.WriteFile(configPath, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	invalidYAML := "invalid: yaml: content: ["
	if err := os.WriteFile(configPath, []byte(invalidYAML), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	invalidJSON := `{"invalid": json`
	if err := os.WriteFile(configPath, []byte(invalidJSON), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadFromFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create first config (will be found)
	config1Path := filepath.Join(tmpDir, "config1.yaml")
	yaml1 := "format:\n  indent: 4\n"
	os.WriteFile(config1Path, []byte(yaml1), 0644)

	// Create second config (won't be checked)
	config2Path := filepath.Join(tmpDir, "config2.yaml")
	yaml2 := "format:\n  indent: 8\n"
	os.WriteFile(config2Path, []byte(yaml2), 0644)

	// Search paths with nonexistent file first
	searchPaths := []string{
		filepath.Join(tmpDir, "nonexistent.yaml"),
		config1Path,
		config2Path,
	}

	loaded, err := LoadFromFiles(searchPaths)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Should load first found config (config1)
	if loaded.Format.Indent != 4 {
		t.Errorf("expected indent=4 from first config, got %d", loaded.Format.Indent)
	}
	if loaded.Source != config1Path {
		t.Errorf("expected source=%s, got %s", config1Path, loaded.Source)
	}
}

func TestLoadFromFiles_NoneFound(t *testing.T) {
	searchPaths := []string{
		"/nonexistent1.yaml",
		"/nonexistent2.yaml",
	}

	_, err := LoadFromFiles(searchPaths)
	if err == nil {
		t.Error("expected error when no config files found")
	}
}

func TestLoadFromEnvironment(t *testing.T) {
	// Set environment variables
	os.Setenv("GOSQLX_FORMAT_INDENT", "4")
	os.Setenv("GOSQLX_VALIDATION_DIALECT", "mysql")
	os.Setenv("GOSQLX_VALIDATION_STRICT_MODE", "true")
	os.Setenv("GOSQLX_LSP_RATE_LIMIT_REQUESTS", "200")
	os.Setenv("GOSQLX_LSP_REQUEST_TIMEOUT", "60s")
	os.Setenv("GOSQLX_SERVER_LOG_LEVEL", "debug")
	os.Setenv("GOSQLX_OUTPUT_FORMAT", "json")

	defer func() {
		os.Unsetenv("GOSQLX_FORMAT_INDENT")
		os.Unsetenv("GOSQLX_VALIDATION_DIALECT")
		os.Unsetenv("GOSQLX_VALIDATION_STRICT_MODE")
		os.Unsetenv("GOSQLX_LSP_RATE_LIMIT_REQUESTS")
		os.Unsetenv("GOSQLX_LSP_REQUEST_TIMEOUT")
		os.Unsetenv("GOSQLX_SERVER_LOG_LEVEL")
		os.Unsetenv("GOSQLX_OUTPUT_FORMAT")
	}()

	envCfg, err := LoadFromEnvironment("GOSQLX")
	if err != nil {
		t.Fatalf("failed to load from environment: %v", err)
	}

	// Merge with defaults for a complete config
	cfg := Merge(DefaultConfig(), envCfg)

	if cfg.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", cfg.Format.Indent)
	}
	if cfg.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect=mysql, got %s", cfg.Validation.Dialect)
	}
	if !cfg.Validation.StrictMode {
		t.Error("expected strict_mode=true")
	}
	if cfg.LSP.RateLimitRequests != 200 {
		t.Errorf("expected rate_limit_requests=200, got %d", cfg.LSP.RateLimitRequests)
	}
	if cfg.LSP.RequestTimeout != 60*time.Second {
		t.Errorf("expected request_timeout=60s, got %v", cfg.LSP.RequestTimeout)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("expected log_level=debug, got %s", cfg.Server.LogLevel)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("expected format=json, got %s", cfg.Output.Format)
	}
	if envCfg.Source != "environment" {
		t.Errorf("expected source=environment, got %s", envCfg.Source)
	}
}

func TestLoadFromEnvironment_CustomPrefix(t *testing.T) {
	os.Setenv("CUSTOM_FORMAT_INDENT", "8")
	defer os.Unsetenv("CUSTOM_FORMAT_INDENT")

	envCfg, err := LoadFromEnvironment("CUSTOM")
	if err != nil {
		t.Fatalf("failed to load from environment: %v", err)
	}

	// Merge with defaults
	cfg := Merge(DefaultConfig(), envCfg)

	if cfg.Format.Indent != 8 {
		t.Errorf("expected indent=8, got %d", cfg.Format.Indent)
	}
}

func TestMerge(t *testing.T) {
	base := DefaultConfig()
	base.Format.Indent = 2
	base.Validation.Dialect = "postgresql"
	base.Server.LogLevel = "info"

	override1 := &Config{
		Format: FormatConfig{
			Indent: 4,
		},
	}

	override2 := &Config{
		Validation: ValidationConfig{
			Dialect: "mysql",
		},
		Server: ServerConfig{
			LogLevel: "debug",
		},
	}

	merged := Merge(base, override1, override2)

	if merged.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", merged.Format.Indent)
	}
	if merged.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect=mysql, got %s", merged.Validation.Dialect)
	}
	if merged.Server.LogLevel != "debug" {
		t.Errorf("expected log_level=debug, got %s", merged.Server.LogLevel)
	}
}

func TestMerge_NoConfigs(t *testing.T) {
	merged := Merge()

	// Should return default config
	if merged.Format.Indent != 2 {
		t.Errorf("expected default indent=2, got %d", merged.Format.Indent)
	}
}

func TestMerge_WithNilConfig(t *testing.T) {
	base := DefaultConfig()
	base.Format.Indent = 4

	merged := Merge(base, nil)

	if merged.Format.Indent != 4 {
		t.Errorf("expected indent=4, got %d", merged.Format.Indent)
	}
}

func TestLoadWithDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write minimal YAML
	yamlContent := "format:\n  indent: 4\n"
	os.WriteFile(configPath, []byte(yamlContent), 0644)

	// Set environment variable
	os.Setenv("GOSQLX_VALIDATION_DIALECT", "mysql")
	defer os.Unsetenv("GOSQLX_VALIDATION_DIALECT")

	// Load with both file and environment
	loaded, err := LoadWithDefaults(configPath, true)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// File setting
	if loaded.Format.Indent != 4 {
		t.Errorf("expected indent=4 from file, got %d", loaded.Format.Indent)
	}

	// Environment override
	if loaded.Validation.Dialect != "mysql" {
		t.Errorf("expected dialect=mysql from env, got %s", loaded.Validation.Dialect)
	}
}

func TestLoadWithDefaults_NoFile(t *testing.T) {
	// Load without file, only defaults
	loaded, err := LoadWithDefaults("", false)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Should have default values
	if loaded.Format.Indent != 2 {
		t.Errorf("expected default indent=2, got %d", loaded.Format.Indent)
	}
}

func TestLoadWithDefaults_InvalidFile(t *testing.T) {
	_, err := LoadWithDefaults("/nonexistent/config.yaml", false)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestGetDefaultConfigPaths(t *testing.T) {
	paths := GetDefaultConfigPaths()

	if len(paths) == 0 {
		t.Error("expected at least some default paths")
	}

	// Check that current directory paths are included
	hasCurrentDir := false
	for _, path := range paths {
		if path == "gosqlx.yaml" || path == "gosqlx.yml" || path == "gosqlx.json" {
			hasCurrentDir = true
			break
		}
	}
	if !hasCurrentDir {
		t.Error("expected current directory config files in default paths")
	}
}
