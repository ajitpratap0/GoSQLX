package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
)

const testConfigTemplate = `# Test GoSQLX Configuration
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 80
  compact: false

validate:
  dialect: postgresql
  strict_mode: false
  recursive: false
  pattern: "*.sql"
  security:
    max_file_size: 10485760

output:
  format: auto
  verbose: false

analyze:
  security: true
  performance: true
  complexity: true
  all: false
`

// TestConfigManager_Init tests config file initialization
func TestConfigManager_Init(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		opts           ConfigManagerOptions
		fileExists     bool
		expectCreated  bool
		expectError    bool
		errorContains  string
		outputContains []string
	}{
		{
			name:          "create config in default location",
			path:          "",
			opts:          ConfigManagerOptions{},
			expectCreated: true,
			outputContains: []string{
				"✅ Created configuration file",
				".gosqlx.yml",
				"customize this file",
			},
		},
		{
			name:          "create config in custom location",
			path:          "custom_config.yml",
			opts:          ConfigManagerOptions{},
			expectCreated: true,
			outputContains: []string{
				"✅ Created configuration file",
				"custom_config.yml",
			},
		},
		{
			name:          "file exists without force",
			path:          "existing.yml",
			opts:          ConfigManagerOptions{Force: false},
			fileExists:    true,
			expectCreated: false,
			expectError:   true,
			errorContains: "already exists",
		},
		{
			name:          "file exists with force",
			path:          "existing.yml",
			opts:          ConfigManagerOptions{Force: true},
			fileExists:    true,
			expectCreated: true,
			outputContains: []string{
				"✅ Created configuration file",
			},
		},
		{
			name:          "verbose mode",
			path:          "verbose_config.yml",
			opts:          ConfigManagerOptions{Verbose: true, Force: true},
			fileExists:    true,
			expectCreated: true,
			outputContains: []string{
				"Overwriting existing configuration",
				"✅ Created configuration file",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directory for test
			tmpDir := t.TempDir()
			testPath := tt.path
			if testPath == "" {
				testPath = ".gosqlx.yml"
			}
			fullPath := filepath.Join(tmpDir, testPath)

			// Create existing file if needed
			if tt.fileExists {
				if err := os.WriteFile(fullPath, []byte("# existing content"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
			}

			var outBuf, errBuf bytes.Buffer
			cm := NewConfigManager(&outBuf, &errBuf, tt.opts, testConfigTemplate)

			result, err := cm.Init(fullPath)

			// Check error expectations
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			// Check result
			if result == nil {
				t.Fatal("Expected result but got nil")
			}
			if result.Created != tt.expectCreated {
				t.Errorf("Expected Created=%v, got %v", tt.expectCreated, result.Created)
			}

			// Check output
			output := outBuf.String()
			for _, expected := range tt.outputContains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', but it doesn't. Output: %s", expected, output)
				}
			}

			// Verify file was created if expected
			if tt.expectCreated && !tt.expectError {
				if _, err := os.Stat(fullPath); os.IsNotExist(err) {
					t.Errorf("Expected file to be created at %s but it doesn't exist", fullPath)
				}

				// Verify content
				content, err := os.ReadFile(fullPath)
				if err != nil {
					t.Errorf("Failed to read created file: %v", err)
				}
				if !strings.Contains(string(content), "# Test GoSQLX Configuration") {
					t.Errorf("Created file doesn't contain expected template content")
				}
			}
		})
	}
}

// TestConfigManager_Validate tests config validation
func TestConfigManager_Validate(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		configFile     string
		expectValid    bool
		expectError    bool
		errorContains  string
		outputContains []string
	}{
		{
			name:          "valid config",
			configContent: testConfigTemplate,
			expectValid:   true,
			outputContains: []string{
				"✅ Configuration is valid",
			},
		},
		{
			name: "invalid indent value",
			configContent: `format:
  indent: 99
validate:
  dialect: postgresql
output:
  format: auto
analyze:
  security: true`,
			expectValid:   false,
			expectError:   true,
			errorContains: "indent must be between 0 and 8",
			outputContains: []string{
				"❌ Configuration validation failed",
			},
		},
		{
			name: "invalid dialect",
			configContent: `format:
  indent: 2
validate:
  dialect: invalid_dialect
output:
  format: auto
analyze:
  security: true`,
			expectValid:   false,
			expectError:   true,
			errorContains: "dialect must be one of",
			outputContains: []string{
				"❌ Configuration validation failed",
			},
		},
		{
			name: "invalid output format",
			configContent: `format:
  indent: 2
validate:
  dialect: postgresql
output:
  format: invalid_format
analyze:
  security: true`,
			expectValid:   false,
			expectError:   true,
			errorContains: "output.format must be one of",
			outputContains: []string{
				"❌ Configuration validation failed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "test_config.yml")
			if err := os.WriteFile(configPath, []byte(tt.configContent), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			var outBuf, errBuf bytes.Buffer
			cm := NewConfigManager(&outBuf, &errBuf, ConfigManagerOptions{}, testConfigTemplate)

			result, err := cm.Validate(configPath)

			// Check error expectations
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			// Check result
			if result == nil {
				t.Fatal("Expected result but got nil")
			}
			if result.Valid != tt.expectValid {
				t.Errorf("Expected Valid=%v, got %v", tt.expectValid, result.Valid)
			}

			// Check output
			output := outBuf.String()
			for _, expected := range tt.outputContains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', but it doesn't. Output: %s", expected, output)
				}
			}
		})
	}
}

// TestConfigManager_Validate_DefaultLocation tests validation without specifying file
func TestConfigManager_Validate_DefaultLocation(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	cm := NewConfigManager(&outBuf, &errBuf, ConfigManagerOptions{}, testConfigTemplate)

	// Validate default location (will use built-in defaults)
	result, err := cm.Validate("")

	// Should succeed with default config
	if err != nil {
		t.Errorf("Expected no error with default config, got: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result but got nil")
	}
	if !result.Valid {
		t.Error("Expected default config to be valid")
	}
	if result.Config == nil {
		t.Error("Expected config to be set")
	}

	output := outBuf.String()
	if !strings.Contains(output, "✅ Configuration is valid") {
		t.Errorf("Expected valid config message in output")
	}
}

// TestConfigManager_Validate_NonExistentFile tests validation of non-existent file
func TestConfigManager_Validate_NonExistentFile(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	cm := NewConfigManager(&outBuf, &errBuf, ConfigManagerOptions{}, testConfigTemplate)

	result, err := cm.Validate("/nonexistent/path/config.yml")

	// Should fail
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
	if result == nil {
		t.Fatal("Expected result but got nil")
	}
	if result.Valid {
		t.Error("Expected Valid=false for non-existent file")
	}
}

// TestConfigManager_Show tests config display
func TestConfigManager_Show(t *testing.T) {
	tests := []struct {
		name           string
		format         string
		expectError    bool
		errorContains  string
		outputContains []string
	}{
		{
			name:   "show as YAML (default)",
			format: "yaml",
			outputContains: []string{
				"# GoSQLX Configuration",
				"format:",
				"indent:",
				"validate:",
				"output:",
				"analyze:",
			},
		},
		{
			name:   "show as JSON",
			format: "json",
			outputContains: []string{
				`"Format"`,
				`"Validation"`,
				`"Output"`,
				`"Analyze"`,
			},
		},
		{
			name:   "auto format (defaults to YAML)",
			format: "auto",
			outputContains: []string{
				"# GoSQLX Configuration",
				"format:",
			},
		},
		{
			name:   "empty format (defaults to YAML)",
			format: "",
			outputContains: []string{
				"# GoSQLX Configuration",
				"format:",
			},
		},
		{
			name:          "invalid format",
			format:        "xml",
			expectError:   true,
			errorContains: "unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file with valid content
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "test_config.yml")
			if err := os.WriteFile(configPath, []byte(testConfigTemplate), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			var outBuf, errBuf bytes.Buffer
			opts := ConfigManagerOptions{Format: tt.format}
			cm := NewConfigManager(&outBuf, &errBuf, opts, testConfigTemplate)

			result, err := cm.Show(configPath)

			// Check error expectations
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			// Check result
			if result == nil {
				t.Fatal("Expected result but got nil")
			}

			// Check output
			output := outBuf.String()
			for _, expected := range tt.outputContains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', but it doesn't. Output: %s", expected, output)
				}
			}

			// Verify result.Output matches buffer output (unless error)
			if !tt.expectError && result.Output != output {
				t.Errorf("Result.Output doesn't match buffer output")
			}
		})
	}
}

// TestConfigManager_Show_DefaultLocation tests showing config from default location
func TestConfigManager_Show_DefaultLocation(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	opts := ConfigManagerOptions{Format: "yaml"}
	cm := NewConfigManager(&outBuf, &errBuf, opts, testConfigTemplate)

	result, err := cm.Show("")

	// Should succeed with default config
	if err != nil {
		t.Errorf("Expected no error with default config, got: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result but got nil")
	}
	if result.Config == nil {
		t.Error("Expected config to be set")
	}

	output := outBuf.String()
	if !strings.Contains(output, "# GoSQLX Configuration") {
		t.Error("Expected YAML header in output")
	}
	if !strings.Contains(output, "format:") {
		t.Error("Expected format section in output")
	}
}

// TestConfigManager_Show_NonExistentFile tests showing non-existent config
func TestConfigManager_Show_NonExistentFile(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	opts := ConfigManagerOptions{Format: "yaml"}
	cm := NewConfigManager(&outBuf, &errBuf, opts, testConfigTemplate)

	result, err := cm.Show("/nonexistent/path/config.yml")

	// Should fail
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
	if result == nil {
		t.Fatal("Expected result but got nil")
	}
	if result.Config != nil {
		t.Error("Expected Config to be nil on error")
	}
}

// TestConfigManagerOptionsFromFlags tests option creation from flags
func TestConfigManagerOptionsFromFlags(t *testing.T) {
	flags := ConfigManagerFlags{
		Format:  "json",
		Verbose: true,
		Force:   true,
	}

	opts := ConfigManagerOptionsFromFlags(flags)

	if opts.Format != "json" {
		t.Errorf("Expected Format=json, got %s", opts.Format)
	}
	if !opts.Verbose {
		t.Error("Expected Verbose=true")
	}
	if !opts.Force {
		t.Error("Expected Force=true")
	}
}

// TestConfigManager_Init_InvalidPath tests initialization with invalid path
func TestConfigManager_Init_InvalidPath(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	cm := NewConfigManager(&outBuf, &errBuf, ConfigManagerOptions{}, testConfigTemplate)

	// Try to create in a directory that doesn't exist (without creating parent dirs)
	result, err := cm.Init("/nonexistent/deeply/nested/path/config.yml")

	// Should fail
	if err == nil {
		t.Error("Expected error for invalid path")
	}
	if result == nil {
		t.Fatal("Expected result but got nil")
	}
	if result.Created {
		t.Error("Expected Created=false on error")
	}
	if !strings.Contains(err.Error(), "failed to create config file") {
		t.Errorf("Expected 'failed to create config file' error, got: %v", err)
	}
}

// TestConfigManager_Validate_MalformedYAML tests validation with malformed YAML
func TestConfigManager_Validate_MalformedYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "malformed.yml")

	// Write malformed YAML
	malformedYAML := `
format:
  indent: 2
  this is not valid yaml syntax
    bad indentation
`
	if err := os.WriteFile(configPath, []byte(malformedYAML), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	cm := NewConfigManager(&outBuf, &errBuf, ConfigManagerOptions{}, testConfigTemplate)

	result, err := cm.Validate(configPath)

	// Should fail
	if err == nil {
		t.Error("Expected error for malformed YAML")
	}
	if result == nil {
		t.Fatal("Expected result but got nil")
	}
	if result.Valid {
		t.Error("Expected Valid=false for malformed YAML")
	}
}

// TestConfigManager_Show_ConfigWithAllSettings tests showing a fully configured file
func TestConfigManager_Show_ConfigWithAllSettings(t *testing.T) {
	fullConfig := `format:
  indent: 4
  uppercase_keywords: false
  max_line_length: 120
  compact: true

validate:
  dialect: mysql
  strict_mode: true
  recursive: true
  pattern: "**/*.sql"
  security:
    max_file_size: 52428800

output:
  format: json
  verbose: true

analyze:
  security: false
  performance: false
  complexity: false
  all: true
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "full_config.yml")
	if err := os.WriteFile(configPath, []byte(fullConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	opts := ConfigManagerOptions{Format: "json"}
	cm := NewConfigManager(&outBuf, &errBuf, opts, testConfigTemplate)

	result, err := cm.Show(configPath)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result but got nil")
	}

	// Verify all custom settings are in output
	output := outBuf.String()
	// Note: JSON uses uppercase field names since Config struct only has yaml tags
	expectedValues := []string{
		`"Indent": 4`,
		`"UppercaseKeywords": false`,
		`"MaxLineLength": 120`,
		`"Compact": true`,
		`"Dialect": "mysql"`,
		`"StrictMode": true`,
		`"All": true`,
	}

	for _, expected := range expectedValues {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', but it doesn't", expected)
		}
	}
}

// TestConfigManager_Integration tests a complete workflow
func TestConfigManager_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "integration_test.yml")

	// Step 1: Initialize config
	var initOut, initErr bytes.Buffer
	initCM := NewConfigManager(&initOut, &initErr, ConfigManagerOptions{}, testConfigTemplate)
	initResult, err := initCM.Init(configPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if !initResult.Created {
		t.Fatal("Expected config to be created")
	}

	// Step 2: Validate the created config
	var valOut, valErr bytes.Buffer
	valCM := NewConfigManager(&valOut, &valErr, ConfigManagerOptions{}, testConfigTemplate)
	valResult, err := valCM.Validate(configPath)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if !valResult.Valid {
		t.Fatal("Expected config to be valid")
	}

	// Step 3: Show the config in YAML
	var showYAMLOut, showYAMLErr bytes.Buffer
	showYAMLCM := NewConfigManager(&showYAMLOut, &showYAMLErr, ConfigManagerOptions{Format: "yaml"}, testConfigTemplate)
	yamlResult, err := showYAMLCM.Show(configPath)
	if err != nil {
		t.Fatalf("Show YAML failed: %v", err)
	}
	if !strings.Contains(yamlResult.Output, "# GoSQLX Configuration") {
		t.Error("Expected YAML header in output")
	}

	// Step 4: Show the config in JSON
	var showJSONOut, showJSONErr bytes.Buffer
	showJSONCM := NewConfigManager(&showJSONOut, &showJSONErr, ConfigManagerOptions{Format: "json"}, testConfigTemplate)
	jsonResult, err := showJSONCM.Show(configPath)
	if err != nil {
		t.Fatalf("Show JSON failed: %v", err)
	}
	if !strings.Contains(jsonResult.Output, `"Format"`) {
		t.Error("Expected JSON format in output")
	}

	// Step 5: Try to init again without force (should fail)
	var reinitOut, reinitErr bytes.Buffer
	reinitCM := NewConfigManager(&reinitOut, &reinitErr, ConfigManagerOptions{Force: false}, testConfigTemplate)
	reinitResult, err := reinitCM.Init(configPath)
	if err == nil {
		t.Error("Expected error when reinitializing without force")
	}
	if reinitResult.Created {
		t.Error("Expected Created=false when file exists")
	}

	// Step 6: Init again with force (should succeed)
	var forceOut, forceErr bytes.Buffer
	forceCM := NewConfigManager(&forceOut, &forceErr, ConfigManagerOptions{Force: true, Verbose: true}, testConfigTemplate)
	forceResult, err := forceCM.Init(configPath)
	if err != nil {
		t.Fatalf("Force init failed: %v", err)
	}
	if !forceResult.Created {
		t.Error("Expected config to be recreated with force")
	}
	forceOutput := forceOut.String()
	if !strings.Contains(forceOutput, "Overwriting") {
		t.Error("Expected overwrite message in verbose mode")
	}
}

// TestNewConfigManager tests constructor
func TestNewConfigManager(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	opts := ConfigManagerOptions{
		Format:  "json",
		Verbose: true,
		Force:   false,
	}
	template := "test template"

	cm := NewConfigManager(&outBuf, &errBuf, opts, template)

	if cm == nil {
		t.Fatal("Expected ConfigManager but got nil")
	}
	if cm.Out != &outBuf {
		t.Error("Out writer not set correctly")
	}
	if cm.Err != &errBuf {
		t.Error("Err writer not set correctly")
	}
	if cm.Opts.Format != "json" {
		t.Errorf("Expected Format=json, got %s", cm.Opts.Format)
	}
	if !cm.Opts.Verbose {
		t.Error("Expected Verbose=true")
	}
	if cm.Opts.Force {
		t.Error("Expected Force=false")
	}
	if cm.Template != template {
		t.Error("Template not set correctly")
	}
}

// Helper function to create a valid config for testing
func createValidTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Format: config.FormatConfig{
			Indent:            2,
			UppercaseKeywords: true,
			MaxLineLength:     80,
			Compact:           false,
		},
		Validation: config.ValidationConfig{
			Dialect:    "postgresql",
			StrictMode: false,
			Recursive:  false,
			Pattern:    "*.sql",
			Security: config.SecurityConfig{
				MaxFileSize: 10 * 1024 * 1024,
			},
		},
		Output: config.OutputConfig{
			Format:  "auto",
			Verbose: false,
		},
		Analyze: config.AnalyzeConfig{
			Security:    true,
			Performance: true,
			Complexity:  true,
			All:         false,
		},
	}
}
