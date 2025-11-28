package config

import (
	"testing"
)

func TestValidateDialect(t *testing.T) {
	tests := []struct {
		name      string
		dialect   string
		wantError bool
	}{
		{"valid postgresql", "postgresql", false},
		{"valid mysql", "mysql", false},
		{"valid sqlserver", "sqlserver", false},
		{"valid oracle", "oracle", false},
		{"valid sqlite", "sqlite", false},
		{"valid generic", "generic", false},
		{"invalid dialect", "invalid_dialect", true},
		{"empty dialect", "", true},
		{"case sensitive", "PostgreSQL", true}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDialect(tt.dialect)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateDialect(%q) error = %v, wantError %v", tt.dialect, err, tt.wantError)
			}
		})
	}
}

func TestValidateOutputFormat(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantError bool
	}{
		{"valid json", "json", false},
		{"valid yaml", "yaml", false},
		{"valid table", "table", false},
		{"valid tree", "tree", false},
		{"valid auto", "auto", false},
		{"invalid format", "invalid_format", true},
		{"empty format", "", true},
		{"case sensitive", "JSON", true}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOutputFormat(tt.format)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateOutputFormat(%q) error = %v, wantError %v", tt.format, err, tt.wantError)
			}
		})
	}
}

func TestValidateIndent(t *testing.T) {
	tests := []struct {
		name      string
		indent    int
		wantError bool
	}{
		{"valid 0", 0, false},
		{"valid 2", 2, false},
		{"valid 4", 4, false},
		{"valid 8", 8, false},
		{"invalid negative", -1, true},
		{"invalid too large", 9, true},
		{"invalid very large", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIndent(tt.indent)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateIndent(%d) error = %v, wantError %v", tt.indent, err, tt.wantError)
			}
		})
	}
}

func TestValidateMaxLineLength(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		wantError bool
	}{
		{"valid 0 (unlimited)", 0, false},
		{"valid 80", 80, false},
		{"valid 120", 120, false},
		{"valid 500", 500, false},
		{"invalid negative", -1, true},
		{"invalid too large", 501, true},
		{"invalid very large", 1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMaxLineLength(tt.length)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateMaxLineLength(%d) error = %v, wantError %v", tt.length, err, tt.wantError)
			}
		})
	}
}

func TestGetSchema(t *testing.T) {
	schema := GetSchema()

	// Test format schema
	if schema.Format.Indent.Min != 0 {
		t.Errorf("expected format.indent.min to be 0, got %d", schema.Format.Indent.Min)
	}
	if schema.Format.Indent.Max != 8 {
		t.Errorf("expected format.indent.max to be 8, got %d", schema.Format.Indent.Max)
	}
	if schema.Format.Indent.Default != 2 {
		t.Errorf("expected format.indent.default to be 2, got %d", schema.Format.Indent.Default)
	}
	if schema.Format.Indent.Desc == "" {
		t.Error("format.indent.description should not be empty")
	}

	if !schema.Format.UppercaseKeywords.Default {
		t.Error("expected format.uppercase_keywords.default to be true")
	}
	if schema.Format.UppercaseKeywords.Desc == "" {
		t.Error("format.uppercase_keywords.description should not be empty")
	}

	if schema.Format.MaxLineLength.Min != 0 {
		t.Errorf("expected format.max_line_length.min to be 0, got %d", schema.Format.MaxLineLength.Min)
	}
	if schema.Format.MaxLineLength.Max != 500 {
		t.Errorf("expected format.max_line_length.max to be 500, got %d", schema.Format.MaxLineLength.Max)
	}
	if schema.Format.MaxLineLength.Default != 80 {
		t.Errorf("expected format.max_line_length.default to be 80, got %d", schema.Format.MaxLineLength.Default)
	}

	if schema.Format.Compact.Default {
		t.Error("expected format.compact.default to be false")
	}

	// Test validation schema
	if len(schema.Validation.Dialect.Options) != len(ValidDialects) {
		t.Errorf("expected %d dialect options, got %d", len(ValidDialects), len(schema.Validation.Dialect.Options))
	}
	if schema.Validation.Dialect.Default != "postgresql" {
		t.Errorf("expected validate.dialect.default to be 'postgresql', got '%s'", schema.Validation.Dialect.Default)
	}
	if schema.Validation.Dialect.Desc == "" {
		t.Error("validate.dialect.description should not be empty")
	}

	if schema.Validation.StrictMode.Default {
		t.Error("expected validate.strict_mode.default to be false")
	}
	if schema.Validation.Recursive.Default {
		t.Error("expected validate.recursive.default to be false")
	}
	if schema.Validation.Pattern.Default != "*.sql" {
		t.Errorf("expected validate.pattern.default to be '*.sql', got '%s'", schema.Validation.Pattern.Default)
	}

	// Test output schema
	if len(schema.Output.Format.Options) != len(ValidOutputFormats) {
		t.Errorf("expected %d output format options, got %d", len(ValidOutputFormats), len(schema.Output.Format.Options))
	}
	if schema.Output.Format.Default != "auto" {
		t.Errorf("expected output.format.default to be 'auto', got '%s'", schema.Output.Format.Default)
	}
	if schema.Output.Format.Desc == "" {
		t.Error("output.format.description should not be empty")
	}

	if schema.Output.Verbose.Default {
		t.Error("expected output.verbose.default to be false")
	}

	// Test analyze schema
	if !schema.Analyze.Security.Default {
		t.Error("expected analyze.security.default to be true")
	}
	if !schema.Analyze.Performance.Default {
		t.Error("expected analyze.performance.default to be true")
	}
	if !schema.Analyze.Complexity.Default {
		t.Error("expected analyze.complexity.default to be true")
	}
	if schema.Analyze.All.Default {
		t.Error("expected analyze.all.default to be false")
	}

	// Verify all descriptions are set
	if schema.Analyze.Security.Desc == "" {
		t.Error("analyze.security.description should not be empty")
	}
	if schema.Analyze.Performance.Desc == "" {
		t.Error("analyze.performance.description should not be empty")
	}
	if schema.Analyze.Complexity.Desc == "" {
		t.Error("analyze.complexity.description should not be empty")
	}
	if schema.Analyze.All.Desc == "" {
		t.Error("analyze.all.description should not be empty")
	}
}

func TestValidDialects(t *testing.T) {
	expectedDialects := []string{"postgresql", "mysql", "sqlserver", "oracle", "sqlite", "generic"}

	if len(ValidDialects) != len(expectedDialects) {
		t.Errorf("expected %d dialects, got %d", len(expectedDialects), len(ValidDialects))
	}

	for i, expected := range expectedDialects {
		if i >= len(ValidDialects) {
			t.Errorf("missing dialect at index %d: %s", i, expected)
			continue
		}
		if ValidDialects[i] != expected {
			t.Errorf("dialect at index %d: expected %s, got %s", i, expected, ValidDialects[i])
		}
	}
}

func TestValidOutputFormats(t *testing.T) {
	expectedFormats := []string{"json", "yaml", "table", "tree", "auto"}

	if len(ValidOutputFormats) != len(expectedFormats) {
		t.Errorf("expected %d output formats, got %d", len(expectedFormats), len(ValidOutputFormats))
	}

	for i, expected := range expectedFormats {
		if i >= len(ValidOutputFormats) {
			t.Errorf("missing output format at index %d: %s", i, expected)
			continue
		}
		if ValidOutputFormats[i] != expected {
			t.Errorf("output format at index %d: expected %s, got %s", i, expected, ValidOutputFormats[i])
		}
	}
}

func TestSchemaConsistencyWithDefaults(t *testing.T) {
	// Verify that schema defaults match DefaultConfig()
	schema := GetSchema()
	defaultCfg := DefaultConfig()

	// Format
	if defaultCfg.Format.Indent != schema.Format.Indent.Default {
		t.Errorf("indent default mismatch: config=%d, schema=%d",
			defaultCfg.Format.Indent, schema.Format.Indent.Default)
	}
	if defaultCfg.Format.UppercaseKeywords != schema.Format.UppercaseKeywords.Default {
		t.Errorf("uppercase_keywords default mismatch: config=%v, schema=%v",
			defaultCfg.Format.UppercaseKeywords, schema.Format.UppercaseKeywords.Default)
	}
	if defaultCfg.Format.MaxLineLength != schema.Format.MaxLineLength.Default {
		t.Errorf("max_line_length default mismatch: config=%d, schema=%d",
			defaultCfg.Format.MaxLineLength, schema.Format.MaxLineLength.Default)
	}
	if defaultCfg.Format.Compact != schema.Format.Compact.Default {
		t.Errorf("compact default mismatch: config=%v, schema=%v",
			defaultCfg.Format.Compact, schema.Format.Compact.Default)
	}

	// Validation
	if defaultCfg.Validation.Dialect != schema.Validation.Dialect.Default {
		t.Errorf("dialect default mismatch: config=%s, schema=%s",
			defaultCfg.Validation.Dialect, schema.Validation.Dialect.Default)
	}
	if defaultCfg.Validation.StrictMode != schema.Validation.StrictMode.Default {
		t.Errorf("strict_mode default mismatch: config=%v, schema=%v",
			defaultCfg.Validation.StrictMode, schema.Validation.StrictMode.Default)
	}
	if defaultCfg.Validation.Recursive != schema.Validation.Recursive.Default {
		t.Errorf("recursive default mismatch: config=%v, schema=%v",
			defaultCfg.Validation.Recursive, schema.Validation.Recursive.Default)
	}
	if defaultCfg.Validation.Pattern != schema.Validation.Pattern.Default {
		t.Errorf("pattern default mismatch: config=%s, schema=%s",
			defaultCfg.Validation.Pattern, schema.Validation.Pattern.Default)
	}

	// Output
	if defaultCfg.Output.Format != schema.Output.Format.Default {
		t.Errorf("output format default mismatch: config=%s, schema=%s",
			defaultCfg.Output.Format, schema.Output.Format.Default)
	}
	if defaultCfg.Output.Verbose != schema.Output.Verbose.Default {
		t.Errorf("verbose default mismatch: config=%v, schema=%v",
			defaultCfg.Output.Verbose, schema.Output.Verbose.Default)
	}

	// Analyze
	if defaultCfg.Analyze.Security != schema.Analyze.Security.Default {
		t.Errorf("security default mismatch: config=%v, schema=%v",
			defaultCfg.Analyze.Security, schema.Analyze.Security.Default)
	}
	if defaultCfg.Analyze.Performance != schema.Analyze.Performance.Default {
		t.Errorf("performance default mismatch: config=%v, schema=%v",
			defaultCfg.Analyze.Performance, schema.Analyze.Performance.Default)
	}
	if defaultCfg.Analyze.Complexity != schema.Analyze.Complexity.Default {
		t.Errorf("complexity default mismatch: config=%v, schema=%v",
			defaultCfg.Analyze.Complexity, schema.Analyze.Complexity.Default)
	}
	if defaultCfg.Analyze.All != schema.Analyze.All.Default {
		t.Errorf("all default mismatch: config=%v, schema=%v",
			defaultCfg.Analyze.All, schema.Analyze.All.Default)
	}
}
