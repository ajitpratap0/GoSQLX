package output

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFormatSARIF(t *testing.T) {
	tests := []struct {
		name       string
		result     *ValidationResult
		version    string
		wantSchema string
		wantRules  int
		wantErrors int
	}{
		{
			name: "single syntax error",
			result: &ValidationResult{
				TotalFiles:   1,
				ValidFiles:   0,
				InvalidFiles: 1,
				Duration:     time.Second,
				Files: []FileValidationResult{
					{
						Path:  "test.sql",
						Valid: false,
						Error: errors.New("parsing failed: unexpected token"),
					},
				},
			},
			version:    "1.4.0",
			wantSchema: "https://json.schemastore.org/sarif-2.1.0.json",
			wantRules:  3,
			wantErrors: 1,
		},
		{
			name: "tokenization error",
			result: &ValidationResult{
				TotalFiles:   1,
				ValidFiles:   0,
				InvalidFiles: 1,
				Duration:     time.Second,
				Files: []FileValidationResult{
					{
						Path:  "invalid.sql",
						Valid: false,
						Error: errors.New("tokenization failed: invalid character"),
					},
				},
			},
			version:    "1.4.0",
			wantSchema: "https://json.schemastore.org/sarif-2.1.0.json",
			wantRules:  3,
			wantErrors: 1,
		},
		{
			name: "multiple errors",
			result: &ValidationResult{
				TotalFiles:   3,
				ValidFiles:   1,
				InvalidFiles: 2,
				Duration:     time.Second,
				Files: []FileValidationResult{
					{
						Path:  "valid.sql",
						Valid: true,
						Error: nil,
					},
					{
						Path:  "error1.sql",
						Valid: false,
						Error: errors.New("parsing failed: missing FROM clause"),
					},
					{
						Path:  "error2.sql",
						Valid: false,
						Error: errors.New("tokenization failed: unclosed string"),
					},
				},
			},
			version:    "1.4.0",
			wantSchema: "https://json.schemastore.org/sarif-2.1.0.json",
			wantRules:  3,
			wantErrors: 2,
		},
		{
			name: "no errors",
			result: &ValidationResult{
				TotalFiles:   2,
				ValidFiles:   2,
				InvalidFiles: 0,
				Duration:     time.Second,
				Files: []FileValidationResult{
					{
						Path:  "valid1.sql",
						Valid: true,
						Error: nil,
					},
					{
						Path:  "valid2.sql",
						Valid: true,
						Error: nil,
					},
				},
			},
			version:    "1.4.0",
			wantSchema: "https://json.schemastore.org/sarif-2.1.0.json",
			wantRules:  3,
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := FormatSARIF(tt.result, tt.version)
			if err != nil {
				t.Fatalf("FormatSARIF() error = %v", err)
			}

			// Parse the SARIF JSON
			var sarif SARIF
			if err := json.Unmarshal(data, &sarif); err != nil {
				t.Fatalf("Failed to unmarshal SARIF: %v", err)
			}

			// Verify schema
			if sarif.Schema != tt.wantSchema {
				t.Errorf("Schema = %v, want %v", sarif.Schema, tt.wantSchema)
			}

			// Verify version
			if sarif.Version != "2.1.0" {
				t.Errorf("Version = %v, want 2.1.0", sarif.Version)
			}

			// Verify runs exist
			if len(sarif.Runs) != 1 {
				t.Fatalf("Runs count = %d, want 1", len(sarif.Runs))
			}

			run := sarif.Runs[0]

			// Verify tool information
			if run.Tool.Driver.Name != "GoSQLX" {
				t.Errorf("Tool name = %v, want GoSQLX", run.Tool.Driver.Name)
			}
			if run.Tool.Driver.Version != tt.version {
				t.Errorf("Tool version = %v, want %v", run.Tool.Driver.Version, tt.version)
			}

			// Verify rules
			if len(run.Tool.Driver.Rules) != tt.wantRules {
				t.Errorf("Rules count = %d, want %d", len(run.Tool.Driver.Rules), tt.wantRules)
			}

			// Verify results count
			if len(run.Results) != tt.wantErrors {
				t.Errorf("Results count = %d, want %d", len(run.Results), tt.wantErrors)
			}

			// Verify each result has required fields
			for i, result := range run.Results {
				if result.RuleID == "" {
					t.Errorf("Result[%d].RuleID is empty", i)
				}
				if result.Level != "error" {
					t.Errorf("Result[%d].Level = %v, want error", i, result.Level)
				}
				if result.Message.Text == "" {
					t.Errorf("Result[%d].Message.Text is empty", i)
				}
				if len(result.Locations) == 0 {
					t.Errorf("Result[%d].Locations is empty", i)
				} else {
					loc := result.Locations[0]
					if loc.PhysicalLocation.ArtifactLocation.URI == "" {
						t.Errorf("Result[%d].Location URI is empty", i)
					}
					if loc.PhysicalLocation.Region.StartLine < 1 {
						t.Errorf("Result[%d].Location StartLine = %d, want >= 1",
							i, loc.PhysicalLocation.Region.StartLine)
					}
				}
				// Verify fingerprint exists
				if _, ok := result.PartialFingerprints["primaryLocationLineHash"]; !ok {
					t.Errorf("Result[%d] missing primaryLocationLineHash fingerprint", i)
				}
			}
		})
	}
}

func TestCreateSARIFResult(t *testing.T) {
	tests := []struct {
		name       string
		fileResult FileValidationResult
		wantRuleID string
	}{
		{
			name: "parsing error",
			fileResult: FileValidationResult{
				Path:  "test.sql",
				Error: errors.New("parsing failed: unexpected token"),
			},
			wantRuleID: "sql-parsing-error",
		},
		{
			name: "tokenization error",
			fileResult: FileValidationResult{
				Path:  "test.sql",
				Error: errors.New("tokenization failed: invalid character"),
			},
			wantRuleID: "sql-tokenization-error",
		},
		{
			name: "generic syntax error",
			fileResult: FileValidationResult{
				Path:  "test.sql",
				Error: errors.New("syntax error on line 5"),
			},
			wantRuleID: "sql-syntax-error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createSARIFResult(tt.fileResult)

			if result.RuleID != tt.wantRuleID {
				t.Errorf("RuleID = %v, want %v", result.RuleID, tt.wantRuleID)
			}

			if result.Level != "error" {
				t.Errorf("Level = %v, want error", result.Level)
			}

			if result.Message.Text == "" {
				t.Error("Message.Text is empty")
			}

			if len(result.Locations) != 1 {
				t.Errorf("Locations count = %d, want 1", len(result.Locations))
			}
		})
	}
}

func TestGenerateFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		path1    string
		ruleID1  string
		msg1     string
		path2    string
		ruleID2  string
		msg2     string
		wantSame bool
	}{
		{
			name:     "identical inputs",
			path1:    "test.sql",
			ruleID1:  "sql-syntax-error",
			msg1:     "error message",
			path2:    "test.sql",
			ruleID2:  "sql-syntax-error",
			msg2:     "error message",
			wantSame: true,
		},
		{
			name:     "different paths",
			path1:    "test1.sql",
			ruleID1:  "sql-syntax-error",
			msg1:     "error message",
			path2:    "test2.sql",
			ruleID2:  "sql-syntax-error",
			msg2:     "error message",
			wantSame: false,
		},
		{
			name:     "different rule IDs",
			path1:    "test.sql",
			ruleID1:  "sql-syntax-error",
			msg1:     "error message",
			path2:    "test.sql",
			ruleID2:  "sql-parsing-error",
			msg2:     "error message",
			wantSame: false,
		},
		{
			name:     "different messages",
			path1:    "test.sql",
			ruleID1:  "sql-syntax-error",
			msg1:     "error message 1",
			path2:    "test.sql",
			ruleID2:  "sql-syntax-error",
			msg2:     "error message 2",
			wantSame: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp1 := generateFingerprint(tt.path1, tt.ruleID1, tt.msg1)
			fp2 := generateFingerprint(tt.path2, tt.ruleID2, tt.msg2)

			if tt.wantSame {
				if fp1 != fp2 {
					t.Errorf("Fingerprints should be same: %v != %v", fp1, fp2)
				}
			} else {
				if fp1 == fp2 {
					t.Errorf("Fingerprints should be different: %v == %v", fp1, fp2)
				}
			}

			// Verify fingerprint is a valid hex string
			if len(fp1) != 16 { // 8 bytes = 16 hex chars
				t.Errorf("Fingerprint length = %d, want 16", len(fp1))
			}
		})
	}
}

func TestNormalizeURI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "unix path",
			input: "path/to/file.sql",
			want:  "path/to/file.sql",
		},
		{
			name:  "windows path",
			input: "path\\to\\file.sql",
			want:  "path/to/file.sql",
		},
		{
			name:  "relative path with dot",
			input: "./path/to/file.sql",
			want:  "path/to/file.sql",
		},
		{
			name:  "simple filename",
			input: "file.sql",
			want:  "file.sql",
		},
		{
			name:  "mixed slashes",
			input: "./path\\to/file.sql",
			want:  "path/to/file.sql",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeURI(tt.input)
			if got != tt.want {
				t.Errorf("normalizeURI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSARIFJSONStructure(t *testing.T) {
	// Test that the SARIF output is valid JSON and has the expected structure
	result := &ValidationResult{
		TotalFiles:   1,
		ValidFiles:   0,
		InvalidFiles: 1,
		Files: []FileValidationResult{
			{
				Path:  "test.sql",
				Error: errors.New("parsing failed: test error"),
			},
		},
	}

	data, err := FormatSARIF(result, "1.4.0")
	if err != nil {
		t.Fatalf("FormatSARIF() error = %v", err)
	}

	// Verify it's valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Verify required top-level fields
	requiredFields := []string{"$schema", "version", "runs"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}

	// Verify the JSON is properly formatted (has indentation)
	if !strings.Contains(string(data), "\n") {
		t.Error("SARIF JSON should be pretty-printed with indentation")
	}
}
