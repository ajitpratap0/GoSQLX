package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnalyzeCommandCLI tests the analyze CLI command through binary execution
func TestAnalyzeCommandCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI exec tests in short mode")
	}

	tmpDir := t.TempDir()

	testCases := []struct {
		name             string
		sql              string
		expectedInOutput string
		expectError      bool
	}{
		{
			name:             "Clean query",
			sql:              "SELECT id, name FROM users WHERE active = true",
			expectedInOutput: "Analysis Results",
			expectError:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tmpDir, "test.sql")
			err := os.WriteFile(testFile, []byte(tc.sql), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Build CLI binary first
			binaryPath := filepath.Join(tmpDir, "gosqlx")
			cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/gosqlx")
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to build CLI binary: %v", err)
			}

			// Test CLI execution
			cmd = exec.Command(binaryPath, "analyze", testFile)
			output, err := cmd.CombinedOutput()

			if tc.expectError {
				if err == nil {
					t.Error("Expected error, but command succeeded")
				}
			} else {
				if err != nil {
					t.Fatalf("CLI command failed: %v\nOutput: %s", err, output)
				}
				outputStr := string(output)
				if !strings.Contains(outputStr, tc.expectedInOutput) {
					t.Errorf("Expected output to contain %s, got: %s", tc.expectedInOutput, outputStr)
				}
			}
		})
	}
}

// TestParseCommandCLI tests the parse CLI command functionality
func TestParseCommandCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI exec tests in short mode")
	}

	tmpDir := t.TempDir()

	testCases := []struct {
		name        string
		sql         string
		expectError bool
	}{
		{
			name:        "Simple SELECT",
			sql:         "SELECT id FROM users",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build CLI binary first
			binaryPath := filepath.Join(tmpDir, "gosqlx")
			cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/gosqlx")
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to build CLI binary: %v", err)
			}

			// Test CLI execution with direct SQL
			cmd = exec.Command(binaryPath, "parse", tc.sql)
			output, err := cmd.CombinedOutput()

			if tc.expectError {
				if err == nil {
					t.Error("Expected error, but command succeeded")
				}
			} else {
				if err != nil {
					t.Fatalf("Parse command failed: %v\nOutput: %s", err, output)
				}
				// Parse should produce some output
				if len(output) == 0 {
					t.Error("Expected parse output, got empty")
				}
			}
		})
	}
}

// TestFormatCommandCLI tests the format CLI command functionality
func TestFormatCommandCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI exec tests in short mode")
	}

	tmpDir := t.TempDir()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple SELECT formatting",
			input:    "select id,name from users",
			expected: "SELECT",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tmpDir, "test.sql")
			err := os.WriteFile(testFile, []byte(tc.input), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Build CLI binary first
			binaryPath := filepath.Join(tmpDir, "gosqlx")
			cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/gosqlx")
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to build CLI binary: %v", err)
			}

			// Test CLI execution
			cmd = exec.Command(binaryPath, "format", testFile)
			output, err := cmd.CombinedOutput()

			if err != nil {
				t.Fatalf("Format command failed: %v\nOutput: %s", err, output)
			}

			formatted := string(output)
			if !strings.Contains(formatted, tc.expected) {
				t.Errorf("Expected formatted output to contain %s, got: %s", tc.expected, formatted)
			}
		})
	}
}

// TestValidateCommandCLI tests the validate CLI command functionality
func TestValidateCommandCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI exec tests in short mode")
	}

	tmpDir := t.TempDir()

	testCases := []struct {
		name        string
		sql         string
		expectValid bool
	}{
		{
			name:        "Valid SELECT",
			sql:         "SELECT id, name FROM users WHERE active = true",
			expectValid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testFile := filepath.Join(tmpDir, "test.sql")
			err := os.WriteFile(testFile, []byte(tc.sql), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Build CLI binary first
			binaryPath := filepath.Join(tmpDir, "gosqlx")
			cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/gosqlx")
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to build CLI binary: %v", err)
			}

			// Test CLI execution
			cmd = exec.Command(binaryPath, "validate", testFile)
			output, err := cmd.CombinedOutput()

			if tc.expectValid {
				if err != nil {
					t.Fatalf("Expected valid SQL, got error: %v\nOutput: %s", err, output)
				}
				// Should have validation output
				if len(output) == 0 {
					t.Error("Expected validation output")
				}
			} else {
				if err == nil {
					t.Error("Expected validation to fail for invalid SQL")
				}
			}
		})
	}
}

// TestCLIIntegration tests basic CLI integration through binary execution
func TestCLIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI integration tests in short mode")
	}

	tmpDir := t.TempDir()

	// Create test SQL file
	testSQL := "SELECT id, name FROM users WHERE active = true"
	testFile := filepath.Join(tmpDir, "test.sql")
	err := os.WriteFile(testFile, []byte(testSQL), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Build CLI binary first
	binaryPath := filepath.Join(tmpDir, "gosqlx")
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/gosqlx")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build CLI binary: %v", err)
	}

	t.Run("CLI Binary Built Successfully", func(t *testing.T) {
		// Test that binary exists and is executable
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			t.Fatalf("CLI binary was not created: %v", err)
		}
	})

	t.Run("CLI Help Command", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "--help")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Help command failed: %v\nOutput: %s", err, output)
		}
		if !strings.Contains(string(output), "GoSQLX") {
			t.Error("Expected help output to contain 'GoSQLX'")
		}
	})
}
