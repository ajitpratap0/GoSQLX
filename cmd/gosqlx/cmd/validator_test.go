package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestValidator_ValidateFile tests single file validation
func TestValidator_ValidateFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name          string
		filename      string
		content       string
		expectValid   bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid SQL file",
			filename:    "valid.sql",
			content:     "SELECT * FROM users WHERE active = true",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "valid empty file",
			filename:    "empty.sql",
			content:     "",
			expectValid: true,
			expectError: false,
		},
		{
			name:          "invalid SQL - missing table name",
			filename:      "invalid.sql",
			content:       "SELECT * FROM",
			expectValid:   false,
			expectError:   true,
			errorContains: "parsing failed",
		},
		{
			name:        "valid complex query with JOINs",
			filename:    "complex.sql",
			content:     "SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.name",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "valid window function",
			filename:    "window.sql",
			content:     "SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "valid CTE",
			filename:    "cte.sql",
			content:     "WITH temp AS (SELECT id FROM users) SELECT * FROM temp",
			expectValid: true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			filepath := filepath.Join(tmpDir, tt.filename)
			if err := os.WriteFile(filepath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Create validator
			var outBuf, errBuf bytes.Buffer
			validator := NewValidator(&outBuf, &errBuf, ValidatorOptions{})

			// Validate file
			result := validator.validateFile(filepath)

			// Check results
			if tt.expectError {
				if result.Error == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(result.Error.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, result.Error)
				}
			} else {
				if result.Error != nil {
					t.Errorf("Unexpected error: %v", result.Error)
				}
			}

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.expectValid, result.Valid)
			}

			if result.Size != int64(len(tt.content)) {
				t.Errorf("Expected size=%d, got size=%d", len(tt.content), result.Size)
			}
		})
	}
}

// TestValidator_Validate tests multi-file validation
func TestValidator_Validate(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name               string
		files              map[string]string // filename -> content
		args               []string
		opts               ValidatorOptions
		expectTotalFiles   int
		expectValidFiles   int
		expectInvalidFiles int
		expectError        bool
		expectOutContains  []string
		expectErrContains  []string
	}{
		{
			name: "single valid file",
			files: map[string]string{
				"query1.sql": "SELECT * FROM users",
			},
			args:               []string{filepath.Join(tmpDir, "query1.sql")},
			opts:               ValidatorOptions{},
			expectTotalFiles:   1,
			expectValidFiles:   1,
			expectInvalidFiles: 0,
			expectOutContains:  []string{"✅", "query1.sql", "Valid SQL"},
		},
		{
			name: "multiple valid files",
			files: map[string]string{
				"query1.sql": "SELECT * FROM users",
				"query2.sql": "INSERT INTO users (name) VALUES ('John')",
				"query3.sql": "UPDATE users SET active = true WHERE id = 1",
			},
			args: []string{
				filepath.Join(tmpDir, "query1.sql"),
				filepath.Join(tmpDir, "query2.sql"),
				filepath.Join(tmpDir, "query3.sql"),
			},
			opts:               ValidatorOptions{},
			expectTotalFiles:   3,
			expectValidFiles:   3,
			expectInvalidFiles: 0,
			expectOutContains:  []string{"✅", "query1.sql", "query2.sql", "query3.sql"},
		},
		{
			name: "mix of valid and invalid files",
			files: map[string]string{
				"valid.sql":   "SELECT * FROM users",
				"invalid.sql": "SELECT * FROM",
			},
			args: []string{
				filepath.Join(tmpDir, "valid.sql"),
				filepath.Join(tmpDir, "invalid.sql"),
			},
			opts:               ValidatorOptions{},
			expectTotalFiles:   2,
			expectValidFiles:   1,
			expectInvalidFiles: 1,
			expectOutContains:  []string{"✅", "valid.sql"},
			expectErrContains:  []string{"❌", "invalid.sql", "parsing failed"},
		},
		{
			name: "quiet mode - valid files",
			files: map[string]string{
				"query.sql": "SELECT * FROM users",
			},
			args:              []string{filepath.Join(tmpDir, "query.sql")},
			opts:              ValidatorOptions{Quiet: true},
			expectTotalFiles:  1,
			expectValidFiles:  1,
			expectOutContains: []string{}, // No output in quiet mode
		},
		{
			name: "quiet mode - invalid files",
			files: map[string]string{
				"invalid.sql": "SELECT * FROM",
			},
			args:               []string{filepath.Join(tmpDir, "invalid.sql")},
			opts:               ValidatorOptions{Quiet: true},
			expectTotalFiles:   1,
			expectInvalidFiles: 1,
			expectOutContains:  []string{}, // No output in quiet mode
			expectErrContains:  []string{}, // No error output in quiet mode
		},
		{
			name: "stats mode",
			files: map[string]string{
				"query1.sql": "SELECT * FROM users",
				"query2.sql": "SELECT * FROM orders",
			},
			args: []string{
				filepath.Join(tmpDir, "query1.sql"),
				filepath.Join(tmpDir, "query2.sql"),
			},
			opts:              ValidatorOptions{ShowStats: true},
			expectTotalFiles:  2,
			expectValidFiles:  2,
			expectOutContains: []string{"📊", "Files processed: 2", "Valid files: 2", "Invalid files: 0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test files
			for filename, content := range tt.files {
				path := filepath.Join(tmpDir, filename)
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file %s: %v", filename, err)
				}
			}

			// Create validator with buffers
			var outBuf, errBuf bytes.Buffer
			validator := NewValidator(&outBuf, &errBuf, tt.opts)

			// Run validation
			result, err := validator.Validate(tt.args)

			// Check error
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			// Check result counts
			if result != nil {
				if result.TotalFiles != tt.expectTotalFiles {
					t.Errorf("Expected %d total files, got %d", tt.expectTotalFiles, result.TotalFiles)
				}
				if result.ValidFiles != tt.expectValidFiles {
					t.Errorf("Expected %d valid files, got %d", tt.expectValidFiles, result.ValidFiles)
				}
				if result.InvalidFiles != tt.expectInvalidFiles {
					t.Errorf("Expected %d invalid files, got %d", tt.expectInvalidFiles, result.InvalidFiles)
				}
			}

			// Check output
			outStr := outBuf.String()
			for _, expected := range tt.expectOutContains {
				if !strings.Contains(outStr, expected) {
					t.Errorf("Expected output to contain '%s', got: %s", expected, outStr)
				}
			}

			// Check error output
			errStr := errBuf.String()
			for _, expected := range tt.expectErrContains {
				if !strings.Contains(errStr, expected) {
					t.Errorf("Expected error output to contain '%s', got: %s", expected, errStr)
				}
			}

			// Cleanup test files
			for filename := range tt.files {
				os.Remove(filepath.Join(tmpDir, filename))
			}
		})
	}
}

// TestValidator_ExpandFileArgs tests file expansion (glob, directories)
func TestValidator_ExpandFileArgs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test directory structure
	subDir := filepath.Join(tmpDir, "subdir")
	os.Mkdir(subDir, 0755)

	// Create test files
	testFiles := []string{
		filepath.Join(tmpDir, "query1.sql"),
		filepath.Join(tmpDir, "query2.sql"),
		filepath.Join(tmpDir, "script.txt"),
		filepath.Join(subDir, "nested.sql"),
	}

	for _, file := range testFiles {
		os.WriteFile(file, []byte("SELECT 1"), 0644)
	}

	tests := []struct {
		name           string
		args           []string
		opts           ValidatorOptions
		expectFiles    int
		expectContains []string
	}{
		{
			name:           "single file",
			args:           []string{filepath.Join(tmpDir, "query1.sql")},
			opts:           ValidatorOptions{},
			expectFiles:    1,
			expectContains: []string{"query1.sql"},
		},
		{
			name:           "glob pattern - *.sql",
			args:           []string{filepath.Join(tmpDir, "*.sql")},
			opts:           ValidatorOptions{},
			expectFiles:    2,
			expectContains: []string{"query1.sql", "query2.sql"},
		},
		{
			name:           "recursive directory",
			args:           []string{tmpDir},
			opts:           ValidatorOptions{Recursive: true, Pattern: "*.sql"},
			expectFiles:    3,
			expectContains: []string{"query1.sql", "query2.sql", "nested.sql"},
		},
		{
			name: "multiple arguments",
			args: []string{
				filepath.Join(tmpDir, "query1.sql"),
				filepath.Join(tmpDir, "query2.sql"),
			},
			opts:           ValidatorOptions{},
			expectFiles:    2,
			expectContains: []string{"query1.sql", "query2.sql"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidator(os.Stdout, os.Stderr, tt.opts)
			files, err := validator.expandFileArgs(tt.args)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(files) != tt.expectFiles {
				t.Errorf("Expected %d files, got %d", tt.expectFiles, len(files))
			}

			for _, expected := range tt.expectContains {
				found := false
				for _, file := range files {
					if strings.Contains(file, expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected files to contain '%s', got: %v", expected, files)
				}
			}
		})
	}
}

// TestValidator_FormatBytes tests byte formatting
func TestValidator_FormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

// TestValidator_DisplayStats tests statistics display
func TestValidator_DisplayStats(t *testing.T) {
	var buf bytes.Buffer
	validator := NewValidator(&buf, &buf, ValidatorOptions{})

	result := &ValidationResult{
		TotalFiles:   10,
		ValidFiles:   8,
		InvalidFiles: 2,
		TotalBytes:   1024 * 1024, // 1 MB
		Duration:     1000000000,  // 1 second (in nanoseconds)
	}

	validator.displayStats(result)

	output := buf.String()
	expectedStrings := []string{
		"📊",
		"Files processed: 10",
		"Valid files: 8",
		"Invalid files: 2",
		"1.0 MB",
		"10.0 files/sec",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', got: %s", expected, output)
		}
	}
}

// TestValidator_NonExistentFile tests handling of non-existent files
func TestValidator_NonExistentFile(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	validator := NewValidator(&outBuf, &errBuf, ValidatorOptions{})

	result := validator.validateFile("/nonexistent/file.sql")

	if result.Error == nil {
		t.Error("Expected error for non-existent file")
	}

	if result.Valid {
		t.Error("Expected valid=false for non-existent file")
	}

	if !strings.Contains(result.Error.Error(), "file access validation failed") {
		t.Errorf("Expected 'file access validation failed' error, got: %v", result.Error)
	}
}

// TestValidator_PermissionDenied tests handling of permission-denied files
func TestValidator_PermissionDenied(t *testing.T) {
	// Skip on Windows as chmod doesn't work the same way
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission test on Windows - chmod behavior is different")
	}

	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "noperm.sql")

	// Create file
	if err := os.WriteFile(filename, []byte("SELECT 1"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Remove read permission
	if err := os.Chmod(filename, 0000); err != nil {
		t.Fatalf("Failed to chmod file: %v", err)
	}
	defer os.Chmod(filename, 0644) // Restore for cleanup

	var outBuf, errBuf bytes.Buffer
	validator := NewValidator(&outBuf, &errBuf, ValidatorOptions{})

	result := validator.validateFile(filename)

	if result.Error == nil {
		t.Error("Expected error for permission-denied file")
	}
}

// TestValidator_EmptyArgs tests handling of empty file arguments
func TestValidator_EmptyArgs(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	validator := NewValidator(&outBuf, &errBuf, ValidatorOptions{})

	_, err := validator.Validate([]string{})

	if err == nil {
		t.Error("Expected error for empty args")
	}

	if !strings.Contains(err.Error(), "no SQL files found") {
		t.Errorf("Expected 'no SQL files found' error, got: %v", err)
	}
}
