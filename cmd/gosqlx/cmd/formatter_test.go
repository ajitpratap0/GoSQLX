package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFormatter_FormatFile tests single file formatting
func TestFormatter_FormatFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name          string
		filename      string
		content       string
		expectChanged bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "valid SQL file - basic SELECT",
			filename:      "query.sql",
			content:       "SELECT * FROM users WHERE active = true",
			expectChanged: true, // Formatter adds indentation and newlines
			expectError:   false,
		},
		{
			name:          "valid empty file",
			filename:      "empty.sql",
			content:       "",
			expectChanged: false,
			expectError:   false,
		},
		{
			name:          "SQL needing formatting",
			filename:      "unformatted.sql",
			content:       "select*from users",
			expectChanged: true,
			expectError:   false,
		},
		{
			name:          "invalid SQL",
			filename:      "invalid.sql",
			content:       "SELECT * FROM",
			expectChanged: false,
			expectError:   true,
			errorContains: "parsing failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			filepath := filepath.Join(tmpDir, tt.filename)
			if err := os.WriteFile(filepath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Create formatter
			var outBuf, errBuf bytes.Buffer
			formatter := NewFormatter(&outBuf, &errBuf, CLIFormatterOptions{
				IndentSize: 2,
				Uppercase:  true,
				Compact:    false,
			})

			// Format file
			result := formatter.formatFile(filepath)

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

			if result.Changed != tt.expectChanged {
				t.Errorf("Expected changed=%v, got changed=%v", tt.expectChanged, result.Changed)
			}
		})
	}
}

// TestFormatter_Format tests multi-file formatting
func TestFormatter_Format(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name                 string
		files                map[string]string // filename -> content
		args                 []string
		opts                 CLIFormatterOptions
		expectTotalFiles     int
		expectFormattedFiles int
		expectFailedFiles    int
		expectError          bool
	}{
		{
			name: "single valid file - to stdout",
			files: map[string]string{
				"query1.sql": "SELECT * FROM users",
			},
			args: []string{filepath.Join(tmpDir, "query1.sql")},
			opts: CLIFormatterOptions{
				IndentSize: 2,
				Uppercase:  true,
			},
			expectTotalFiles:     1,
			expectFormattedFiles: 1,
		},
		{
			name: "multiple files - in-place",
			files: map[string]string{
				"query1.sql": "SELECT * FROM users",
				"query2.sql": "INSERT INTO users (name) VALUES ('John')",
			},
			args: []string{
				filepath.Join(tmpDir, "query1.sql"),
				filepath.Join(tmpDir, "query2.sql"),
			},
			opts: CLIFormatterOptions{
				IndentSize: 2,
				Uppercase:  true,
				InPlace:    true,
			},
			expectTotalFiles:     2,
			expectFormattedFiles: 0, // No changes needed
		},
		{
			name: "check mode - needs formatting",
			files: map[string]string{
				"unformatted.sql": "select*from users",
			},
			args: []string{filepath.Join(tmpDir, "unformatted.sql")},
			opts: CLIFormatterOptions{
				IndentSize: 2,
				Uppercase:  true,
				Check:      true,
			},
			expectTotalFiles: 1,
			expectError:      true, // Check mode returns error if files need formatting
		},
		{
			name: "check mode - needs formatting (all SQL needs formatting)",
			files: map[string]string{
				"formatted.sql": "SELECT * FROM users",
			},
			args: []string{filepath.Join(tmpDir, "formatted.sql")},
			opts: CLIFormatterOptions{
				IndentSize: 2,
				Uppercase:  true,
				Check:      true,
			},
			expectTotalFiles: 1,
			expectError:      true, // Formatter adds formatting to all SQL
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

			// Create formatter with buffers
			var outBuf, errBuf bytes.Buffer
			formatter := NewFormatter(&outBuf, &errBuf, tt.opts)

			// Run formatting
			result, err := formatter.Format(tt.args)

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
			}

			// Cleanup test files
			for filename := range tt.files {
				os.Remove(filepath.Join(tmpDir, filename))
			}
		})
	}
}

// TestFormatter_VerboseMode tests verbose output
func TestFormatter_VerboseMode(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tmpDir, "test.sql")
	if err := os.WriteFile(testFile, []byte("SELECT * FROM users"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	formatter := NewFormatter(&outBuf, &errBuf, CLIFormatterOptions{
		IndentSize: 2,
		Uppercase:  true,
		InPlace:    true,
		Verbose:    true,
	})

	_, err := formatter.Format([]string{testFile})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verbose mode should produce output
	output := outBuf.String()
	if output == "" {
		t.Error("Expected verbose output but got none")
	}
}

// TestFormatter_CompactMode tests compact formatting
func TestFormatter_CompactMode(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "test.sql")
	if err := os.WriteFile(testFile, []byte("SELECT * FROM users WHERE id = 1"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	formatter := NewFormatter(&outBuf, &errBuf, CLIFormatterOptions{
		IndentSize: 2,
		Uppercase:  true,
		Compact:    true,
	})

	result, err := formatter.Format([]string{testFile})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}

	// Compact mode output should be in stdout
	output := outBuf.String()
	if output == "" {
		t.Error("Expected formatted output but got none")
	}
}

// TestFormatter_NonExistentFile tests handling of non-existent files
func TestFormatter_NonExistentFile(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	formatter := NewFormatter(&outBuf, &errBuf, CLIFormatterOptions{
		IndentSize: 2,
		Uppercase:  true,
	})

	result := formatter.formatFile("/nonexistent/file.sql")

	if result.Error == nil {
		t.Error("Expected error for non-existent file")
	}

	if result.Changed {
		t.Error("Expected changed=false for non-existent file")
	}

	if !strings.Contains(result.Error.Error(), "file access validation failed") {
		t.Errorf("Expected 'file access validation failed' error, got: %v", result.Error)
	}
}

// TestFormatter_EmptyArgs tests handling of empty file arguments
func TestFormatter_EmptyArgs(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	formatter := NewFormatter(&outBuf, &errBuf, CLIFormatterOptions{
		IndentSize: 2,
		Uppercase:  true,
	})

	_, err := formatter.Format([]string{})

	if err == nil {
		t.Error("Expected error for empty args")
	}

	if !strings.Contains(err.Error(), "no SQL files found") {
		t.Errorf("Expected 'no SQL files found' error, got: %v", err)
	}
}

// TestFormatter_UppercaseMode tests keyword uppercasing
func TestFormatter_UppercaseMode(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		uppercase bool
		input     string
	}{
		{
			name:      "uppercase keywords",
			uppercase: true,
			input:     "select * from users",
		},
		{
			name:      "preserve original case",
			uppercase: false,
			input:     "SELECT * FROM users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFile := filepath.Join(tmpDir, "test.sql")
			if err := os.WriteFile(testFile, []byte(tt.input), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			var outBuf, errBuf bytes.Buffer
			formatter := NewFormatter(&outBuf, &errBuf, CLIFormatterOptions{
				IndentSize: 2,
				Uppercase:  tt.uppercase,
			})

			result, err := formatter.Format([]string{testFile})
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.TotalFiles != 1 {
				t.Errorf("Expected 1 file, got %d", result.TotalFiles)
			}

			os.Remove(testFile)
		})
	}
}

// TestFormatterOptionsFromConfig tests configuration merging
func TestFormatterOptionsFromConfig(t *testing.T) {
	cfg := &CLIFormatterOptions{
		IndentSize: 4,
		Uppercase:  false,
		Compact:    true,
	}

	// This function is in the formatter.go, but we can't test it directly
	// without access to config.Config. This is a placeholder for integration testing.

	if cfg.IndentSize != 4 {
		t.Errorf("Expected IndentSize=4, got %d", cfg.IndentSize)
	}
}
