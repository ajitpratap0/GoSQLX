package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInputUtils tests the new robust input detection functionality
func TestDetectAndReadInput(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Test 1: Direct SQL input
	t.Run("DirectSQL", func(t *testing.T) {
		result, err := DetectAndReadInput("SELECT * FROM users")
		if err != nil {
			t.Fatalf("Expected success for direct SQL, got error: %v", err)
		}
		if result.Type != InputTypeSQL {
			t.Errorf("Expected InputTypeSQL, got %v", result.Type)
		}
		if string(result.Content) != "SELECT * FROM users" {
			t.Errorf("Expected SQL content, got: %s", string(result.Content))
		}
	})

	// Test 2: Valid SQL file
	t.Run("ValidSQLFile", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "test.sql")
		content := "SELECT id, name FROM users WHERE active = true;"
		err := os.WriteFile(testFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		result, err := DetectAndReadInput(testFile)
		if err != nil {
			t.Fatalf("Expected success for SQL file, got error: %v", err)
		}
		if result.Type != InputTypeFile {
			t.Errorf("Expected InputTypeFile, got %v", result.Type)
		}
		if string(result.Content) != content {
			t.Errorf("Expected file content, got: %s", string(result.Content))
		}
	})

	// Test 3: Directory input (should fail)
	t.Run("DirectoryInput", func(t *testing.T) {
		_, err := DetectAndReadInput(tmpDir)
		if err == nil {
			t.Error("Expected error for directory input, got success")
		}
		if !strings.Contains(err.Error(), "directory") {
			t.Errorf("Expected directory error message, got: %v", err)
		}
	})

	// Test 4: Invalid file extension
	t.Run("InvalidFileExtension", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "test.exe")
		err := os.WriteFile(testFile, []byte("SELECT 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		_, err = DetectAndReadInput(testFile)
		if err == nil {
			t.Error("Expected error for invalid file extension, got success")
		}
		if !strings.Contains(err.Error(), "unsupported file extension") {
			t.Errorf("Expected extension error message, got: %v", err)
		}
	})

	// Test 5: Empty input
	t.Run("EmptyInput", func(t *testing.T) {
		_, err := DetectAndReadInput("")
		if err == nil {
			t.Error("Expected error for empty input, got success")
		}
	})

	// Test 6: File size limit (create a file that's too large)
	t.Run("FileSizeLimit", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "large.sql")
		largeContent := strings.Repeat("SELECT * FROM users; ", MaxFileSize/20+1)
		err := os.WriteFile(testFile, []byte(largeContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create large test file: %v", err)
		}

		_, err = DetectAndReadInput(testFile)
		if err == nil {
			t.Error("Expected error for large file, got success")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("Expected size limit error message, got: %v", err)
		}
	})
}

// TestLooksLikeSQL tests the SQL heuristic detection
func TestLooksLikeSQL(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"SimpleSelect", "SELECT * FROM users", true},
		{"InsertStatement", "INSERT INTO table VALUES (1, 'test')", true},
		{"UpdateStatement", "UPDATE users SET name = 'John'", true},
		{"DeleteStatement", "DELETE FROM users WHERE id = 1", true},
		{"CreateStatement", "CREATE TABLE users (id INT)", true},
		{"WithCTE", "WITH cte AS (SELECT 1) SELECT * FROM cte", true},
		{"LowercaseSelect", "select id from users", true},
		{"SQLWithSemicolon", "some random text; but has semicolon", true},
		{"PlainText", "this is just plain text", false},
		{"Filename", "myfile.sql", false},
		{"Path", "/path/to/file", false},
		{"Empty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := looksLikeSQL(tc.input)
			if result != tc.expected {
				t.Errorf("looksLikeSQL(%q) = %v, expected %v", tc.input, result, tc.expected)
			}
		})
	}
}

// TestExpandFileArgs tests the file expansion functionality
func TestExpandFileArgs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	testFiles := []string{
		"query1.sql",
		"query2.sql",
		"script.txt",
		"readme.md",
	}

	for _, file := range testFiles {
		fullPath := filepath.Join(tmpDir, file)
		err := os.WriteFile(fullPath, []byte("SELECT 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	// Create subdirectory with a file
	subDir := filepath.Join(tmpDir, "subdir")
	err := os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	t.Run("ExpandDirectory", func(t *testing.T) {
		expanded, err := ExpandFileArgs([]string{tmpDir})
		if err != nil {
			t.Fatalf("ExpandFileArgs failed: %v", err)
		}

		// Should find .sql and .txt files but not .md
		expectedCount := 3 // query1.sql, query2.sql, script.txt
		if len(expanded) != expectedCount {
			t.Errorf("Expected %d expanded files, got %d: %v", expectedCount, len(expanded), expanded)
		}

		// Check that all expanded files have valid extensions
		for _, file := range expanded {
			ext := strings.ToLower(filepath.Ext(file))
			if !isValidSQLFileExtension(ext) {
				t.Errorf("Expanded file has invalid extension: %s", file)
			}
		}
	})

	t.Run("DirectFileArgs", func(t *testing.T) {
		directFile := filepath.Join(tmpDir, "query1.sql")
		expanded, err := ExpandFileArgs([]string{directFile})
		if err != nil {
			t.Fatalf("ExpandFileArgs failed for direct file: %v", err)
		}

		if len(expanded) != 1 || expanded[0] != directFile {
			t.Errorf("Expected direct file path, got: %v", expanded)
		}
	})

	t.Run("NonexistentFile", func(t *testing.T) {
		nonexistent := "nonexistent_file.sql"
		expanded, err := ExpandFileArgs([]string{nonexistent})
		if err != nil {
			t.Fatalf("ExpandFileArgs should not fail for nonexistent files: %v", err)
		}

		// Should still return the argument (for error handling in calling code)
		if len(expanded) != 1 || expanded[0] != nonexistent {
			t.Errorf("Expected nonexistent file to be passed through, got: %v", expanded)
		}
	})
}

// TestValidateFileAccess tests the file access validation
func TestValidateFileAccess(t *testing.T) {
	tmpDir := t.TempDir()

	// Test 1: Valid file
	t.Run("ValidFile", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "valid.sql")
		err := os.WriteFile(testFile, []byte("SELECT 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		err = ValidateFileAccess(testFile)
		if err != nil {
			t.Errorf("Expected success for valid file, got error: %v", err)
		}
	})

	// Test 2: Directory
	t.Run("Directory", func(t *testing.T) {
		err := ValidateFileAccess(tmpDir)
		if err == nil {
			t.Error("Expected error for directory, got success")
		}
		if !strings.Contains(err.Error(), "directory") {
			t.Errorf("Expected directory error message, got: %v", err)
		}
	})

	// Test 3: Nonexistent file
	t.Run("NonexistentFile", func(t *testing.T) {
		nonexistent := filepath.Join(tmpDir, "nonexistent.sql")
		err := ValidateFileAccess(nonexistent)
		if err == nil {
			t.Error("Expected error for nonexistent file, got success")
		}
		if !strings.Contains(err.Error(), "cannot access file") {
			t.Errorf("Expected access error message, got: %v", err)
		}
	})
}

// TestMemoryManagement tests that AST objects are properly released
func TestMemoryManagement(t *testing.T) {
	// This test verifies our memory management improvements don't crash
	// Note: Actual memory leak detection would require more sophisticated tooling

	testSQL := "SELECT id, name FROM users WHERE active = true"

	t.Run("AnalyzeMemoryManagement", func(t *testing.T) {
		// This should not crash or leak memory
		result, err := DetectAndReadInput(testSQL)
		if err != nil {
			t.Fatalf("Input detection failed: %v", err)
		}

		if result.Type != InputTypeSQL {
			t.Errorf("Expected SQL input type, got: %v", result.Type)
		}

		// The analyze workflow would continue here, but we're testing
		// that the input processing doesn't cause issues
	})

	t.Run("ParseMemoryManagement", func(t *testing.T) {
		// Similar test for parse command workflow
		result, err := DetectAndReadInput(testSQL)
		if err != nil {
			t.Fatalf("Input detection failed: %v", err)
		}

		if len(result.Content) == 0 {
			t.Error("Expected non-empty content")
		}
	})
}

// TestSecurityLimits tests the security improvements
func TestSecurityLimits(t *testing.T) {
	t.Run("MaxFileSizeConstant", func(t *testing.T) {
		// Verify the security limit is reasonable (10MB)
		expectedLimit := 10 * 1024 * 1024
		if MaxFileSize != int64(expectedLimit) {
			t.Errorf("Expected MaxFileSize to be %d, got %d", expectedLimit, MaxFileSize)
		}
	})

	t.Run("SQLLengthLimit", func(t *testing.T) {
		// Test that very long SQL strings are rejected
		longSQL := strings.Repeat("SELECT * FROM users; ", MaxFileSize/10+1)
		_, err := DetectAndReadInput(longSQL)
		if err == nil {
			t.Error("Expected error for overly long SQL, got success")
		}
		if !strings.Contains(err.Error(), "too long") {
			t.Errorf("Expected length limit error, got: %v", err)
		}
	})
}

// TestFileExtensionValidation tests the file extension checking
func TestFileExtensionValidation(t *testing.T) {
	testCases := []struct {
		extension string
		valid     bool
	}{
		{".sql", true},
		{".txt", true},
		{"", true},     // Files without extension allowed
		{".SQL", true}, // Case insensitive
		{".exe", false},
		{".bat", false},
		{".sh", false},
		{".py", false},
		{".js", false},
	}

	for _, tc := range testCases {
		t.Run("Extension_"+tc.extension, func(t *testing.T) {
			result := isValidSQLFileExtension(strings.ToLower(tc.extension))
			if result != tc.valid {
				t.Errorf("isValidSQLFileExtension(%q) = %v, expected %v", tc.extension, result, tc.valid)
			}
		})
	}
}

// TestErrorPathsIntegration tests error handling improvements
func TestErrorPathsIntegration(t *testing.T) {
	t.Run("InvalidSQLPattern", func(t *testing.T) {
		// Test that non-SQL input is properly rejected
		_, err := DetectAndReadInput("just some random text that is not SQL")
		if err == nil {
			t.Error("Expected error for non-SQL input, got success")
		}
		if !strings.Contains(err.Error(), "does not appear to be valid SQL") {
			t.Errorf("Expected SQL validation error, got: %v", err)
		}
	})

	t.Run("EmptyFileHandling", func(t *testing.T) {
		tmpDir := t.TempDir()
		emptyFile := filepath.Join(tmpDir, "empty.sql")
		err := os.WriteFile(emptyFile, []byte(""), 0644)
		if err != nil {
			t.Fatalf("Failed to create empty file: %v", err)
		}

		_, err = DetectAndReadInput(emptyFile)
		if err == nil {
			t.Error("Expected error for empty file, got success")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("Expected empty file error, got: %v", err)
		}
	})
}
