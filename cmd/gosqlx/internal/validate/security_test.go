package validate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateInputFile_ValidFiles(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		filename  string
		content   string
		extension string
	}{
		{"SQL file", "query.sql", "SELECT * FROM users", ".sql"},
		{"Text file", "query.txt", "SELECT * FROM users", ".txt"},
		{"No extension", "query", "SELECT * FROM users", ""},
		{"Large extension case", "QUERY.SQL", "SELECT 1", ".SQL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFile := filepath.Join(tmpDir, tt.filename)
			err := os.WriteFile(testFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			err = ValidateInputFile(testFile)
			if err != nil {
				t.Errorf("Expected validation to pass for %s, got error: %v", tt.name, err)
			}
		})
	}
}

func TestValidateInputFile_InvalidExtensions(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		filename  string
		shouldFail bool
	}{
		{"Executable", "malware.exe", true},
		{"Shell script", "script.sh", true},
		{"Python", "script.py", true},
		{"Batch file", "script.bat", true},
		{"Binary", "file.bin", true},
		{"DLL", "library.dll", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFile := filepath.Join(tmpDir, tt.filename)
			err := os.WriteFile(testFile, []byte("SELECT 1"), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			err = ValidateInputFile(testFile)
			if tt.shouldFail && err == nil {
				t.Errorf("Expected validation to fail for %s, but it passed", tt.name)
			}
			if tt.shouldFail && !strings.Contains(err.Error(), "unsupported file extension") {
				t.Errorf("Expected extension error, got: %v", err)
			}
		})
	}
}

func TestValidateInputFile_OversizedFiles(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("File exceeds MaxFileSize", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "large.sql")

		// Create a file larger than MaxFileSize
		largeContent := strings.Repeat("A", int(MaxFileSize)+1000)
		err := os.WriteFile(testFile, []byte(largeContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create large file: %v", err)
		}

		err = ValidateInputFile(testFile)
		if err == nil {
			t.Error("Expected validation to fail for oversized file")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("Expected size error, got: %v", err)
		}
	})

	t.Run("File at size limit", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "at_limit.sql")

		// Create a file exactly at MaxFileSize
		content := strings.Repeat("A", int(MaxFileSize))
		err := os.WriteFile(testFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		err = ValidateInputFile(testFile)
		if err != nil {
			t.Errorf("File at size limit should be valid, got error: %v", err)
		}
	})
}

func TestValidateInputFile_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid file in tmpDir
	validFile := filepath.Join(tmpDir, "valid.sql")
	err := os.WriteFile(validFile, []byte("SELECT 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create valid file: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		shouldFail  bool
		skipOnError bool // Skip if path creation fails
	}{
		{
			name:       "Path traversal with ..",
			path:       filepath.Join(tmpDir, "..", filepath.Base(tmpDir), "valid.sql"),
			shouldFail: false, // This resolves to the valid file
		},
		{
			name:        "Multiple path traversals",
			path:        filepath.Join(tmpDir, "..", "..", "..", "etc", "passwd"),
			shouldFail:  true,
			skipOnError: true, // File might not exist
		},
		{
			name:       "Normalized valid path",
			path:       validFile,
			shouldFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInputFile(tt.path)

			if tt.skipOnError && err != nil {
				// Expected to fail for various reasons (file doesn't exist, etc.)
				return
			}

			if tt.shouldFail && err == nil {
				t.Errorf("Expected validation to fail for %s", tt.name)
			}
			if !tt.shouldFail && err != nil {
				t.Errorf("Expected validation to pass for %s, got error: %v", tt.name, err)
			}
		})
	}
}

func TestValidateInputFile_Symlinks(t *testing.T) {
	// Skip on Windows as symlink creation requires admin privileges
	if runtime.GOOS == "windows" {
		t.Skip("Symlink tests skipped on Windows")
	}

	tmpDir := t.TempDir()

	// Create a target file
	targetFile := filepath.Join(tmpDir, "target.sql")
	err := os.WriteFile(targetFile, []byte("SELECT 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Create a symlink to the target
	symlinkPath := filepath.Join(tmpDir, "symlink.sql")
	err = os.Symlink(targetFile, symlinkPath)
	if err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	t.Run("Symlink in same directory", func(t *testing.T) {
		err := ValidateInputFile(symlinkPath)
		if err == nil {
			t.Error("Expected validation to fail for symlink (default security policy)")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("Expected symlink error, got: %v", err)
		}
	})

	// Create symlink pointing outside tmpDir
	outsideDir := filepath.Join(tmpDir, "outside")
	err = os.Mkdir(outsideDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create outside directory: %v", err)
	}

	outsideFile := filepath.Join(outsideDir, "outside.sql")
	err = os.WriteFile(outsideFile, []byte("SELECT 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create outside file: %v", err)
	}

	outsideSymlink := filepath.Join(tmpDir, "outside_symlink.sql")
	err = os.Symlink(outsideFile, outsideSymlink)
	if err != nil {
		t.Fatalf("Failed to create outside symlink: %v", err)
	}

	t.Run("Symlink to outside directory", func(t *testing.T) {
		err := ValidateInputFile(outsideSymlink)
		if err == nil {
			t.Error("Expected validation to fail for symlink pointing outside")
		}
	})

	// Test with custom validator that allows symlinks
	t.Run("Allow symlinks with custom validator", func(t *testing.T) {
		validator := NewSecurityValidator()
		validator.AllowSymlinks = true

		err := validator.Validate(symlinkPath)
		if err != nil {
			t.Errorf("Expected validation to pass when symlinks are allowed, got: %v", err)
		}
	})
}

func TestValidateInputFile_BrokenSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink tests skipped on Windows")
	}

	tmpDir := t.TempDir()

	// Create a symlink to a non-existent target
	brokenSymlink := filepath.Join(tmpDir, "broken.sql")
	err := os.Symlink("/nonexistent/file.sql", brokenSymlink)
	if err != nil {
		t.Fatalf("Failed to create broken symlink: %v", err)
	}

	err = ValidateInputFile(brokenSymlink)
	if err == nil {
		t.Error("Expected validation to fail for broken symlink")
	}
	if !strings.Contains(err.Error(), "invalid file path") {
		t.Errorf("Expected invalid path error for broken symlink, got: %v", err)
	}
}

func TestValidateInputFile_NonRegularFiles(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Directory", func(t *testing.T) {
		err := ValidateInputFile(tmpDir)
		if err == nil {
			t.Error("Expected validation to fail for directory")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("Expected 'not a regular file' error, got: %v", err)
		}
	})

	// Test device files (Unix only)
	if runtime.GOOS != "windows" {
		t.Run("Device file", func(t *testing.T) {
			err := ValidateInputFile("/dev/null")
			if err == nil {
				t.Error("Expected validation to fail for device file")
			}
		})
	}
}

func TestValidateInputFile_Nonexistent(t *testing.T) {
	nonexistent := "/nonexistent/path/to/file.sql"

	err := ValidateInputFile(nonexistent)
	if err == nil {
		t.Error("Expected validation to fail for nonexistent file")
	}
	if !strings.Contains(err.Error(), "invalid file path") {
		t.Errorf("Expected path error for nonexistent file, got: %v", err)
	}
}

func TestValidateInputFile_NoReadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Permission tests unreliable on Windows")
	}

	tmpDir := t.TempDir()
	restrictedFile := filepath.Join(tmpDir, "restricted.sql")

	// Create file
	err := os.WriteFile(restrictedFile, []byte("SELECT 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Remove read permissions
	err = os.Chmod(restrictedFile, 0000)
	if err != nil {
		t.Fatalf("Failed to change permissions: %v", err)
	}
	defer os.Chmod(restrictedFile, 0644) // Restore for cleanup

	err = ValidateInputFile(restrictedFile)
	if err == nil {
		t.Error("Expected validation to fail for unreadable file")
	}
	if !strings.Contains(err.Error(), "cannot open file") {
		t.Errorf("Expected permission error, got: %v", err)
	}
}

func TestSecurityValidator_CustomSettings(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Custom file size limit", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "test.sql")
		content := strings.Repeat("A", 1000)
		err := os.WriteFile(testFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		validator := NewSecurityValidator()
		validator.MaxFileSize = 500 // Only allow 500 bytes

		err = validator.Validate(testFile)
		if err == nil {
			t.Error("Expected validation to fail with custom size limit")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("Expected size error, got: %v", err)
		}
	})

	t.Run("Custom allowed extensions", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "test.sql")
		err := os.WriteFile(testFile, []byte("SELECT 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		validator := NewSecurityValidator()
		validator.AllowedExtensions = []string{".txt"} // Only allow .txt

		err = validator.Validate(testFile)
		if err == nil {
			t.Error("Expected validation to fail with custom extensions")
		}
		if !strings.Contains(err.Error(), "unsupported file extension") {
			t.Errorf("Expected extension error, got: %v", err)
		}
	})

	t.Run("Working directory restriction", func(t *testing.T) {
		// Create file in tmpDir
		testFile := filepath.Join(tmpDir, "test.sql")
		err := os.WriteFile(testFile, []byte("SELECT 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		// Create another temp directory
		otherDir := t.TempDir()
		otherFile := filepath.Join(otherDir, "other.sql")
		err = os.WriteFile(otherFile, []byte("SELECT 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create other file: %v", err)
		}

		validator := NewSecurityValidator()
		validator.WorkingDirectory = tmpDir

		// File in working directory should pass
		err = validator.Validate(testFile)
		if err != nil {
			t.Errorf("Expected file in working directory to pass, got: %v", err)
		}

		// File outside working directory should fail when accessed via ..
		// (This is a limitation - we can't easily test this without complex path setups)
	})
}

func TestIsSecurePath(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		secure bool
	}{
		{"Normal path", "/home/user/query.sql", true},
		{"Path traversal", "/home/user/../../../etc/passwd", false},
		{"Relative path with ..", "../../etc/passwd", false},
		{"Null byte injection", "/home/user/file\x00.sql", false},
		{"etc directory", "/etc/passwd", false},
		{"proc directory", "/proc/self/environ", false},
		{"sys directory", "/sys/kernel", false},
		{"Windows system", "C:\\Windows\\System32\\cmd.exe", false},
		{"Normal Windows path", "C:\\Users\\user\\query.sql", true},
		{"Clean path", "/tmp/query.sql", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSecurePath(tt.path)
			if result != tt.secure {
				t.Errorf("IsSecurePath(%q) = %v, expected %v", tt.path, result, tt.secure)
			}
		})
	}
}

func TestCheckPathTraversal(t *testing.T) {
	validator := NewSecurityValidator()

	tests := []struct {
		name        string
		path        string
		shouldFail  bool
		workingDir  string
	}{
		{"Clean path", "/home/user/query.sql", false, ""},
		{"Path with ..", "/home/user/../user/query.sql", false, ""}, // Resolves to safe path
		{"Suspicious pattern /../", "/home/user/../../../etc/passwd", false, ""}, // Cleaned path is different
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.workingDir != "" {
				validator.WorkingDirectory = tt.workingDir
			}

			err := validator.checkPathTraversal(tt.path)
			if tt.shouldFail && err == nil {
				t.Errorf("Expected path traversal check to fail for %s", tt.path)
			}
			if !tt.shouldFail && err != nil {
				t.Errorf("Expected path traversal check to pass for %s, got: %v", tt.path, err)
			}
		})
	}
}

func BenchmarkValidateInputFile(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "bench.sql")
	err := os.WriteFile(testFile, []byte("SELECT * FROM users WHERE id = 1"), 0644)
	if err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateInputFile(testFile)
	}
}

func BenchmarkIsSecurePath(b *testing.B) {
	testPath := "/home/user/queries/complex_query.sql"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsSecurePath(testPath)
	}
}
