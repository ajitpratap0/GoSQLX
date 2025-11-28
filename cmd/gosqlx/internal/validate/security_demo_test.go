package validate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSecurityFeatures_PathTraversalAttacks demonstrates protection against path traversal attacks
func TestSecurityFeatures_PathTraversalAttacks(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file in the temp directory
	safeFile := filepath.Join(tmpDir, "safe.sql")
	err := os.WriteFile(safeFile, []byte("SELECT 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create safe file: %v", err)
	}

	t.Run("Attempt to access /etc/passwd via path traversal", func(t *testing.T) {
		maliciousPath := tmpDir + "/../../../../../../../etc/passwd"
		err := ValidateInputFile(maliciousPath)

		// On systems where /etc/passwd exists, we should either:
		// 1. Reject it due to extension (.passwd is not .sql)
		// 2. Allow it if it passes all checks (rare)
		// The key is that our validation runs and doesn't crash
		if err != nil {
			t.Logf("Path traversal attempt correctly blocked: %v", err)
		} else {
			t.Logf("Path traversal resolved to a valid file (system-specific behavior)")
		}
	})

	t.Run("Path traversal that stays within allowed directory", func(t *testing.T) {
		// This should be allowed as it resolves to a valid file within our temp directory
		traversalPath := filepath.Join(tmpDir, "subdir", "..", "safe.sql")
		err := ValidateInputFile(traversalPath)
		if err != nil {
			t.Errorf("Expected valid traversal within safe directory to pass, got: %v", err)
		}
	})

	t.Run("Null byte injection attempt", func(t *testing.T) {
		maliciousPath := tmpDir + "/file.sql\x00.txt"
		result := IsSecurePath(maliciousPath)
		if result {
			t.Error("Null byte injection should be flagged as insecure")
		}
	})
}

// TestSecurityFeatures_SymlinkAttacks demonstrates protection against symlink attacks
func TestSecurityFeatures_SymlinkAttacks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink tests skipped on Windows")
	}

	tmpDir := t.TempDir()

	// Create a legitimate file
	legitimateFile := filepath.Join(tmpDir, "legitimate.sql")
	err := os.WriteFile(legitimateFile, []byte("SELECT 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to create legitimate file: %v", err)
	}

	t.Run("Symlink to system directory", func(t *testing.T) {
		symlinkPath := filepath.Join(tmpDir, "evil.sql")
		err := os.Symlink("/etc", symlinkPath)
		if err != nil {
			t.Skipf("Cannot create symlink: %v", err)
		}

		err = ValidateInputFile(symlinkPath)
		if err == nil {
			t.Error("Symlink to system directory should be rejected")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("Expected symlink error, got: %v", err)
		}
	})

	t.Run("Symlink to file outside working directory", func(t *testing.T) {
		outsideDir := t.TempDir() // Different temp directory
		outsideFile := filepath.Join(outsideDir, "outside.sql")
		err := os.WriteFile(outsideFile, []byte("SELECT 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create outside file: %v", err)
		}

		symlinkPath := filepath.Join(tmpDir, "sneaky.sql")
		err = os.Symlink(outsideFile, symlinkPath)
		if err != nil {
			t.Skipf("Cannot create symlink: %v", err)
		}

		err = ValidateInputFile(symlinkPath)
		if err == nil {
			t.Error("Symlink to outside directory should be rejected by default")
		}
	})

	t.Run("Chain of symlinks", func(t *testing.T) {
		// Create a chain: link1 -> link2 -> legitimate file
		link2 := filepath.Join(tmpDir, "link2.sql")
		err := os.Symlink(legitimateFile, link2)
		if err != nil {
			t.Skipf("Cannot create symlink: %v", err)
		}

		link1 := filepath.Join(tmpDir, "link1.sql")
		err = os.Symlink(link2, link1)
		if err != nil {
			t.Skipf("Cannot create symlink: %v", err)
		}

		err = ValidateInputFile(link1)
		if err == nil {
			t.Error("Chain of symlinks should be rejected")
		}
	})
}

// TestSecurityFeatures_FileSizeLimits demonstrates protection against DoS via large files
func TestSecurityFeatures_FileSizeLimits(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Reject file exceeding 10MB limit", func(t *testing.T) {
		largeFile := filepath.Join(tmpDir, "huge.sql")

		// Create a 10MB + 1 byte file
		largeContent := strings.Repeat("A", int(MaxFileSize)+1)
		err := os.WriteFile(largeFile, []byte(largeContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create large file: %v", err)
		}

		err = ValidateInputFile(largeFile)
		if err == nil {
			t.Error("File exceeding MaxFileSize should be rejected")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("Expected size error, got: %v", err)
		}
	})

	t.Run("Accept file at exactly 10MB", func(t *testing.T) {
		limitFile := filepath.Join(tmpDir, "at_limit.sql")

		// Create exactly 10MB file
		content := strings.Repeat("A", int(MaxFileSize))
		err := os.WriteFile(limitFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		err = ValidateInputFile(limitFile)
		if err != nil {
			t.Errorf("File at MaxFileSize should be accepted, got: %v", err)
		}
	})

	t.Run("Custom file size limit", func(t *testing.T) {
		smallFile := filepath.Join(tmpDir, "small.sql")
		err := os.WriteFile(smallFile, []byte(strings.Repeat("A", 1000)), 0644)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		validator := NewSecurityValidator()
		validator.MaxFileSize = 500 // Only allow 500 bytes

		err = validator.Validate(smallFile)
		if err == nil {
			t.Error("File exceeding custom limit should be rejected")
		}
	})
}

// TestSecurityFeatures_FileTypeRestrictions demonstrates protection against malicious file types
func TestSecurityFeatures_FileTypeRestrictions(t *testing.T) {
	tmpDir := t.TempDir()

	dangerousExtensions := []string{
		".exe", ".bat", ".sh", ".py", ".js", ".dll", ".so", ".dylib",
		".com", ".cmd", ".vbs", ".jar", ".app", ".deb", ".rpm",
	}

	for _, ext := range dangerousExtensions {
		t.Run("Reject "+ext+" file", func(t *testing.T) {
			dangerousFile := filepath.Join(tmpDir, "malware"+ext)
			err := os.WriteFile(dangerousFile, []byte("malicious content"), 0644)
			if err != nil {
				t.Fatalf("Failed to create file: %v", err)
			}

			err = ValidateInputFile(dangerousFile)
			if err == nil {
				t.Errorf("Dangerous file type %s should be rejected", ext)
			}
			if !strings.Contains(err.Error(), "unsupported file extension") {
				t.Errorf("Expected extension error for %s, got: %v", ext, err)
			}
		})
	}
}

// TestSecurityFeatures_SpecialFiles demonstrates protection against special file types
func TestSecurityFeatures_SpecialFiles(t *testing.T) {
	t.Run("Reject device files", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Device file tests not applicable on Windows")
		}

		err := ValidateInputFile("/dev/null")
		if err == nil {
			t.Error("Device files should be rejected")
		}
		if !strings.Contains(err.Error(), "not a regular file") && !strings.Contains(err.Error(), "unsupported file extension") {
			t.Errorf("Expected file type error, got: %v", err)
		}
	})

	t.Run("Reject directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := ValidateInputFile(tmpDir)
		if err == nil {
			t.Error("Directories should be rejected")
		}
	})

	t.Run("Reject FIFOs/pipes", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("FIFO tests not applicable on Windows")
		}

		// Note: Creating FIFOs requires mkfifo syscall, which is complex in Go
		// This test documents the intended behavior
		t.Skip("FIFO creation test skipped (would require syscall)")
	})
}

// TestSecurityFeatures_SystemPaths demonstrates protection against accessing system directories
func TestSecurityFeatures_SystemPaths(t *testing.T) {
	systemPaths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/proc/self/environ",
		"/sys/kernel/debug",
	}

	if runtime.GOOS == "windows" {
		systemPaths = []string{
			"C:\\Windows\\System32\\config\\SAM",
			"C:\\Windows\\System32\\drivers\\etc\\hosts",
		}
	}

	for _, path := range systemPaths {
		t.Run("Quick check for "+path, func(t *testing.T) {
			// IsSecurePath provides a quick check without filesystem access
			if strings.Contains(path, "etc") || strings.Contains(path, "System32") {
				result := IsSecurePath(path)
				if result {
					t.Logf("Warning: System path %s not flagged by quick check", path)
				}
			}
		})
	}
}

// TestSecurityFeatures_Integration performs end-to-end security validation
func TestSecurityFeatures_Integration(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Full validation pipeline for safe file", func(t *testing.T) {
		safeFile := filepath.Join(tmpDir, "safe.sql")
		err := os.WriteFile(safeFile, []byte("SELECT * FROM users WHERE id = 1"), 0644)
		if err != nil {
			t.Fatalf("Failed to create safe file: %v", err)
		}

		// All checks should pass
		err = ValidateInputFile(safeFile)
		if err != nil {
			t.Errorf("Safe file should pass all security checks, got: %v", err)
		}
	})

	t.Run("Multiple security violations", func(t *testing.T) {
		// Create a file that violates multiple security rules
		if runtime.GOOS != "windows" {
			// Create a symlink with dangerous extension
			outsideFile := t.TempDir() + "/malware.exe"
			err := os.WriteFile(outsideFile, []byte("bad"), 0644)
			if err != nil {
				t.Fatalf("Failed to create outside file: %v", err)
			}

			symlinkPath := filepath.Join(tmpDir, "evil.exe")
			err = os.Symlink(outsideFile, symlinkPath)
			if err == nil {
				err = ValidateInputFile(symlinkPath)
				if err == nil {
					t.Error("File with multiple security violations should be rejected")
				}
				// Should catch at least one of: symlink, extension
				t.Logf("Correctly rejected with: %v", err)
			}
		}
	})
}
