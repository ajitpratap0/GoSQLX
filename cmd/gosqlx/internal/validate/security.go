package validate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxFileSize limits file size to prevent DoS attacks (10MB)
	MaxFileSize = 10 * 1024 * 1024
)

// SecurityValidator provides comprehensive file security validation
type SecurityValidator struct {
	MaxFileSize       int64
	AllowedExtensions []string
	AllowSymlinks     bool
	WorkingDirectory  string // Optional: restrict to working directory
}

// NewSecurityValidator creates a validator with default security settings
func NewSecurityValidator() *SecurityValidator {
	return &SecurityValidator{
		MaxFileSize:       MaxFileSize,
		AllowedExtensions: []string{".sql", ".txt", ""},
		AllowSymlinks:     false,
		WorkingDirectory:  "",
	}
}

// ValidateInputFile performs comprehensive security validation on a file path
func ValidateInputFile(path string) error {
	validator := NewSecurityValidator()
	return validator.Validate(path)
}

// Validate performs comprehensive security checks on a file path
func (v *SecurityValidator) Validate(path string) error {
	// 1. Check for path traversal attempts BEFORE resolving symlinks
	// This is critical - we must check the original path for ".." sequences
	// before they get normalized away by EvalSymlinks
	if err := v.checkPathTraversal(path); err != nil {
		return err
	}

	// 2. Resolve symlinks and get real path
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Check if it's a symlink error vs file not found
		if _, statErr := os.Lstat(path); statErr == nil {
			// File exists but symlink resolution failed
			return fmt.Errorf("invalid file path (broken symlink): %w", err)
		}
		return fmt.Errorf("invalid file path: %w", err)
	}

	// 3. Check if symlink points to different location (potential security issue)
	if !v.AllowSymlinks {
		// Use Lstat to detect symlinks without following them
		linkInfo, err := os.Lstat(path)
		if err != nil {
			// If Lstat fails, continue with regular validation
			// The file might not exist or we don't have permissions
		} else if linkInfo.Mode()&os.ModeSymlink != 0 {
			// This is an actual symlink (not just path normalization)
			return fmt.Errorf("symlinks are not allowed for security reasons: %s -> %s", path, realPath)
		}
	}

	// 4. Get file info
	info, err := os.Stat(realPath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}

	// 5. Check it's a regular file (not directory, device, socket, etc.)
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s (mode: %s)", path, info.Mode())
	}

	// 6. Check file size
	if info.Size() > v.MaxFileSize {
		return fmt.Errorf("file too large: %d bytes (max %d bytes)", info.Size(), v.MaxFileSize)
	}

	// 7. Validate file extension
	if err := v.validateExtension(realPath); err != nil {
		return err
	}

	// 8. Test read permissions
	file, err := os.Open(realPath)
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	file.Close()

	return nil
}

// checkPathTraversal detects path traversal attempts
func (v *SecurityValidator) checkPathTraversal(path string) error {
	// Clean the path
	cleanPath := filepath.Clean(path)

	// Get absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute path: %w", err)
	}

	// Check for suspicious patterns containing ".."
	if strings.Contains(path, "..") {
		// Verify the cleaned path doesn't escape intended boundaries
		if v.WorkingDirectory != "" {
			workDir, err := filepath.Abs(v.WorkingDirectory)
			if err != nil {
				return fmt.Errorf("cannot resolve working directory: %w", err)
			}

			if !strings.HasPrefix(absPath, workDir) {
				return fmt.Errorf("path traversal detected: path escapes working directory")
			}
		} else {
			// When no WorkingDirectory is set, count the number of ".." sequences
			// Multiple ".." sequences are suspicious and potentially dangerous
			dotDotCount := strings.Count(path, "..")
			if dotDotCount > 1 {
				return fmt.Errorf("path traversal detected: multiple '..' sequences in path")
			}

			// Even a single ".." can be dangerous - check if it leads to sensitive areas
			// Additional checks for suspicious patterns in the original path
			suspiciousPatterns := []string{
				"/../",
				"\\..\\",
			}

			originalPath := filepath.ToSlash(path)
			cleanedSlash := filepath.ToSlash(cleanPath)

			for _, pattern := range suspiciousPatterns {
				if strings.Contains(originalPath, pattern) {
					// Check if cleaning the path significantly changed it
					// This indicates a potential traversal attempt
					if !strings.HasSuffix(cleanedSlash, filepath.Base(originalPath)) {
						// The cleaned path doesn't end with the original filename
						// This suggests path manipulation
						return fmt.Errorf("suspicious path pattern detected: %s", pattern)
					}
				}
			}
		}
	}

	return nil
}

// validateExtension checks if the file has an allowed extension
func (v *SecurityValidator) validateExtension(path string) error {
	ext := strings.ToLower(filepath.Ext(path))

	for _, allowed := range v.AllowedExtensions {
		if ext == allowed {
			return nil
		}
	}

	return fmt.Errorf("unsupported file extension: %s (allowed: %v)", ext, v.AllowedExtensions)
}

// ValidateFileAccess is a convenience function that validates file access
// This is compatible with the existing ValidateFileAccess function in cmd
func ValidateFileAccess(path string) error {
	return ValidateInputFile(path)
}

// IsSecurePath performs a quick check if a path looks secure
func IsSecurePath(path string) bool {
	// Quick checks without filesystem access
	if strings.Contains(path, "..") {
		return false
	}

	// Check for null bytes (security issue in some systems)
	if strings.Contains(path, "\x00") {
		return false
	}

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"/etc/",
		"/proc/",
		"/sys/",
		"C:\\Windows\\",
		"C:\\System32\\",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerPath, strings.ToLower(pattern)) {
			return false
		}
	}

	return true
}
