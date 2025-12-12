package validate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxFileSize limits file size to prevent DoS attacks.
	//
	// Default: 10MB (10 * 1024 * 1024 bytes)
	//
	// This limit prevents:
	//   - Memory exhaustion from loading large files
	//   - Denial of service attacks
	//   - Processing timeouts
	//
	// Can be configured in .gosqlx.yml:
	//
	//	validate:
	//	  security:
	//	    max_file_size: 20971520  # 20MB
	MaxFileSize = 10 * 1024 * 1024
)

// SecurityValidator provides comprehensive file security validation.
//
// Implements defense-in-depth security checks for file access including:
//   - Path traversal prevention
//   - Symlink validation
//   - File size limits
//   - File type validation
//   - Permission checks
//
// Fields:
//   - MaxFileSize: Maximum allowed file size in bytes
//   - AllowedExtensions: Array of permitted file extensions (.sql, .txt)
//   - AllowSymlinks: Whether to allow symlink following (default: false)
//   - WorkingDirectory: Optional directory restriction for path validation
//
// Thread Safety:
//
//	SecurityValidator instances are not thread-safe. Create separate
//	instances for concurrent use or use appropriate synchronization.
type SecurityValidator struct {
	MaxFileSize       int64
	AllowedExtensions []string
	AllowSymlinks     bool
	WorkingDirectory  string // Optional: restrict to working directory
}

// NewSecurityValidator creates a validator with default security settings.
//
// Returns a SecurityValidator configured with production-ready defaults:
//   - MaxFileSize: 10MB
//   - AllowedExtensions: .sql, .txt, and files without extension
//   - AllowSymlinks: false (symlinks rejected for security)
//   - WorkingDirectory: empty (no directory restriction)
//
// Returns:
//   - *SecurityValidator with default configuration
//
// Example:
//
//	validator := NewSecurityValidator()
//	if err := validator.Validate("query.sql"); err != nil {
//	    log.Fatalf("Validation failed: %v", err)
//	}
//
// Customization:
//
//	validator := NewSecurityValidator()
//	validator.MaxFileSize = 20 * 1024 * 1024  // Allow 20MB files
//	validator.AllowSymlinks = true             // Allow symlinks
//	validator.WorkingDirectory = "/safe/path"  // Restrict to directory
//
// NewSecurityValidator creates a validator with default security settings
func NewSecurityValidator() *SecurityValidator {
	return &SecurityValidator{
		MaxFileSize:       MaxFileSize,
		AllowedExtensions: []string{".sql", ".txt", ""},
		AllowSymlinks:     false,
		WorkingDirectory:  "",
	}
}

// ValidateInputFile performs comprehensive security validation on a file path.
//
// This is the primary security entry point for file validation. It creates
// a SecurityValidator with default settings and validates the given file path.
//
// Security checks performed:
//  1. Path traversal prevention (../ sequences)
//  2. Symlink resolution and validation
//  3. File existence and accessibility
//  4. Regular file check (not directory, device, etc.)
//  5. File size limit enforcement (10MB default)
//  6. File extension validation (.sql, .txt)
//  7. Read permission verification
//
// Parameters:
//   - path: File path to validate (absolute or relative)
//
// Returns:
//   - nil if file is safe to read
//   - error with specific security violation details
//
// Example:
//
//	if err := validate.ValidateInputFile("query.sql"); err != nil {
//	    return fmt.Errorf("security check failed: %w", err)
//	}
//	// Safe to read file
//	content, _ := os.ReadFile("query.sql")
//
// Security guarantees:
//   - File cannot be outside working directory (if symlink)
//   - File size is within configured limits
//   - File is a regular file with valid extension
//   - File is readable by current process
//
// ValidateInputFile performs comprehensive security validation on a file path
func ValidateInputFile(path string) error {
	validator := NewSecurityValidator()
	return validator.Validate(path)
}

// Validate performs comprehensive security checks on a file path.
//
// This is the core validation method that performs all security checks
// in the correct order to prevent TOCTOU attacks and other vulnerabilities.
//
// Validation sequence:
//  1. Path traversal check on original path
//  2. Symlink resolution to real path
//  3. Symlink policy enforcement (if AllowSymlinks is false)
//  4. File existence and accessibility check
//  5. Regular file verification (not directory/device/socket)
//  6. File size limit enforcement
//  7. File extension validation
//  8. Read permission test
//
// Parameters:
//   - path: File path to validate
//
// Returns:
//   - nil if all security checks pass
//   - error with specific check that failed
//
// The validation is defensive and fails closed - any error results in
// rejection to maintain security guarantees.
//
// Example:
//
//	validator := &SecurityValidator{
//	    MaxFileSize: 5 * 1024 * 1024,  // 5MB
//	    AllowedExtensions: []string{".sql"},
//	    AllowSymlinks: false,
//	    WorkingDirectory: "/project/sql",
//	}
//	if err := validator.Validate("query.sql"); err != nil {
//	    log.Printf("Validation failed: %v", err)
//	    return err
//	}
//
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
	// G304: realPath is fully validated above via EvalSymlinks and security checks
	file, err := os.Open(realPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	// G104: Check error on Close to ensure resources are properly released
	if closeErr := file.Close(); closeErr != nil {
		return fmt.Errorf("error closing file: %w", closeErr)
	}

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
	if !strings.Contains(path, "..") {
		return nil
	}

	// Use working directory validation if configured
	if v.WorkingDirectory != "" {
		return v.checkWorkingDirectoryTraversal(absPath)
	}

	// Otherwise use heuristic checks
	return v.checkSuspiciousDotDotPatterns(path, cleanPath)
}

// checkWorkingDirectoryTraversal validates path doesn't escape working directory
func (v *SecurityValidator) checkWorkingDirectoryTraversal(absPath string) error {
	workDir, err := filepath.Abs(v.WorkingDirectory)
	if err != nil {
		return fmt.Errorf("cannot resolve working directory: %w", err)
	}

	if !strings.HasPrefix(absPath, workDir) {
		return fmt.Errorf("path traversal detected: path escapes working directory")
	}

	return nil
}

// checkSuspiciousDotDotPatterns detects dangerous ".." usage patterns
func (v *SecurityValidator) checkSuspiciousDotDotPatterns(originalPath, cleanedPath string) error {
	// Multiple ".." sequences are suspicious and potentially dangerous
	dotDotCount := strings.Count(originalPath, "..")
	if dotDotCount > 1 {
		return fmt.Errorf("path traversal detected: multiple '..' sequences in path")
	}

	// Check for suspicious path separator patterns
	return v.hasSuspiciousPathPattern(originalPath, cleanedPath)
}

// hasSuspiciousPathPattern detects obfuscated traversal attempts
func (v *SecurityValidator) hasSuspiciousPathPattern(originalPath, cleanedPath string) error {
	suspiciousPatterns := []string{
		"/../",
		"\\..\\",
	}

	originalSlash := filepath.ToSlash(originalPath)
	cleanedSlash := filepath.ToSlash(cleanedPath)

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(originalSlash, pattern) {
			// Check if cleaning the path significantly changed it
			// This indicates a potential traversal attempt
			if !strings.HasSuffix(cleanedSlash, filepath.Base(originalSlash)) {
				return fmt.Errorf("suspicious path pattern detected: %s", pattern)
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

// ValidateFileAccess is a convenience function that validates file access.
//
// This function provides backward compatibility with existing code that uses
// ValidateFileAccess. It delegates to ValidateInputFile for actual validation.
//
// Parameters:
//   - path: File path to validate
//
// Returns:
//   - nil if file is safe to access
//   - error if validation fails
//
// This is equivalent to calling ValidateInputFile directly.
//
// ValidateFileAccess is a convenience function that validates file access
// This is compatible with the existing ValidateFileAccess function in cmd
func ValidateFileAccess(path string) error {
	return ValidateInputFile(path)
}

// IsSecurePath performs a quick check if a path looks secure.
//
// Performs lightweight path validation without filesystem access, useful
// for early filtering before expensive validation. This is a heuristic
// check and should not be relied upon as the sole security measure.
//
// Checks performed:
//   - No directory traversal sequences (..)
//   - No null bytes
//   - Not targeting sensitive system directories
//
// Parameters:
//   - path: File path to check
//
// Returns:
//   - true if path appears safe (passes heuristics)
//   - false if path contains suspicious patterns
//
// Note: This is a preliminary check only. Always use ValidateInputFile
// or SecurityValidator.Validate for comprehensive security validation.
//
// Example:
//
//	if !IsSecurePath(userInput) {
//	    return errors.New("suspicious path detected")
//	}
//	// Still need full validation
//	if err := ValidateInputFile(userInput); err != nil {
//	    return err
//	}
//
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
