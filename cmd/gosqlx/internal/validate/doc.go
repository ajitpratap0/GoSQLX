// Package validate provides security validation for file access in the gosqlx CLI.
//
// # Overview
//
// This package implements comprehensive security checks for file operations
// to prevent common vulnerabilities including path traversal, symlink attacks,
// and resource exhaustion through large files.
//
// # Security Features
//
// ## Path Traversal Prevention
//
// Prevents directory traversal attacks using patterns like:
//   - ../../../etc/passwd
//   - ..\..\..\windows\system32
//   - Encoded variants (%2e%2e%2f)
//
// Implementation:
//   - Resolves absolute paths before validation
//   - Checks for upward directory traversal
//   - Validates against working directory boundaries
//
// ## Symlink Validation
//
// Prevents symlink-based attacks by:
//   - Resolving symlinks to their targets
//   - Validating target file properties
//   - Detecting circular symlinks
//   - Enforcing size limits on symlink targets
//
// Protection against:
//   - Symlinks to sensitive system files
//   - Symlinks to files outside working directory
//   - Time-of-check to time-of-use (TOCTOU) attacks
//
// ## File Size Limits
//
// Prevents resource exhaustion through:
//   - Default 10MB file size limit
//   - Configurable limits via .gosqlx.yml
//   - Pre-read size validation
//   - Memory-efficient file handling
//
// Protects against:
//   - Denial of service (DoS) attacks
//   - Memory exhaustion
//   - Processing timeouts
//
// ## File Type Validation
//
// Validates file types by:
//   - Checking file extensions (.sql, .txt)
//   - Detecting binary files (null byte scanning)
//   - Validating file permissions
//   - Checking file readability
//
// # Functions
//
// ## ValidateInputFile
//
// Comprehensive file validation with all security checks:
//
//	func ValidateInputFile(path string) error
//
// Performs:
//  1. Path traversal check
//  2. Symlink resolution and validation
//  3. File size limit enforcement
//  4. File type validation
//  5. Permission checks
//
// Parameters:
//   - path: File path to validate
//
// Returns:
//   - nil if file is safe to read
//   - error with specific security violation
//
// Usage:
//
//	if err := validate.ValidateInputFile("query.sql"); err != nil {
//	    return fmt.Errorf("security validation failed: %w", err)
//	}
//	content, _ := os.ReadFile("query.sql")
//
// ## ValidateFilePath
//
// Validates file path for directory traversal:
//
//	func ValidateFilePath(path string) error
//
// Checks:
//   - Absolute path resolution
//   - Upward directory traversal (../)
//   - Working directory boundaries
//
// Usage:
//
//	if err := validate.ValidateFilePath(filePath); err != nil {
//	    return fmt.Errorf("invalid file path: %w", err)
//	}
//
// ## ResolveAndValidateSymlink
//
// Resolves symlinks and validates targets:
//
//	func ResolveAndValidateSymlink(path string) (string, error)
//
// Performs:
//   - Symlink resolution to final target
//   - Target existence check
//   - Target size validation
//   - Circular symlink detection
//
// Returns:
//   - Resolved file path
//   - Error if symlink validation fails
//
// Usage:
//
//	resolvedPath, err := validate.ResolveAndValidateSymlink(filePath)
//	if err != nil {
//	    return fmt.Errorf("symlink validation failed: %w", err)
//	}
//	content, _ := os.ReadFile(resolvedPath)
//
// ## ValidateFileSize
//
// Enforces file size limits:
//
//	func ValidateFileSize(path string, maxSize int64) error
//
// Checks:
//   - File size against limit
//   - File existence and readability
//
// Parameters:
//   - path: File path to check
//   - maxSize: Maximum allowed file size in bytes
//
// Returns:
//   - nil if file is within size limit
//   - error if file exceeds limit or is inaccessible
//
// Usage:
//
//	maxSize := 10 * 1024 * 1024 // 10MB
//	if err := validate.ValidateFileSize(filePath, maxSize); err != nil {
//	    return fmt.Errorf("file too large: %w", err)
//	}
//
// # Constants
//
// ## DefaultMaxFileSize
//
// Default maximum file size (10MB):
//
//	const DefaultMaxFileSize = 10 * 1024 * 1024
//
// Rationale:
//   - Sufficient for typical SQL files
//   - Prevents memory exhaustion
//   - Configurable via .gosqlx.yml
//
// Can be overridden in configuration:
//
//	validate:
//	  security:
//	    max_file_size: 20971520  # 20MB
//
// # Security Best Practices
//
// ## Always Validate Before Reading
//
// Validate file access before any file operations:
//
//	// INCORRECT - no validation
//	content, _ := os.ReadFile(userProvidedPath)
//
//	// CORRECT - validate first
//	if err := validate.ValidateInputFile(userProvidedPath); err != nil {
//	    return err
//	}
//	content, _ := os.ReadFile(userProvidedPath)
//
// ## Use Validated Paths
//
// Always use the validated/resolved path for file operations:
//
//	resolvedPath, err := validate.ResolveAndValidateSymlink(userPath)
//	if err != nil {
//	    return err
//	}
//	// Use resolvedPath for all subsequent operations
//	content, _ := os.ReadFile(resolvedPath)
//
// ## Handle Validation Errors
//
// Provide clear error messages without exposing system details:
//
//	if err := validate.ValidateInputFile(path); err != nil {
//	    // DON'T expose system paths in error messages
//	    return fmt.Errorf("file access validation failed")
//
//	    // DO provide helpful context
//	    return fmt.Errorf("file access validation failed: %w", err)
//	}
//
// ## Configuration Limits
//
// Respect configured file size limits:
//
//	cfg, _ := config.LoadDefault()
//	maxSize := cfg.Validation.Security.MaxFileSize
//	if err := validate.ValidateFileSize(path, maxSize); err != nil {
//	    return err
//	}
//
// # Attack Scenarios and Mitigations
//
// ## Path Traversal Attack
//
// Attack attempt:
//
//	gosqlx validate ../../../etc/passwd
//
// Mitigation:
//
//	ValidateFilePath() rejects upward traversal:
//	Error: "path traversal detected: file is outside working directory"
//
// ## Symlink Attack
//
// Attack attempt:
//
//	ln -s /etc/passwd malicious.sql
//	gosqlx validate malicious.sql
//
// Mitigation:
//
//	ResolveAndValidateSymlink() validates target:
//	Error: "symlink target is outside working directory"
//
// ## Resource Exhaustion
//
// Attack attempt:
//
//	# Create 1GB file
//	dd if=/dev/zero of=huge.sql bs=1M count=1024
//	gosqlx validate huge.sql
//
// Mitigation:
//
//	ValidateFileSize() enforces limit:
//	Error: "file size (1073741824 bytes) exceeds maximum (10485760 bytes)"
//
// ## Time-of-Check to Time-of-Use (TOCTOU)
//
// Attack attempt:
//
//	# Replace file between validation and read
//	gosqlx validate good.sql &
//	sleep 0.1; ln -sf /etc/passwd good.sql
//
// Mitigation:
//
//   - Symlink resolution before validation
//   - Immediate file operations after validation
//   - Operating system-level protections
//
// # Testing
//
// The package includes comprehensive security tests:
//
//   - security_test.go: Core security validation tests
//   - security_demo_test.go: Demonstration of security features
//
// Test coverage includes:
//   - Path traversal attempts (various encodings)
//   - Symlink attack scenarios
//   - File size limit enforcement
//   - Edge cases (empty files, non-existent files)
//   - Platform-specific behavior (Windows vs Unix)
//
// # Platform Considerations
//
// ## Unix/Linux/macOS
//
// Path handling:
//   - Forward slash (/) as separator
//   - Symlink support (ReadLink, EvalSymlinks)
//   - Case-sensitive file systems (typically)
//
// ## Windows
//
// Path handling:
//   - Backslash (\) as separator
//   - UNC paths (\\server\share)
//   - Case-insensitive file systems
//   - Limited symlink support (requires admin)
//
// The package uses filepath.ToSlash and filepath.FromSlash for cross-platform compatibility.
//
// # Error Types
//
// Validation errors include specific context:
//
//	"path traversal detected: file is outside working directory"
//	"symlink target is outside working directory"
//	"file size (X bytes) exceeds maximum (Y bytes)"
//	"file not found: path/to/file.sql"
//	"permission denied: cannot read file"
//
// Errors can be checked using errors.Is() for specific handling.
//
// # Performance
//
// Validation performance:
//   - Path validation: <1μs (path resolution)
//   - Symlink resolution: <10μs (filesystem stat)
//   - Size check: <1μs (metadata only, no read)
//
// Total overhead: <20μs per file, negligible for typical workloads.
//
// # Integration
//
// This package is integrated into:
//
//   - cmd/gosqlx/cmd/input_utils.go (DetectAndReadInput, ValidateFileAccess)
//   - cmd/gosqlx/cmd/validator.go (file validation before processing)
//   - cmd/gosqlx/cmd/formatter.go (file validation before formatting)
//   - cmd/gosqlx/cmd/parser_cmd.go (file validation before parsing)
//
// All file operations in the CLI use this validation layer.
//
// # Examples
//
// ## Basic File Validation
//
//	import "github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/validate"
//
//	func processFile(path string) error {
//	    // Validate file before reading
//	    if err := validate.ValidateInputFile(path); err != nil {
//	        return fmt.Errorf("file validation failed: %w", err)
//	    }
//
//	    // Safe to read file
//	    content, err := os.ReadFile(path)
//	    if err != nil {
//	        return err
//	    }
//
//	    // Process content
//	    return processSQL(content)
//	}
//
// ## Symlink Handling
//
//	func processSymlink(path string) error {
//	    // Resolve symlink to actual file
//	    resolvedPath, err := validate.ResolveAndValidateSymlink(path)
//	    if err != nil {
//	        return fmt.Errorf("symlink validation failed: %w", err)
//	    }
//
//	    // Use resolved path
//	    content, _ := os.ReadFile(resolvedPath)
//	    return processSQL(content)
//	}
//
// ## Custom Size Limit
//
//	func processLargeFile(path string) error {
//	    // Allow larger files (20MB)
//	    maxSize := int64(20 * 1024 * 1024)
//	    if err := validate.ValidateFileSize(path, maxSize); err != nil {
//	        return fmt.Errorf("file too large: %w", err)
//	    }
//
//	    content, _ := os.ReadFile(path)
//	    return processSQL(content)
//	}
//
// # See Also
//
//   - cmd/gosqlx/cmd/input_utils.go - Input handling utilities
//   - cmd/gosqlx/internal/config/config.go - Configuration management
//   - https://owasp.org/www-community/attacks/Path_Traversal - Path traversal attacks
//   - https://cwe.mitre.org/data/definitions/59.html - Link following vulnerabilities
package validate
