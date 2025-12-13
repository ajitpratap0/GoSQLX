package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/validate"
)

const (
	// MaxFileSize limits file size to prevent DoS attacks.
	//
	// Default: 10MB (10 * 1024 * 1024 bytes)
	//
	// This is the maximum size for files and stdin input to prevent:
	//   - Memory exhaustion
	//   - Denial of service attacks
	//   - Processing timeouts
	MaxFileSize = 10 * 1024 * 1024
)

// InputType represents the type of input detected.
//
// Used to distinguish between direct SQL input and file-based input
// for appropriate handling in commands.
type InputType int

const (
	// InputTypeSQL indicates direct SQL query string input.
	InputTypeSQL InputType = iota
	// InputTypeFile indicates file path input.
	InputTypeFile
)

// InputResult contains the detected input type and content.
//
// Returned by DetectAndReadInput to provide both the raw SQL content
// and metadata about the input source.
//
// Fields:
//   - Type: Input type (InputTypeSQL or InputTypeFile)
//   - Content: Raw SQL content as bytes
//   - Source: Original input string or file path for error reporting
type InputResult struct {
	Type    InputType
	Content []byte
	Source  string // Original input string or file path
}

// DetectAndReadInput robustly detects whether input is a file path or direct SQL.
//
// This function implements intelligent input detection with security validation.
// It determines if the input is a file path or direct SQL and returns the
// appropriate content with full security checks.
//
// Detection logic:
//  1. Check if input is a valid file path (os.Stat succeeds)
//  2. If file exists, validate security and read content
//  3. If not a file, check if it looks like a file path (.sql extension, path separators)
//  4. If looks like file path, return file not found error
//  5. Otherwise treat as direct SQL query
//
// Security measures:
//   - File path validation (path traversal prevention)
//   - File size limits (10MB default)
//   - SQL length limits for direct input
//   - Binary data detection
//   - File extension validation
//
// Parameters:
//   - input: String that may be a file path or direct SQL
//
// Returns:
//   - *InputResult: Detected input with content and metadata
//   - error: If validation fails or input is invalid
//
// Example:
//
//	// File input
//	result, err := DetectAndReadInput("query.sql")
//	// result.Type == InputTypeFile, result.Content contains file contents
//
//	// Direct SQL
//	result, err := DetectAndReadInput("SELECT * FROM users")
//	// result.Type == InputTypeSQL, result.Content contains SQL query
//
//	// Error case
//	result, err := DetectAndReadInput("nonexistent.sql")
//	// Returns file not found error
//
// DetectAndReadInput robustly detects whether input is a file path or direct SQL
// and returns the SQL content with proper validation and security limits
func DetectAndReadInput(input string) (*InputResult, error) {
	if input == "" {
		return nil, fmt.Errorf("empty input provided")
	}

	// Trim whitespace for better detection
	input = strings.TrimSpace(input)

	// Check if input looks like a file path using os.Stat
	_, statErr := os.Stat(input)
	if statErr == nil {
		// Input is a valid file path - perform comprehensive security validation
		if err := validate.ValidateInputFile(input); err != nil {
			return nil, fmt.Errorf("security validation failed: %w", err)
		}

		// Read the file
		// G304: Path is validated by ValidateInputFile above
		content, err := os.ReadFile(input) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", input, err)
		}

		if len(content) == 0 {
			return nil, fmt.Errorf("file is empty: %s", input)
		}

		return &InputResult{
			Type:    InputTypeFile,
			Content: content,
			Source:  input,
		}, nil
	}

	// If stat failed, check if it looks like a file path that doesn't exist
	// (contains path separators or has .sql extension)
	if strings.Contains(input, string(filepath.Separator)) || strings.HasSuffix(strings.ToLower(input), ".sql") {
		// Looks like a file path but doesn't exist - return the original stat error
		return nil, fmt.Errorf("invalid file path: %w", statErr)
	}

	// Input is not a file path, treat as direct SQL
	// Validate that it looks like SQL (basic heuristics)
	if !looksLikeSQL(input) {
		return nil, fmt.Errorf("input does not appear to be valid SQL or a file path: %s", input)
	}

	// Security check: SQL length limit
	if len(input) > MaxFileSize {
		return nil, fmt.Errorf("SQL query too long: %d characters (max %d)", len(input), MaxFileSize)
	}

	return &InputResult{
		Type:    InputTypeSQL,
		Content: []byte(input),
		Source:  "direct input",
	}, nil
}

// isValidSQLFileExtension checks if the file extension is acceptable for SQL
func isValidSQLFileExtension(ext string) bool {
	switch ext {
	case ".sql", ".txt", "": // Allow .sql, .txt, and files without extension
		return true
	default:
		return false
	}
}

// looksLikeSQL performs basic heuristic checks to see if input looks like SQL
func looksLikeSQL(input string) bool {
	// Convert to uppercase for case-insensitive checking
	upperInput := strings.ToUpper(strings.TrimSpace(input))

	// Check for common SQL keywords at the beginning
	sqlKeywords := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
		"WITH", "EXPLAIN", "ANALYZE", "SHOW", "DESCRIBE", "DESC", "MERGE",
	}

	for _, keyword := range sqlKeywords {
		if strings.HasPrefix(upperInput, keyword) {
			return true
		}
	}

	// If no keywords found but contains semicolon, might still be SQL
	return strings.Contains(input, ";")
}

// ExpandFileArgs expands file arguments, handling directories and wildcards
// This centralizes the file expansion logic used across multiple commands
func ExpandFileArgs(args []string) ([]string, error) {
	var expanded []string

	for _, arg := range args {
		// Check if argument is a file or directory
		stat, err := os.Stat(arg)
		if err != nil {
			// If stat fails, treat as direct SQL or invalid path
			expanded = append(expanded, arg)
			continue
		}

		if stat.IsDir() {
			// Expand directory to find SQL files
			files, err := expandDirectory(arg)
			if err != nil {
				return nil, fmt.Errorf("failed to expand directory %s: %w", arg, err)
			}
			expanded = append(expanded, files...)
		} else {
			// Single file
			expanded = append(expanded, arg)
		}
	}

	return expanded, nil
}

// expandDirectory finds SQL files in a directory
func expandDirectory(dir string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip subdirectories
		}

		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))

		// Only include SQL-like files
		if isValidSQLFileExtension(ext) {
			fullPath := filepath.Join(dir, name)
			files = append(files, fullPath)
		}
	}

	return files, nil
}

// ValidateFileAccess checks if we can read the file and it meets size requirements
// Now uses enhanced security validation with path traversal and symlink checks
func ValidateFileAccess(path string) error {
	// Use the enhanced security validator from internal package
	return validate.ValidateInputFile(path)
}

// expandFileArgs is a lowercase alias for ExpandFileArgs for backward compatibility
func expandFileArgs(args []string) ([]string, error) {
	return ExpandFileArgs(args)
}
