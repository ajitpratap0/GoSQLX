package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/validate"
)

const (
	// MaxFileSize limits file size to prevent DoS attacks (10MB)
	MaxFileSize = 10 * 1024 * 1024
)

// InputType represents the type of input detected
type InputType int

const (
	InputTypeSQL InputType = iota
	InputTypeFile
)

// InputResult contains the detected input type and content
type InputResult struct {
	Type    InputType
	Content []byte
	Source  string // Original input string or file path
}

// DetectAndReadInput robustly detects whether input is a file path or direct SQL
// and returns the SQL content with proper validation and security limits
func DetectAndReadInput(input string) (*InputResult, error) {
	if input == "" {
		return nil, fmt.Errorf("empty input provided")
	}

	// Trim whitespace for better detection
	input = strings.TrimSpace(input)

	// Check if input looks like a file path using os.Stat
	if _, err := os.Stat(input); err == nil {
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

	// Input is not a valid file path, treat as direct SQL
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
		"WITH", "EXPLAIN", "ANALYZE", "SHOW", "DESCRIBE", "DESC",
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
