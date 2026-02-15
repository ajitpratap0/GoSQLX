package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// ValidationResult holds the result of validating a single SQL file
type ValidationResult struct {
	FilePath string
	Valid    bool
	Error    error
}

// ValidateFile validates a single SQL file
func ValidateFile(filePath string) ValidationResult {
	// Read the file
	content, err := os.ReadFile(filepath.Clean(filePath)) // #nosec G304 // #nosec G304,G703
	if err != nil {
		return ValidationResult{
			FilePath: filePath,
			Valid:    false,
			Error:    fmt.Errorf("failed to read file: %w", err),
		}
	}

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize the SQL
	tokens, err := tkz.Tokenize(content)
	if err != nil {
		return ValidationResult{
			FilePath: filePath,
			Valid:    false,
			Error:    fmt.Errorf("tokenization error: %w", err),
		}
	}

	// Create parser
	p := parser.NewParser()
	defer p.Release()

	// Parse the tokens
	_, err = p.ParseFromModelTokens(tokens)
	if err != nil {
		return ValidationResult{
			FilePath: filePath,
			Valid:    false,
			Error:    fmt.Errorf("parse error: %w", err),
		}
	}

	return ValidationResult{
		FilePath: filePath,
		Valid:    true,
		Error:    nil,
	}
}

// ValidateDirectory recursively validates all .sql files in a directory
func ValidateDirectory(dirPath string) ([]ValidationResult, error) {
	var results []ValidationResult

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error { // #nosec G703
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process .sql files
		if !strings.HasSuffix(strings.ToLower(path), ".sql") {
			return nil
		}

		// Validate the file
		result := ValidateFile(path)
		results = append(results, result)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return results, nil
}

// PrintResults prints validation results in a user-friendly format
func PrintResults(results []ValidationResult) {
	validCount := 0
	invalidCount := 0

	fmt.Println("\n=== SQL Validation Results ===\n")

	for _, result := range results {
		if result.Valid {
			fmt.Printf("✓ %s\n", result.FilePath)
			validCount++
		} else {
			fmt.Printf("✗ %s\n", result.FilePath)
			fmt.Printf("  Error: %v\n\n", result.Error)
			invalidCount++
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total files: %d\n", len(results))
	fmt.Printf("Valid: %d\n", validCount)
	fmt.Printf("Invalid: %d\n", invalidCount)
}
