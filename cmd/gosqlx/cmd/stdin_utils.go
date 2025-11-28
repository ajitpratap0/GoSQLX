package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/term"
)

const (
	// MaxStdinSize limits stdin input to prevent DoS attacks (10MB)
	MaxStdinSize = 10 * 1024 * 1024
)

// IsStdinPipe detects if stdin is a pipe (not a terminal)
// This allows auto-detection of piped input like: echo "SELECT 1" | gosqlx validate
func IsStdinPipe() bool {
	// Check if stdin is a terminal using golang.org/x/term
	// If it's not a terminal, it's likely a pipe or redirect
	return !term.IsTerminal(int(os.Stdin.Fd()))
}

// ReadFromStdin reads SQL content from stdin with security limits
// Returns the content and any error encountered
func ReadFromStdin() ([]byte, error) {
	// Create a limited reader to prevent DoS attacks
	limitedReader := io.LimitedReader{
		R: os.Stdin,
		N: MaxStdinSize + 1, // Read one more byte to detect size violations
	}

	// Read all data from stdin
	content, err := io.ReadAll(&limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}

	// Check if size limit was exceeded
	if len(content) > MaxStdinSize {
		return nil, fmt.Errorf("stdin input too large: exceeds %d bytes limit", MaxStdinSize)
	}

	// Check if content is empty
	if len(content) == 0 {
		return nil, fmt.Errorf("stdin is empty")
	}

	return content, nil
}

// GetInputSource determines the source of input and returns the content
// Supports three modes:
// 1. Explicit stdin via "-" argument
// 2. Auto-detected piped stdin
// 3. File path or direct SQL
func GetInputSource(arg string) (*InputResult, error) {
	// Mode 1: Explicit stdin via "-" argument
	if arg == "-" {
		content, err := ReadFromStdin()
		if err != nil {
			return nil, err
		}
		return &InputResult{
			Type:    InputTypeSQL,
			Content: content,
			Source:  "stdin",
		}, nil
	}

	// Mode 2: Auto-detect piped stdin (when no args or args look like flags)
	// This is handled by the caller checking IsStdinPipe() before calling this

	// Mode 3: File path or direct SQL (existing behavior)
	return DetectAndReadInput(arg)
}

// WriteOutput writes content to the specified output destination
// Handles stdout and file output with broken pipe detection
func WriteOutput(content []byte, outputFile string, writer io.Writer) error {
	// If output file is specified, write to file
	if outputFile != "" {
		// Security: Use 0600 permissions for output files (owner read/write only)
		// G306: This is intentional - output files should be user-private
		if err := os.WriteFile(outputFile, content, 0600); err != nil { // #nosec G306
			return fmt.Errorf("failed to write to file %s: %w", outputFile, err)
		}
		return nil
	}

	// Write to stdout (or provided writer)
	_, err := writer.Write(content)
	if err != nil {
		// Check for broken pipe error
		if IsBrokenPipe(err) {
			// Broken pipe is not a critical error in Unix pipelines
			// It just means the reader closed early (e.g., head, grep)
			return nil
		}
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

// IsBrokenPipe checks if an error is a broken pipe error
// This is common in Unix pipelines when the reader closes early
func IsBrokenPipe(err error) bool {
	// Check for EPIPE (broken pipe) on Unix-like systems
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPIPE
	}
	return false
}

// ValidateStdinInput validates stdin content for security
// This is a wrapper around existing security validation
func ValidateStdinInput(content []byte) error {
	// Basic validation: check if content looks like SQL
	if len(content) == 0 {
		return fmt.Errorf("empty input")
	}

	// Size check (already done in ReadFromStdin, but double-check)
	if len(content) > MaxStdinSize {
		return fmt.Errorf("input too large: %d bytes (max %d)", len(content), MaxStdinSize)
	}

	// Additional validation: ensure it's not binary data
	// Check for null bytes (common in binary files)
	for i := 0; i < len(content) && i < 512; i++ {
		if content[i] == 0 {
			return fmt.Errorf("binary data detected in input")
		}
	}

	return nil
}

// DetectInputMode determines the input mode based on arguments and stdin state
// Returns: (useStdin bool, inputArg string, error)
func DetectInputMode(args []string) (bool, string, error) {
	// Case 1: Explicit stdin via "-"
	if len(args) > 0 && args[0] == "-" {
		return true, "-", nil
	}

	// Case 2: No arguments
	if len(args) == 0 {
		// Check if stdin is piped
		if IsStdinPipe() {
			return true, "-", nil
		}
		// No piped stdin and no args = error
		return false, "", fmt.Errorf("no input provided")
	}

	// Case 3: Arguments provided
	// Always prefer explicit arguments over stdin
	return false, args[0], nil
}

// ReadInputWithFallback tries to read from the specified source with stdin fallback
// This provides a convenient way to handle both file and stdin inputs
func ReadInputWithFallback(args []string) (*InputResult, error) {
	// Detect input mode
	useStdin, inputArg, err := DetectInputMode(args)
	if err != nil {
		return nil, err
	}

	// If using stdin, read from it
	if useStdin {
		content, err := ReadFromStdin()
		if err != nil {
			return nil, err
		}

		// Validate stdin content
		if err := ValidateStdinInput(content); err != nil {
			return nil, fmt.Errorf("stdin validation failed: %w", err)
		}

		return &InputResult{
			Type:    InputTypeSQL,
			Content: content,
			Source:  "stdin",
		}, nil
	}

	// Otherwise, use the provided argument
	return GetInputSource(inputArg)
}

// ShouldReadFromStdin determines if we should read from stdin based on args
// This is a simple helper for commands that need to check stdin state
func ShouldReadFromStdin(args []string) bool {
	// Explicit stdin marker
	if len(args) > 0 && args[0] == "-" {
		return true
	}

	// No args and stdin is piped
	if len(args) == 0 && IsStdinPipe() {
		return true
	}

	return false
}
