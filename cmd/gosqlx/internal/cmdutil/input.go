package cmdutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/validate"
	"golang.org/x/term"
)

const (
	// MaxFileSize limits file size to prevent DoS attacks (10MB).
	MaxFileSize = 10 * 1024 * 1024

	// MaxStdinSize limits stdin input to prevent DoS attacks (10MB).
	MaxStdinSize = 10 * 1024 * 1024
)

// InputType represents the type of input detected.
type InputType int

const (
	// InputTypeSQL indicates direct SQL query string input.
	InputTypeSQL InputType = iota
	// InputTypeFile indicates file path input.
	InputTypeFile
)

// InputResult contains the detected input type and content.
type InputResult struct {
	Type    InputType
	Content []byte
	Source  string // Original input string or file path
}

// DetectAndReadInput robustly detects whether input is a file path or direct SQL
// and returns the SQL content with proper validation and security limits.
func DetectAndReadInput(input string) (*InputResult, error) {
	if input == "" {
		return nil, fmt.Errorf("empty input provided")
	}

	input = strings.TrimSpace(input)

	_, statErr := os.Stat(input)
	if statErr == nil {
		if err := validate.ValidateInputFile(input); err != nil {
			return nil, fmt.Errorf("security validation failed: %w", err)
		}

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

	if strings.Contains(input, string(filepath.Separator)) || strings.HasSuffix(strings.ToLower(input), ".sql") {
		return nil, fmt.Errorf("invalid file path: %w", statErr)
	}

	if !LooksLikeSQL(input) {
		return nil, fmt.Errorf("input does not appear to be valid SQL or a file path: %s", input)
	}

	if len(input) > MaxFileSize {
		return nil, fmt.Errorf("SQL query too long: %d characters (max %d)", len(input), MaxFileSize)
	}

	return &InputResult{
		Type:    InputTypeSQL,
		Content: []byte(input),
		Source:  "direct input",
	}, nil
}

// IsValidSQLFileExtension checks if the file extension is acceptable for SQL.
func IsValidSQLFileExtension(ext string) bool {
	switch ext {
	case ".sql", ".txt", "":
		return true
	default:
		return false
	}
}

// LooksLikeSQL performs basic heuristic checks to see if input looks like SQL.
func LooksLikeSQL(input string) bool {
	upper := strings.ToUpper(strings.TrimSpace(input))
	keywords := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
		"TRUNCATE", "WITH", "MERGE", "EXPLAIN", "ANALYZE", "SHOW", "DESCRIBE", "DESC",
	}
	for _, kw := range keywords {
		if strings.HasPrefix(upper, kw+" ") || strings.HasPrefix(upper, kw+"\n") || strings.HasPrefix(upper, kw+"\t") || upper == kw {
			return true
		}
	}
	return false
}

// ExpandFileArgs expands file arguments, handling directories and wildcards.
func ExpandFileArgs(args []string) ([]string, error) {
	var expanded []string

	for _, arg := range args {
		stat, err := os.Stat(arg)
		if err != nil {
			expanded = append(expanded, arg)
			continue
		}

		if stat.IsDir() {
			files, err := ExpandDirectory(arg)
			if err != nil {
				return nil, fmt.Errorf("failed to expand directory %s: %w", arg, err)
			}
			expanded = append(expanded, files...)
		} else {
			expanded = append(expanded, arg)
		}
	}

	return expanded, nil
}

// ExpandDirectory finds SQL files in a directory.
func ExpandDirectory(dir string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))

		if IsValidSQLFileExtension(ext) {
			fullPath := filepath.Join(dir, name)
			files = append(files, fullPath)
		}
	}

	return files, nil
}

// ValidateFileAccess checks if we can read the file and it meets size requirements.
func ValidateFileAccess(path string) error {
	return validate.ValidateInputFile(path)
}

// IsStdinPipe detects if stdin is a pipe (not a terminal).
func IsStdinPipe() bool {
	return !term.IsTerminal(int(os.Stdin.Fd())) // #nosec G115
}

// ReadFromStdin reads SQL content from stdin with security limits.
func ReadFromStdin() ([]byte, error) {
	limitedReader := io.LimitedReader{
		R: os.Stdin,
		N: MaxStdinSize + 1,
	}

	content, err := io.ReadAll(&limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}

	if len(content) > MaxStdinSize {
		return nil, fmt.Errorf("stdin input too large: exceeds %d bytes limit", MaxStdinSize)
	}

	if len(content) == 0 {
		return nil, fmt.Errorf("stdin is empty")
	}

	return content, nil
}

// GetInputSource determines the source of input and returns the content.
func GetInputSource(arg string) (*InputResult, error) {
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

	return DetectAndReadInput(arg)
}

// WriteOutput writes content to the specified output destination.
func WriteOutput(content []byte, outputFile string, writer io.Writer) error {
	if outputFile != "" {
		if err := os.WriteFile(outputFile, content, 0600); err != nil { // #nosec G306,G703
			return fmt.Errorf("failed to write to file %s: %w", outputFile, err)
		}
		return nil
	}

	_, err := writer.Write(content)
	if err != nil {
		if IsBrokenPipe(err) {
			return nil
		}
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

// IsBrokenPipe checks if an error is a broken pipe error.
func IsBrokenPipe(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPIPE
	}
	return false
}

// ValidateStdinInput validates stdin content for security.
func ValidateStdinInput(content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("empty input")
	}

	if len(content) > MaxStdinSize {
		return fmt.Errorf("input too large: %d bytes (max %d)", len(content), MaxStdinSize)
	}

	for i := 0; i < len(content) && i < 512; i++ {
		if content[i] == 0 {
			return fmt.Errorf("binary data detected in input")
		}
	}

	return nil
}

// DetectInputMode determines the input mode based on arguments and stdin state.
func DetectInputMode(args []string) (bool, string, error) {
	if len(args) > 0 && args[0] == "-" {
		return true, "-", nil
	}

	if len(args) == 0 {
		if IsStdinPipe() {
			return true, "-", nil
		}
		return false, "", fmt.Errorf("no input provided")
	}

	return false, args[0], nil
}

// ReadInputWithFallback tries to read from the specified source with stdin fallback.
func ReadInputWithFallback(args []string) (*InputResult, error) {
	useStdin, inputArg, err := DetectInputMode(args)
	if err != nil {
		return nil, err
	}

	if useStdin {
		content, err := ReadFromStdin()
		if err != nil {
			return nil, err
		}

		if err := ValidateStdinInput(content); err != nil {
			return nil, fmt.Errorf("stdin validation failed: %w", err)
		}

		return &InputResult{
			Type:    InputTypeSQL,
			Content: content,
			Source:  "stdin",
		}, nil
	}

	return GetInputSource(inputArg)
}

// ShouldReadFromStdin determines if we should read from stdin based on args.
func ShouldReadFromStdin(args []string) bool {
	if len(args) > 0 && args[0] == "-" {
		return IsStdinPipe()
	}

	if len(args) == 0 && IsStdinPipe() {
		return true
	}

	return false
}
