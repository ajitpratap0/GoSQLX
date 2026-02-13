package output

import (
	"encoding/json"
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// JSONValidationOutput represents the JSON output format for validation command.
//
// Provides structured JSON output for SQL validation results, suitable for
// programmatic consumption, CI/CD integration, and automated processing.
//
// Fields:
//   - Command: Command name ("validate")
//   - Input: Input metadata (type, files, count)
//   - Status: Overall status ("success", "failure", "no_files")
//   - Results: Validation results summary
//   - Errors: Array of validation errors (empty if all valid)
//   - Stats: Performance statistics (optional)
type JSONValidationOutput struct {
	Command string                `json:"command"`
	Input   JSONInputInfo         `json:"input"`
	Status  string                `json:"status"`
	Results JSONValidationResults `json:"results"`
	Errors  []JSONValidationError `json:"errors,omitempty"`
	Stats   *JSONValidationStats  `json:"stats,omitempty"`
}

// JSONInputInfo contains information about the input.
//
// Describes the input source and files processed in the validation run.
//
// Fields:
//   - Type: Input type ("file", "files", "stdin", "directory")
//   - Files: Array of file paths processed
//   - Count: Number of files processed
type JSONInputInfo struct {
	Type  string   `json:"type"` // "file", "files", "stdin", "directory"
	Files []string `json:"files,omitempty"`
	Count int      `json:"count"`
}

// JSONValidationResults contains validation results.
//
// Provides summary statistics about validation outcomes.
//
// Fields:
//   - Valid: True if all files passed validation
//   - TotalFiles: Total number of files processed
//   - ValidFiles: Number of files that passed validation
//   - InvalidFiles: Number of files with validation errors
type JSONValidationResults struct {
	Valid        bool `json:"valid"`
	TotalFiles   int  `json:"total_files"`
	ValidFiles   int  `json:"valid_files"`
	InvalidFiles int  `json:"invalid_files"`
}

// JSONValidationError represents a single validation error.
//
// Contains detailed information about a validation failure for one file.
//
// Fields:
//   - File: File path where error occurred
//   - Message: Error message text
//   - Code: Error code (e.g., "E1001") if available
//   - Type: Error category ("tokenization", "parsing", "syntax", "io")
type JSONValidationError struct {
	File    string `json:"file"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
	Type    string `json:"type"` // "tokenization", "parsing", "syntax", "io"
}

// JSONValidationStats contains performance statistics.
//
// Provides detailed performance metrics for the validation run.
//
// Fields:
//   - Duration: Human-readable duration string (e.g., "10ms")
//   - DurationMs: Duration in milliseconds
//   - TotalBytes: Total size of processed files in bytes
//   - ThroughputFPS: Files processed per second
//   - ThroughputBPS: Bytes processed per second
type JSONValidationStats struct {
	Duration      string  `json:"duration"`
	DurationMs    float64 `json:"duration_ms"`
	TotalBytes    int64   `json:"total_bytes"`
	ThroughputFPS float64 `json:"throughput_files_per_sec,omitempty"`
	ThroughputBPS int64   `json:"throughput_bytes_per_sec,omitempty"`
}

// JSONParseOutput represents the JSON output format for parse command.
//
// Provides structured JSON output for SQL parsing results, including
// AST structure, token information, and metadata.
//
// Fields:
//   - Command: Command name ("parse")
//   - Input: Input metadata
//   - Status: Parse status ("success" or "error")
//   - Results: Parse results (AST, tokens, metadata) if successful
//   - Error: Error information if parsing failed
type JSONParseOutput struct {
	Command string           `json:"command"`
	Input   JSONInputInfo    `json:"input"`
	Status  string           `json:"status"`
	Results *JSONParseResult `json:"results,omitempty"`
	Error   *JSONParseError  `json:"error,omitempty"`
}

// JSONParseResult contains parse results.
//
// Represents the successful parsing of SQL including AST structure,
// token information, and parsing metadata.
//
// Fields:
//   - AST: Abstract Syntax Tree representation
//   - Tokens: Token stream (optional, if requested)
//   - TokenCount: Number of tokens generated
//   - Metadata: Parser metadata (version, compliance, features)
type JSONParseResult struct {
	AST        *JSONASTRepresentation `json:"ast,omitempty"`
	Tokens     []JSONToken            `json:"tokens,omitempty"`
	TokenCount int                    `json:"token_count"`
	Metadata   JSONParseMetadata      `json:"metadata"`
}

// JSONASTRepresentation represents the AST structure.
//
// Provides a JSON-friendly representation of the Abstract Syntax Tree
// generated from SQL parsing.
//
// Fields:
//   - Type: AST type ("AST")
//   - Statements: Array of top-level SQL statements
//   - Count: Number of statements in the AST
type JSONASTRepresentation struct {
	Type       string          `json:"type"`
	Statements []JSONStatement `json:"statements"`
	Count      int             `json:"statement_count"`
}

// JSONStatement represents a single AST statement.
//
// Represents one SQL statement from the AST with type information,
// details, and optional position information.
//
// Fields:
//   - Type: Statement type (e.g., "SelectStatement", "InsertStatement")
//   - Details: Type-specific details (columns, tables, clauses)
//   - Position: Source position (optional)
type JSONStatement struct {
	Type     string                 `json:"type"`
	Details  map[string]interface{} `json:"details,omitempty"`
	Position *JSONPosition          `json:"position,omitempty"`
}

// JSONToken represents a single token.
//
// Represents a lexical token from SQL tokenization with type,
// value, and source position.
//
// Fields:
//   - Type: Token type (e.g., "KEYWORD", "IDENTIFIER", "NUMBER")
//   - Value: Token text value
//   - Position: Source position (line, column)
type JSONToken struct {
	Type     string        `json:"type"`
	Value    string        `json:"value"`
	Position *JSONPosition `json:"position"`
}

// JSONPosition represents a position in the source.
//
// Identifies a specific location in the SQL source text using
// line, column, and optional byte offset.
//
// Fields:
//   - Line: Line number (1-based)
//   - Column: Column number (1-based)
//   - Offset: Byte offset from start (optional)
type JSONPosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
	Offset int `json:"offset,omitempty"`
}

// JSONParseError represents a parsing error.
//
// Contains detailed information about parsing failures including
// error type, message, code, and source position.
//
// Fields:
//   - Message: Error message text
//   - Code: Error code (e.g., "E2001") if available
//   - Type: Error category ("tokenization", "parsing", "io")
//   - Position: Source position where error occurred (optional)
type JSONParseError struct {
	Message  string        `json:"message"`
	Code     string        `json:"code,omitempty"`
	Type     string        `json:"type"` // "tokenization", "parsing", "io"
	Position *JSONPosition `json:"position,omitempty"`
}

// JSONParseMetadata contains metadata about the parsing.
//
// Provides information about the parser capabilities and configuration.
//
// Fields:
//   - ParserVersion: Parser version string
//   - SQLCompliance: SQL standard compliance level (e.g., "~80-85% SQL-99")
//   - Features: Supported SQL features (CTEs, Window Functions, etc.)
type JSONParseMetadata struct {
	ParserVersion string   `json:"parser_version"`
	SQLCompliance string   `json:"sql_compliance"`
	Features      []string `json:"features"`
}

// FormatValidationJSON converts validation results to JSON format.
//
// Generates structured JSON output from validation results, suitable for
// programmatic consumption, CI/CD integration, and automated processing.
//
// Parameters:
//   - result: Validation results to format
//   - inputFiles: Array of input file paths
//   - includeStats: Whether to include performance statistics
//
// Returns:
//   - JSON-encoded bytes with indentation for readability
//   - Error if marshaling fails
//
// Example:
//
//	result := &ValidationResult{
//	    TotalFiles: 2,
//	    ValidFiles: 1,
//	    InvalidFiles: 1,
//	}
//	jsonData, err := FormatValidationJSON(result, []string{"query.sql"}, true)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(string(jsonData))
//
// FormatValidationJSON converts validation results to JSON format
func FormatValidationJSON(result *ValidationResult, inputFiles []string, includeStats bool) ([]byte, error) {
	output := &JSONValidationOutput{
		Command: "validate",
		Input: JSONInputInfo{
			Type:  determineInputType(inputFiles),
			Files: inputFiles,
			Count: len(inputFiles),
		},
		Status: determineStatus(result),
		Results: JSONValidationResults{
			Valid:        result.InvalidFiles == 0,
			TotalFiles:   result.TotalFiles,
			ValidFiles:   result.ValidFiles,
			InvalidFiles: result.InvalidFiles,
		},
		Errors: make([]JSONValidationError, 0),
	}

	// Add errors
	for _, fileResult := range result.Files {
		if fileResult.Error != nil {
			errCode := extractErrorCode(fileResult.Error)
			output.Errors = append(output.Errors, JSONValidationError{
				File:    fileResult.Path,
				Message: fileResult.Error.Error(),
				Code:    errCode,
				Type:    categorizeByCode(errCode, fileResult.Error.Error()),
			})
		}
	}

	// Add statistics if requested
	if includeStats {
		throughputFPS := 0.0
		if result.Duration.Seconds() > 0 {
			throughputFPS = float64(result.TotalFiles) / result.Duration.Seconds()
		}

		throughputBPS := int64(0)
		if result.Duration.Seconds() > 0 {
			throughputBPS = int64(float64(result.TotalBytes) / result.Duration.Seconds())
		}

		output.Stats = &JSONValidationStats{
			Duration:      result.Duration.String(),
			DurationMs:    float64(result.Duration.Milliseconds()),
			TotalBytes:    result.TotalBytes,
			ThroughputFPS: throughputFPS,
			ThroughputBPS: throughputBPS,
		}
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal validation JSON: %w", err)
	}

	return data, nil
}

// FormatParseJSON converts parse results to JSON format
func FormatParseJSON(astObj *ast.AST, inputSource string, showTokens bool, tokens interface{}) ([]byte, error) {
	output := &JSONParseOutput{
		Command: "parse",
		Input: JSONInputInfo{
			Type:  "query",
			Files: []string{inputSource},
			Count: 1,
		},
		Status: "success",
		Results: &JSONParseResult{
			Metadata: JSONParseMetadata{
				ParserVersion: "2.0.0-alpha",
				SQLCompliance: "~80-85% SQL-99",
				Features:      []string{"CTEs", "Window Functions", "JOINs", "Set Operations"},
			},
		},
	}

	// Add AST if available
	if astObj != nil {
		statements := make([]JSONStatement, 0, len(astObj.Statements))
		for _, stmt := range astObj.Statements {
			statements = append(statements, convertStatementToJSON(stmt))
		}

		output.Results.AST = &JSONASTRepresentation{
			Type:       "AST",
			Statements: statements,
			Count:      len(statements),
		}
	}

	// Add tokens if requested
	if showTokens && tokens != nil {
		// Token handling will be added based on the token type
		output.Results.Tokens = []JSONToken{} // Placeholder
		output.Results.TokenCount = 0
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal parse JSON: %w", err)
	}

	return data, nil
}

// FormatParseErrorJSON creates a JSON error output for parse failures
func FormatParseErrorJSON(err error, inputSource string) ([]byte, error) {
	errCode := extractErrorCode(err)
	output := &JSONParseOutput{
		Command: "parse",
		Input: JSONInputInfo{
			Type:  "query",
			Files: []string{inputSource},
			Count: 1,
		},
		Status: "error",
		Error: &JSONParseError{
			Message: err.Error(),
			Code:    errCode,
			Type:    categorizeByCode(errCode, err.Error()),
		},
	}

	// Marshal to JSON with indentation
	data, err2 := json.MarshalIndent(output, "", "  ")
	if err2 != nil {
		return nil, fmt.Errorf("failed to marshal parse error JSON: %w", err2)
	}

	return data, nil
}

// determineInputType determines the type of input based on the file list
func determineInputType(files []string) string {
	if len(files) == 0 {
		return "stdin"
	}
	if len(files) == 1 {
		if files[0] == "-" || files[0] == "" {
			return "stdin"
		}
		return "file"
	}
	return "files"
}

// determineStatus determines the overall status based on validation results
func determineStatus(result *ValidationResult) string {
	if result.InvalidFiles > 0 {
		return "failure"
	}
	if result.ValidFiles > 0 {
		return "success"
	}
	return "no_files"
}

// extractErrorCode extracts the error code from an error
func extractErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if code, ok := goerrors.ExtractErrorCode(err); ok {
		return string(code)
	}
	return ""
}

// categorizeByCode categorizes errors by error code if available
func categorizeByCode(code, errMsg string) string {
	if code != "" {
		switch {
		case strings.HasPrefix(code, "E1"):
			return "tokenization"
		case strings.HasPrefix(code, "E2"):
			return "parsing"
		case strings.HasPrefix(code, "E3"):
			return "semantic"
		case strings.HasPrefix(code, "E4"):
			return "unsupported"
		}
	}
	return categorizeError(errMsg)
}

// categorizeError categorizes error messages by type
func categorizeError(errorMsg string) string {
	errorLower := errorMsg
	if len(errorLower) > 100 {
		errorLower = errorLower[:100]
	}

	switch {
	case contains(errorLower, "tokenization"):
		return "tokenization"
	case contains(errorLower, "parsing"):
		return "parsing"
	case contains(errorLower, "syntax"):
		return "syntax"
	case contains(errorLower, "read file", "file access", "open"):
		return "io"
	default:
		return "unknown"
	}
}

// contains checks if a string contains any of the substrings
func contains(s string, substrings ...string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// convertStatementToJSON converts an AST statement to JSON representation
func convertStatementToJSON(stmt ast.Statement) JSONStatement {
	result := JSONStatement{
		Type:    fmt.Sprintf("%T", stmt),
		Details: make(map[string]interface{}),
	}

	// Simplify type name
	if len(result.Type) > 0 && result.Type[0] == '*' {
		result.Type = result.Type[1:]
	}
	for i := len(result.Type) - 1; i >= 0; i-- {
		if result.Type[i] == '.' {
			result.Type = result.Type[i+1:]
			break
		}
	}

	// Add statement-specific details
	switch s := stmt.(type) {
	case *ast.SelectStatement:
		result.Details["columns"] = len(s.Columns)
		result.Details["has_from"] = len(s.From) > 0
		result.Details["has_where"] = s.Where != nil
		result.Details["has_group_by"] = len(s.GroupBy) > 0
		result.Details["has_order_by"] = len(s.OrderBy) > 0
		result.Details["has_limit"] = s.Limit != nil
		result.Details["has_distinct"] = s.Distinct
	case *ast.InsertStatement:
		result.Details["has_table"] = s.TableName != ""
		result.Details["has_values"] = s.Values != nil
		result.Details["has_columns"] = len(s.Columns) > 0
	case *ast.UpdateStatement:
		result.Details["has_table"] = s.TableName != ""
		result.Details["has_where"] = s.Where != nil
		result.Details["set_count"] = len(s.Assignments)
	case *ast.DeleteStatement:
		result.Details["has_table"] = s.TableName != ""
		result.Details["has_where"] = s.Where != nil
	case *ast.CreateTableStatement:
		result.Details["object_type"] = "table"
		result.Details["has_if_not_exists"] = s.IfNotExists
	case *ast.CreateIndexStatement:
		result.Details["object_type"] = "index"
		result.Details["has_unique"] = s.Unique
	}

	return result
}
