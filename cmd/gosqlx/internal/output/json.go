package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// JSONValidationOutput represents the JSON output format for validation command
type JSONValidationOutput struct {
	Command string                `json:"command"`
	Input   JSONInputInfo         `json:"input"`
	Status  string                `json:"status"`
	Results JSONValidationResults `json:"results"`
	Errors  []JSONValidationError `json:"errors,omitempty"`
	Stats   *JSONValidationStats  `json:"stats,omitempty"`
}

// JSONInputInfo contains information about the input
type JSONInputInfo struct {
	Type  string   `json:"type"` // "file", "files", "stdin", "directory"
	Files []string `json:"files,omitempty"`
	Count int      `json:"count"`
}

// JSONValidationResults contains validation results
type JSONValidationResults struct {
	Valid        bool `json:"valid"`
	TotalFiles   int  `json:"total_files"`
	ValidFiles   int  `json:"valid_files"`
	InvalidFiles int  `json:"invalid_files"`
}

// JSONValidationError represents a single validation error
type JSONValidationError struct {
	File    string `json:"file"`
	Message string `json:"message"`
	Type    string `json:"type"` // "tokenization", "parsing", "syntax", "io"
}

// JSONValidationStats contains performance statistics
type JSONValidationStats struct {
	Duration      string  `json:"duration"`
	DurationMs    float64 `json:"duration_ms"`
	TotalBytes    int64   `json:"total_bytes"`
	ThroughputFPS float64 `json:"throughput_files_per_sec,omitempty"`
	ThroughputBPS int64   `json:"throughput_bytes_per_sec,omitempty"`
}

// JSONParseOutput represents the JSON output format for parse command
type JSONParseOutput struct {
	Command string           `json:"command"`
	Input   JSONInputInfo    `json:"input"`
	Status  string           `json:"status"`
	Results *JSONParseResult `json:"results,omitempty"`
	Error   *JSONParseError  `json:"error,omitempty"`
}

// JSONParseResult contains parse results
type JSONParseResult struct {
	AST        *JSONASTRepresentation `json:"ast,omitempty"`
	Tokens     []JSONToken            `json:"tokens,omitempty"`
	TokenCount int                    `json:"token_count"`
	Metadata   JSONParseMetadata      `json:"metadata"`
}

// JSONASTRepresentation represents the AST structure
type JSONASTRepresentation struct {
	Type       string          `json:"type"`
	Statements []JSONStatement `json:"statements"`
	Count      int             `json:"statement_count"`
}

// JSONStatement represents a single AST statement
type JSONStatement struct {
	Type     string                 `json:"type"`
	Details  map[string]interface{} `json:"details,omitempty"`
	Position *JSONPosition          `json:"position,omitempty"`
}

// JSONToken represents a single token
type JSONToken struct {
	Type     string        `json:"type"`
	Value    string        `json:"value"`
	Position *JSONPosition `json:"position"`
}

// JSONPosition represents a position in the source
type JSONPosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
	Offset int `json:"offset,omitempty"`
}

// JSONParseError represents a parsing error
type JSONParseError struct {
	Message  string        `json:"message"`
	Type     string        `json:"type"` // "tokenization", "parsing", "io"
	Position *JSONPosition `json:"position,omitempty"`
}

// JSONParseMetadata contains metadata about the parsing
type JSONParseMetadata struct {
	ParserVersion string   `json:"parser_version"`
	SQLCompliance string   `json:"sql_compliance"`
	Features      []string `json:"features"`
}

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
			output.Errors = append(output.Errors, JSONValidationError{
				File:    fileResult.Path,
				Message: fileResult.Error.Error(),
				Type:    categorizeError(fileResult.Error.Error()),
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
			Type:    categorizeError(err.Error()),
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
		result.Details["set_count"] = len(s.Updates)
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
