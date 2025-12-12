package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ValidationResult contains the results of a validation run.
//
// This structure aggregates validation results across multiple files,
// providing summary statistics and individual file results.
//
// Fields:
//   - TotalFiles: Total number of files processed
//   - ValidFiles: Number of files that passed validation
//   - InvalidFiles: Number of files with validation errors
//   - TotalBytes: Total size of all processed files in bytes
//   - Duration: Time taken to process all files
//   - Files: Individual file validation results
//
// Example:
//
//	result := &ValidationResult{
//	    TotalFiles:   2,
//	    ValidFiles:   1,
//	    InvalidFiles: 1,
//	    Duration:     10 * time.Millisecond,
//	}
type ValidationResult struct {
	TotalFiles   int
	ValidFiles   int
	InvalidFiles int
	TotalBytes   int64
	Duration     time.Duration
	Files        []FileValidationResult
}

// FileValidationResult contains the result for a single file.
//
// Represents the validation outcome for one SQL file including
// success status, file metadata, and any validation errors.
//
// Fields:
//   - Path: File path (absolute or relative)
//   - Valid: True if validation succeeded, false otherwise
//   - Size: File size in bytes
//   - Error: Validation error if validation failed, nil otherwise
//
// Example:
//
//	fileResult := FileValidationResult{
//	    Path:  "query.sql",
//	    Valid: false,
//	    Size:  1024,
//	    Error: errors.New("syntax error at line 5"),
//	}
type FileValidationResult struct {
	Path  string
	Valid bool
	Size  int64
	Error error
}

// SARIF represents a SARIF 2.1.0 document.
//
// SARIF (Static Analysis Results Interchange Format) is a standard format
// for representing static analysis results. This implementation complies with
// SARIF 2.1.0 specification for integration with GitHub Code Scanning and
// other static analysis tools.
//
// Fields:
//   - Schema: JSON schema URL for SARIF 2.1.0
//   - Version: SARIF format version (always "2.1.0")
//   - Runs: Array of analysis runs (typically one run per invocation)
//
// Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
type SARIF struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
//
// A run represents a single invocation of an analysis tool on a set of files.
// Each run contains tool information, rules, and results.
//
// Fields:
//   - Tool: Information about the analysis tool (GoSQLX)
//   - Results: Array of findings from the analysis
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
//
// Contains metadata about the tool that produced the analysis results.
//
// Fields:
//   - Driver: Tool driver information (name, version, rules)
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool information.
//
// Provides detailed information about the analysis tool including
// name, version, and rule definitions.
//
// Fields:
//   - Name: Tool name ("GoSQLX")
//   - Version: Tool version (e.g., "1.6.0")
//   - InformationURI: URL to tool documentation
//   - Rules: Array of rule definitions
//   - SemanticVersion: Semantic version string
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
}

// SARIFRule describes a validation rule.
//
// Defines a specific validation rule that can be violated in the analysis.
// Rules provide metadata about what was checked and how to fix violations.
//
// Fields:
//   - ID: Unique rule identifier (e.g., "sql-syntax-error")
//   - Name: Human-readable rule name
//   - ShortDescription: Brief description of the rule
//   - FullDescription: Detailed description of what the rule checks
//   - Help: Guidance on how to fix violations
//   - DefaultLevel: Default severity level (not used in current implementation)
//   - Properties: Additional rule metadata (category, tags)
type SARIFRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription SARIFMessage           `json:"shortDescription,omitempty"`
	FullDescription  SARIFMessage           `json:"fullDescription,omitempty"`
	Help             SARIFMessage           `json:"help,omitempty"`
	DefaultLevel     string                 `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFResult represents a single finding.
//
// A result represents one specific violation or issue found during analysis.
// Each result is associated with a rule and has a location in the source code.
//
// Fields:
//   - RuleID: ID of the rule that was violated
//   - Level: Severity level ("error", "warning", "note")
//   - Message: Description of the violation
//   - Locations: Where the violation occurred (file, line, column)
//   - PartialFingerprints: Fingerprints for result deduplication
type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

// SARIFMessage contains text content.
//
// A simple text message used throughout SARIF for descriptions,
// help text, and result messages.
//
// Fields:
//   - Text: The message text
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation specifies where a result was found.
//
// Provides the physical location of a finding in source code.
//
// Fields:
//   - PhysicalLocation: File and position information
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation provides file and region information.
//
// Contains both the file identifier and the specific region within the file
// where the finding occurred.
//
// Fields:
//   - ArtifactLocation: File identification
//   - Region: Line and column information
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation identifies the file.
//
// Specifies which file contains the finding using a URI and optional base ID.
//
// Fields:
//   - URI: File path as URI (forward slashes, relative path)
//   - URIBaseID: Optional base ID for resolving relative paths ("%SRCROOT%")
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion specifies the location within a file.
//
// Defines the specific lines and columns where a finding occurred.
// Line and column numbers are 1-based per SARIF specification.
//
// Fields:
//   - StartLine: Starting line number (1-based)
//   - StartColumn: Starting column number (1-based, optional)
//   - EndLine: Ending line number (optional)
//   - EndColumn: Ending column number (optional)
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// FormatSARIF converts validation results to SARIF 2.1.0 format.
//
// This function generates a SARIF document from validation results, suitable
// for GitHub Code Scanning integration and other static analysis tools.
//
// The generated SARIF includes:
//   - Tool information (name, version, repository URL)
//   - Rule definitions for SQL validation errors
//   - Individual results for each validation error with file locations
//   - Fingerprints for result deduplication
//
// Parameters:
//   - result: Validation results to format
//   - toolVersion: GoSQLX version string (e.g., "1.6.0")
//
// Returns:
//   - JSON-encoded SARIF document
//   - Error if formatting fails
//
// Example:
//
//	result := &ValidationResult{
//	    Files: []FileValidationResult{
//	        {Path: "query.sql", Valid: false, Error: errors.New("syntax error")},
//	    },
//	}
//	sarifData, err := FormatSARIF(result, "1.6.0")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	os.WriteFile("results.sarif", sarifData, 0600)
//
// SARIF Compliance:
//   - Complies with SARIF 2.1.0 specification
//   - Compatible with GitHub Code Scanning
//   - Includes proper schema reference
//   - Uses standard severity levels (error, warning, note)
//
// FormatSARIF converts validation results to SARIF 2.1.0 format
func FormatSARIF(result *ValidationResult, toolVersion string) ([]byte, error) {
	// Create SARIF document
	sarif := &SARIF{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            "GoSQLX",
						Version:         toolVersion,
						SemanticVersion: toolVersion,
						InformationURI:  "https://github.com/ajitpratap0/GoSQLX",
						Rules: []SARIFRule{
							{
								ID:   "sql-syntax-error",
								Name: "SQL Syntax Error",
								ShortDescription: SARIFMessage{
									Text: "SQL syntax validation failed",
								},
								FullDescription: SARIFMessage{
									Text: "The SQL file contains syntax errors that prevent it from being parsed correctly. This may cause runtime errors or unexpected behavior when executed.",
								},
								Help: SARIFMessage{
									Text: "Review the SQL syntax and fix any errors. Common issues include missing keywords, incorrect punctuation, or invalid SQL constructs.",
								},
								Properties: map[string]interface{}{
									"category": "sql-validation",
									"tags":     []string{"sql", "syntax", "validation"},
								},
							},
							{
								ID:   "sql-parsing-error",
								Name: "SQL Parsing Error",
								ShortDescription: SARIFMessage{
									Text: "SQL parsing failed",
								},
								FullDescription: SARIFMessage{
									Text: "The SQL file could not be parsed successfully. This indicates structural issues with the SQL statement.",
								},
								Help: SARIFMessage{
									Text: "Verify the SQL structure is correct and follows the expected SQL dialect syntax.",
								},
								Properties: map[string]interface{}{
									"category": "sql-validation",
									"tags":     []string{"sql", "parsing", "validation"},
								},
							},
							{
								ID:   "sql-tokenization-error",
								Name: "SQL Tokenization Error",
								ShortDescription: SARIFMessage{
									Text: "SQL tokenization failed",
								},
								FullDescription: SARIFMessage{
									Text: "The SQL file could not be tokenized. This usually indicates invalid characters or malformed SQL syntax.",
								},
								Help: SARIFMessage{
									Text: "Check for invalid characters, unmatched quotes, or other tokenization issues in the SQL file.",
								},
								Properties: map[string]interface{}{
									"category": "sql-validation",
									"tags":     []string{"sql", "tokenization", "validation"},
								},
							},
						},
					},
				},
				Results: []SARIFResult{},
			},
		},
	}

	// Add results for invalid files
	for _, fileResult := range result.Files {
		if fileResult.Error != nil {
			sarifResult := createSARIFResult(fileResult)
			sarif.Runs[0].Results = append(sarif.Runs[0].Results, sarifResult)
		}
	}

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	return data, nil
}

// createSARIFResult creates a SARIF result from a file validation result.
//
// Converts a FileValidationResult into a SARIF-compliant result entry,
// including rule classification, location information, and fingerprinting.
//
// Parameters:
//   - fileResult: File validation result to convert
//
// Returns:
//   - SARIF result ready for inclusion in SARIF document
//
// The function:
//   - Classifies the error by rule ID (tokenization, parsing, syntax)
//   - Normalizes file paths to relative URIs
//   - Generates fingerprints for result deduplication
//   - Sets appropriate severity level (currently always "error")
func createSARIFResult(fileResult FileValidationResult) SARIFResult {
	// Determine rule ID based on error message
	ruleID := "sql-syntax-error"
	errorMsg := fileResult.Error.Error()

	if strings.Contains(errorMsg, "tokenization") {
		ruleID = "sql-tokenization-error"
	} else if strings.Contains(errorMsg, "parsing") {
		ruleID = "sql-parsing-error"
	}

	// Normalize path to relative path
	relPath := fileResult.Path
	if filepath.IsAbs(relPath) {
		// Try to make it relative to current directory
		if rel, err := filepath.Rel(".", relPath); err == nil {
			relPath = rel
		}
	}

	// Create partial fingerprint for deduplication
	fingerprint := generateFingerprint(relPath, ruleID, errorMsg)

	return SARIFResult{
		RuleID: ruleID,
		Level:  "error",
		Message: SARIFMessage{
			Text: errorMsg,
		},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI:       normalizeURI(relPath),
						URIBaseID: "%SRCROOT%",
					},
					Region: SARIFRegion{
						StartLine: 1, // Default to line 1 since we don't have line info yet
					},
				},
			},
		},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": fingerprint,
		},
	}
}

// generateFingerprint creates a unique fingerprint for result deduplication.
//
// Generates a stable hash from the combination of file path, rule ID, and error message.
// This fingerprint is used by analysis platforms (like GitHub Code Scanning) to
// deduplicate results across multiple runs.
//
// Parameters:
//   - path: File path where error occurred
//   - ruleID: Rule identifier (e.g., "sql-syntax-error")
//   - message: Error message text
//
// Returns:
//   - 16-character hexadecimal fingerprint string
//
// The fingerprint is generated using SHA-256 hashing and truncated to 8 bytes
// for a balance between uniqueness and compactness.
func generateFingerprint(path, ruleID, message string) string {
	// Create a hash from the combination of path, rule, and message
	h := sha256.New()
	h.Write([]byte(path))
	h.Write([]byte(ruleID))
	h.Write([]byte(message))
	hash := h.Sum(nil)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter fingerprint
}

// normalizeURI converts file paths to URI format with forward slashes.
//
// Normalizes file paths for use in SARIF URIs by:
//   - Converting backslashes to forward slashes (Windows compatibility)
//   - Removing leading "./" prefix for cleaner paths
//
// Parameters:
//   - path: File path to normalize
//
// Returns:
//   - URI-formatted path with forward slashes
//
// This ensures consistent path representation across platforms (Windows, Linux, macOS)
// in SARIF output, which is critical for tool interoperability.
func normalizeURI(path string) string {
	// Convert backslashes to forward slashes for Windows compatibility
	// Note: filepath.ToSlash only converts on Windows, so we do it manually for consistency
	normalized := strings.ReplaceAll(path, "\\", "/")

	// Remove leading ./ if present
	normalized = strings.TrimPrefix(normalized, "./")

	return normalized
}
