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

// ValidationResult contains the results of a validation run
type ValidationResult struct {
	TotalFiles   int
	ValidFiles   int
	InvalidFiles int
	TotalBytes   int64
	Duration     time.Duration
	Files        []FileValidationResult
}

// FileValidationResult contains the result for a single file
type FileValidationResult struct {
	Path  string
	Valid bool
	Size  int64
	Error error
}

// SARIF represents a SARIF 2.1.0 document
type SARIF struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool information
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
}

// SARIFRule describes a validation rule
type SARIFRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription SARIFMessage           `json:"shortDescription,omitempty"`
	FullDescription  SARIFMessage           `json:"fullDescription,omitempty"`
	Help             SARIFMessage           `json:"help,omitempty"`
	DefaultLevel     string                 `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFResult represents a single finding
type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

// SARIFMessage contains text content
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation specifies where a result was found
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation provides file and region information
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation identifies the file
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion specifies the location within a file
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

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

// createSARIFResult creates a SARIF result from a file validation result
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

// generateFingerprint creates a unique fingerprint for result deduplication
func generateFingerprint(path, ruleID, message string) string {
	// Create a hash from the combination of path, rule, and message
	h := sha256.New()
	h.Write([]byte(path))
	h.Write([]byte(ruleID))
	h.Write([]byte(message))
	hash := h.Sum(nil)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter fingerprint
}

// normalizeURI converts file paths to URI format with forward slashes
func normalizeURI(path string) string {
	// Convert backslashes to forward slashes for Windows compatibility
	// Note: filepath.ToSlash only converts on Windows, so we do it manually for consistency
	normalized := strings.ReplaceAll(path, "\\", "/")

	// Remove leading ./ if present
	normalized = strings.TrimPrefix(normalized, "./")

	return normalized
}
