// Package output provides output formatting for the gosqlx CLI.
//
// # Overview
//
// This package implements multiple output formats for CLI commands, enabling
// integration with various tools and workflows. It provides structured output
// generation for validation results, analysis reports, and parsing results.
//
// # Supported Formats
//
// ## JSON Format
//
// Structured JSON output for programmatic consumption. Used for:
//   - Validation results
//   - Parse results (AST representation)
//   - Analysis reports
//   - Configuration display
//
// Features:
//   - Indented JSON for readability
//   - Consistent field naming (snake_case)
//   - Comprehensive error information
//   - Metadata inclusion (version, timestamp)
//
// Example:
//
//	{
//	  "version": "1.6.0",
//	  "timestamp": "2024-01-15T10:30:00Z",
//	  "results": [...],
//	  "summary": {...}
//	}
//
// ## YAML Format
//
// YAML output for configuration-style consumption. Used for:
//   - Configuration display
//   - Parse results (alternative to JSON)
//   - Analysis reports (human-readable structured)
//
// Features:
//   - Clean YAML formatting
//   - Comment support for documentation
//   - Compatible with configuration files
//
// Example:
//
//	version: 1.6.0
//	timestamp: 2024-01-15T10:30:00Z
//	results:
//	  - file: query.sql
//	    valid: true
//
// ## SARIF Format (Static Analysis Results Interchange Format)
//
// SARIF 2.1.0 format for GitHub Code Scanning integration. Used for:
//   - Validation results with file locations
//   - Security analysis results
//   - Linting violations
//
// Features:
//   - GitHub Code Scanning integration
//   - Precise error locations (line, column)
//   - Severity levels (error, warning, note)
//   - Rule documentation links
//   - Multi-file support
//
// Example:
//
//	{
//	  "version": "2.1.0",
//	  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
//	  "runs": [{
//	    "tool": {
//	      "driver": {
//	        "name": "GoSQLX",
//	        "version": "1.6.0"
//	      }
//	    },
//	    "results": [...]
//	  }]
//	}
//
// ## Text Format
//
// Human-readable text output with emojis and formatting. Used for:
//   - Default console output
//   - Interactive use
//   - Verbose mode
//
// Features:
//   - Colored output (when supported)
//   - Emoji indicators (✅, ❌, ⚠️)
//   - Progress indicators
//   - Summary statistics
//
// ## Table Format
//
// Tabular output for structured data display. Used for:
//   - Token listings
//   - Statistics summaries
//   - Multi-column data
//
// Features:
//   - Aligned columns
//   - Header rows
//   - Separator lines
//   - Compact presentation
//
// ## Tree Format
//
// Tree visualization for hierarchical data. Used for:
//   - AST structure display
//   - Directory listings
//   - Nested data
//
// Features:
//   - Unicode tree characters (├──, └──)
//   - Indentation for hierarchy
//   - Collapsible sections
//
// # Output Types
//
// ## ValidationResult
//
// Contains results from SQL validation operations:
//
//	type ValidationResult struct {
//	    Files        []FileValidationResult
//	    TotalFiles   int
//	    ValidFiles   int
//	    InvalidFiles int
//	    TotalBytes   int64
//	    Duration     time.Duration
//	}
//
// Used by:
//   - validate command
//   - SARIF output
//   - JSON validation output
//
// ## FileValidationResult
//
// Contains validation result for a single file:
//
//	type FileValidationResult struct {
//	    Path  string
//	    Valid bool
//	    Error error
//	    Size  int64
//	}
//
// Includes:
//   - File path and size
//   - Validation status (valid/invalid)
//   - Error information with location
//
// ## ParseResult
//
// Contains results from SQL parsing operations:
//
//	type ParseResult struct {
//	    AST       *ast.AST
//	    Tokens    []models.TokenWithSpan
//	    Metadata  map[string]interface{}
//	}
//
// Used by:
//   - parse command
//   - JSON parse output
//   - Tree visualization
//
// ## AnalysisResult
//
// Contains results from SQL analysis operations:
//
//	type AnalysisResult struct {
//	    SecurityScore    int
//	    PerformanceScore int
//	    ComplexityScore  int
//	    Issues           []Issue
//	    Recommendations  []string
//	}
//
// Used by:
//   - analyze command
//   - Security reports
//   - JSON analysis output
//
// # Functions
//
// ## FormatValidationJSON
//
// Formats validation results as JSON:
//
//	func FormatValidationJSON(result *ValidationResult, files []string, showStats bool) ([]byte, error)
//
// Parameters:
//   - result: Validation results to format
//   - files: List of processed files
//   - showStats: Include performance statistics
//
// Returns:
//   - JSON-encoded bytes
//   - Error if formatting fails
//
// Usage:
//
//	jsonData, err := output.FormatValidationJSON(result, files, true)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(string(jsonData))
//
// ## FormatSARIF
//
// Formats validation results as SARIF 2.1.0:
//
//	func FormatSARIF(result *ValidationResult, version string) ([]byte, error)
//
// Parameters:
//   - result: Validation results to format
//   - version: Tool version string
//
// Returns:
//   - SARIF-encoded JSON bytes
//   - Error if formatting fails
//
// SARIF features:
//   - Compliant with SARIF 2.1.0 schema
//   - GitHub Code Scanning compatible
//   - Precise error locations
//   - Rule metadata and help
//
// Usage:
//
//	sarifData, err := output.FormatSARIF(result, "1.6.0")
//	if err != nil {
//	    return err
//	}
//	os.WriteFile("results.sarif", sarifData, 0600)
//
// ## FormatParseJSON
//
// Formats parse results as JSON:
//
//	func FormatParseJSON(astObj *ast.AST, source string, includeTokens bool, tokens []models.TokenWithSpan) ([]byte, error)
//
// Parameters:
//   - astObj: AST to format
//   - source: Source file or input description
//   - includeTokens: Whether to include token list
//   - tokens: Token list (if includeTokens is true)
//
// Returns:
//   - JSON-encoded bytes
//   - Error if formatting fails
//
// Output includes:
//   - AST structure (statements, expressions)
//   - Token information (optional)
//   - Metadata (parser version, features)
//
// Usage:
//
//	jsonData, err := output.FormatParseJSON(astObj, "query.sql", true, tokens)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(string(jsonData))
//
// ## FormatPRComment
//
// Formats validation results as GitHub PR comment:
//
//	func FormatPRComment(result *ValidationResult, files []string) string
//
// Parameters:
//   - result: Validation results to format
//   - files: List of processed files
//
// Returns:
//   - Markdown-formatted PR comment
//
// Features:
//   - Markdown formatting
//   - File-by-file breakdown
//   - Summary statistics
//   - Error highlighting
//
// Usage:
//
//	comment := output.FormatPRComment(result, files)
//	// Post to GitHub PR via API
//
// # GitHub Integration
//
// ## GitHub Code Scanning
//
// SARIF output integrates with GitHub Code Scanning:
//
//	# GitHub Actions workflow
//	- name: Validate SQL
//	  run: gosqlx validate --output-format sarif --output-file results.sarif ./sql/
//
//	- name: Upload SARIF
//	  uses: github/codeql-action/upload-sarif@v2
//	  with:
//	    sarif_file: results.sarif
//
// Results appear in:
//   - Pull request checks
//   - Security tab
//   - Code scanning alerts
//
// ## GitHub Pull Request Comments
//
// PR comments provide inline feedback:
//
//	# GitHub Actions workflow
//	- name: Validate SQL
//	  id: validate
//	  run: gosqlx validate -o results.json --output-format json ./sql/
//
//	- name: Comment PR
//	  uses: actions/github-script@v6
//	  with:
//	    script: |
//	      const results = require('./results.json');
//	      const comment = formatPRComment(results);
//	      github.rest.issues.createComment({...});
//
// # CI/CD Integration
//
// Output formats support various CI/CD systems:
//
// ## GitLab CI
//
// JSON output for GitLab Code Quality:
//
//	script:
//	  - gosqlx validate --output-format json -o gl-code-quality-report.json ./sql/
//	artifacts:
//	  reports:
//	    codequality: gl-code-quality-report.json
//
// ## Jenkins
//
// JSON output for Jenkins warnings plugin:
//
//	sh 'gosqlx validate --output-format json -o results.json ./sql/'
//	recordIssues(tools: [java(pattern: 'results.json')])
//
// ## Azure DevOps
//
// SARIF output for Azure DevOps:
//
//   - task: PublishSecurityAnalysisLogs@3
//     inputs:
//     ArtifactName: 'CodeAnalysisLogs'
//     AllTools: false
//     APIScan: false
//     BinSkim: false
//     CredScan: false
//     SARIF: true
//
// # Error Handling
//
// Output formatters handle errors gracefully:
//
//	jsonData, err := output.FormatValidationJSON(result, files, true)
//	if err != nil {
//	    // Possible errors:
//	    // - JSON marshaling failure
//	    // - Invalid result structure
//	    // - Memory allocation failure
//	    return fmt.Errorf("failed to format output: %w", err)
//	}
//
// Formatting errors include context about the failure.
//
// # Performance Considerations
//
// Output formatting is optimized for performance:
//
//   - JSON encoding uses standard library (efficient)
//   - SARIF generation reuses data structures
//   - Large outputs are streamed when possible
//   - Buffer pooling for I/O operations
//
// For large result sets (1000+ files), consider:
//   - Streaming output to file
//   - Batch processing
//   - Compressed output
//
// # Testing
//
// The package includes comprehensive tests:
//
//   - json_test.go: JSON formatting tests
//   - sarif_test.go: SARIF format compliance tests
//   - pr_comment_test.go: PR comment formatting tests
//
// Test coverage includes:
//   - Valid results formatting
//   - Error handling
//   - Edge cases (empty results, large files)
//   - Schema compliance (SARIF)
//
// # Examples
//
// ## Validation Output
//
// Generate JSON validation output:
//
//	result := &output.ValidationResult{
//	    Files: []output.FileValidationResult{
//	        {Path: "query.sql", Valid: true, Size: 1024},
//	        {Path: "broken.sql", Valid: false, Error: errors.New("parse error")},
//	    },
//	    TotalFiles:   2,
//	    ValidFiles:   1,
//	    InvalidFiles: 1,
//	    Duration:     10 * time.Millisecond,
//	}
//
//	jsonData, _ := output.FormatValidationJSON(result, []string{"query.sql", "broken.sql"}, true)
//	fmt.Println(string(jsonData))
//
// ## SARIF Output
//
// Generate SARIF for GitHub Code Scanning:
//
//	result := &output.ValidationResult{
//	    Files: []output.FileValidationResult{
//	        {Path: "query.sql", Valid: false, Error: errors.New("syntax error at line 5")},
//	    },
//	}
//
//	sarifData, _ := output.FormatSARIF(result, "1.6.0")
//	os.WriteFile("results.sarif", sarifData, 0600)
//
// ## Parse Output
//
// Generate JSON for AST:
//
//	astObj := parser.ParseFromModelTokens(tokensWithSpan)
//	jsonData, _ := output.FormatParseJSON(astObj, "query.sql", false, nil)
//	fmt.Println(string(jsonData))
//
// # See Also
//
//   - cmd/gosqlx/cmd/validate.go - Validation command implementation
//   - cmd/gosqlx/cmd/analyze.go - Analysis command implementation
//   - cmd/gosqlx/cmd/parse.go - Parse command implementation
//   - https://sarifweb.azurewebsites.net/ - SARIF specification
//   - https://docs.github.com/en/code-security/code-scanning - GitHub Code Scanning docs
package output
