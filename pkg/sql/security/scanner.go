// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package security provides SQL injection detection and security scanning for GoSQLX.
//
// The primary entry points are NewScanner (creates a scanner that reports all severity
// levels), NewScannerWithSeverity (creates a scanner filtered to a minimum severity),
// Scanner.Scan (analyzes a parsed *ast.AST via deep tree traversal), and Scanner.ScanSQL
// (analyzes a raw SQL string using pre-compiled regex patterns). Both methods return a
// *ScanResult containing all Findings with severity, pattern type, risk description, and
// remediation suggestions, plus summary counts accessible via HasCritical(),
// HasHighOrAbove(), and IsClean().
//
// # Overview
//
// The security scanner performs static analysis on SQL to detect potential
// injection attacks and unsafe patterns. It uses a combination of AST traversal,
// pattern matching, and heuristic analysis to identify security issues.
//
// # Pattern Detection
//
// The scanner detects 8 types of SQL injection patterns:
//
//   - TAUTOLOGY: Always-true conditions (1=1, 'a'='a') used to bypass authentication
//   - COMMENT_BYPASS: Comment-based injection (--, /**/, #) to bypass validation
//   - UNION_BASED: UNION SELECT patterns for data extraction and schema enumeration
//   - STACKED_QUERY: Multiple statements with destructive operations (DROP, DELETE)
//   - TIME_BASED: Time delay functions (SLEEP, WAITFOR, pg_sleep) for blind injection
//   - OUT_OF_BAND: External data exfiltration (xp_cmdshell, LOAD_FILE, UTL_HTTP)
//   - DANGEROUS_FUNCTION: Dynamic SQL execution (EXEC, sp_executesql, PREPARE FROM)
//   - BOOLEAN_BASED: Conditional logic exploitation for data extraction
//
// # Severity Levels
//
// Each finding is assigned one of four severity levels:
//
//   - CRITICAL: Definite injection pattern detected (e.g., OR 1=1 --)
//   - HIGH: Highly suspicious patterns requiring immediate review
//   - MEDIUM: Potentially unsafe patterns that need investigation
//   - LOW: Informational findings and best practice violations
//
// # Basic Usage
//
// AST-based scanning:
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
//	)
//
//	// Parse SQL into AST
//	ast, err := parser.Parse(tokens)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Scan for security issues
//	scanner := security.NewScanner()
//	results := scanner.Scan(ast)
//
//	// Review findings
//	for _, finding := range results.Findings {
//	    fmt.Printf("[%s] %s: %s\n",
//	        finding.Severity,
//	        finding.Pattern,
//	        finding.Description)
//	}
//
// Raw SQL scanning:
//
//	scanner := security.NewScanner()
//	results := scanner.ScanSQL("SELECT * FROM users WHERE id = 1 OR 1=1 --")
//
//	if results.HasCritical() {
//	    fmt.Println("CRITICAL security issues found!")
//	    for _, f := range results.Findings {
//	        fmt.Printf("  - %s: %s\n", f.Pattern, f.Description)
//	        fmt.Printf("    Risk: %s\n", f.Risk)
//	        fmt.Printf("    Suggestion: %s\n", f.Suggestion)
//	    }
//	}
//
// # Filtering by Severity
//
// Filter findings by minimum severity level:
//
//	// Only report HIGH and CRITICAL findings
//	scanner, err := security.NewScannerWithSeverity(security.SeverityHigh)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	results := scanner.Scan(ast)
//	fmt.Printf("Found %d high-severity issues\n", results.HighCount + results.CriticalCount)
//
// # Scan Results
//
// The ScanResult structure provides comprehensive information:
//
//	results := scanner.Scan(ast)
//
//	fmt.Printf("Total findings: %d\n", results.TotalCount)
//	fmt.Printf("Critical: %d, High: %d, Medium: %d, Low: %d\n",
//	    results.CriticalCount,
//	    results.HighCount,
//	    results.MediumCount,
//	    results.LowCount)
//
//	// Check severity thresholds
//	if results.IsClean() {
//	    fmt.Println("No security issues detected")
//	}
//
//	if results.HasHighOrAbove() {
//	    fmt.Println("High-priority security issues require attention")
//	}
//
// # Finding Details
//
// Each Finding contains detailed information:
//
//	for _, finding := range results.Findings {
//	    fmt.Printf("Pattern: %s\n", finding.Pattern)      // Pattern type
//	    fmt.Printf("Severity: %s\n", finding.Severity)    // Risk level
//	    fmt.Printf("Description: %s\n", finding.Description) // What was found
//	    fmt.Printf("Risk: %s\n", finding.Risk)           // Security impact
//	    fmt.Printf("Suggestion: %s\n", finding.Suggestion) // Remediation advice
//	    if finding.Line > 0 {
//	        fmt.Printf("Location: Line %d, Column %d\n", finding.Line, finding.Column)
//	    }
//	}
//
// # Performance Considerations
//
// The scanner uses pre-compiled regex patterns (initialized once at package load)
// for optimal performance. Scanning is thread-safe and suitable for concurrent use.
// Regex groups are guarded by case-fold-aware literal prefilters derived from each
// pattern at init, so clean input rarely reaches the regex engine.
//
// # Production Integration
//
// Example CI/CD integration:
//
//	scanner := security.NewScanner()
//	results := scanner.ScanSQL(userProvidedSQL)
//
//	if results.HasCritical() {
//	    // Block deployment
//	    log.Fatal("CRITICAL security vulnerabilities detected")
//	}
//
//	if results.HasHighOrAbove() {
//	    // Require security review
//	    fmt.Println("WARNING: High-severity security issues require review")
//	}
//
// # Pattern Examples
//
// TAUTOLOGY detection:
//
//	"SELECT * FROM users WHERE username='admin' OR 1=1 --"
//	→ CRITICAL: Always-true condition detected
//
// UNION_BASED detection:
//
//	"SELECT name FROM products UNION SELECT password FROM users"
//	→ CRITICAL: UNION-based data extraction
//
// TIME_BASED detection:
//
//	"SELECT * FROM orders WHERE id=1 AND SLEEP(5)"
//	→ HIGH: Time-based blind injection
//
// STACKED_QUERY detection:
//
//	"SELECT * FROM users; DROP TABLE users --"
//	→ CRITICAL: Stacked query with destructive operation
//
// # Version
//
// This package is part of GoSQLX v1.6.0 and is production-ready for enterprise use.
package security

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Severity represents the severity level of a security finding.
// It is used to categorize the risk and priority of detected vulnerabilities.
type Severity string

const (
	// SeverityCritical indicates definite injection (e.g., OR 1=1 --)
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh indicates likely injection (suspicious patterns)
	SeverityHigh Severity = "HIGH"
	// SeverityMedium indicates potentially unsafe patterns (needs review)
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow indicates informational findings
	SeverityLow Severity = "LOW"
)

// severityOrder maps severity levels to numeric values for comparison.
// Unknown severities default to highest priority (included in all scans).
var severityOrder = map[Severity]int{
	SeverityLow:      0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// patternGroup is the set of regexes for one PatternType together with the
// severity, risk and suggestion reported for any of them.
type patternGroup struct {
	patterns   []compiledPattern
	severity   Severity
	risk       string
	suggestion string
}

// commentPattern is a comment-bypass regex with its description and severity.
type commentPattern struct {
	compiledPattern
	description string
	severity    Severity
}

// Pre-compiled regex patterns for performance (compiled once at package init)
var (
	// regexGroups is built once by initCompiledPatterns under compiledPatternsOnce
	// and is read-only afterwards, so it is safe for concurrent use.
	regexGroups          map[PatternType]*patternGroup
	compiledPatternsOnce sync.Once

	// Comment detection patterns (pre-compiled)
	commentPatterns     []commentPattern
	commentPatternsOnce sync.Once

	// tautologyCapturePatterns are used by detectTautologyInSQL to find candidate
	// equality pairs. Each pattern captures a left-hand value; the caller verifies
	// that the right-hand value matches. Go RE2 does not support backreferences so
	// the two-step approach is used instead.
	tautologyCapturePatterns []compiledPattern
	tautologyCaptureOnce     sync.Once
)

// initCompiledPatterns initializes all regex patterns once at package level.
func initCompiledPatterns() {
	regexGroups = map[PatternType]*patternGroup{
		// Time-based blind injection functions
		PatternTimeBased: {
			patterns: []compiledPattern{
				compilePattern(`(?i)\bSLEEP[\s\v]*\(`),
				compilePattern(`(?i)\bWAITFOR[\s\v]+DELAY\b`),
				compilePattern(`(?i)\bpg_sleep[\s\v]*\(`),
				compilePattern(`(?i)\bBENCHMARK[\s\v]*\(`),
				compilePattern(`(?i)\bDBMS_LOCK\.SLEEP[\s\v]*\(`),
			},
			severity:   SeverityHigh,
			risk:       "Time-based blind SQL injection",
			suggestion: "Review and sanitize SQL input",
		},

		// Out-of-band / dangerous functions
		PatternOutOfBand: {
			patterns: []compiledPattern{
				compilePattern(`(?i)\bxp_cmdshell\b`),
				compilePattern(`(?i)\bLOAD_FILE[\s\v]*\(`),
				compilePattern(`(?i)\bINTO[\s\v]+OUTFILE\b`),
				compilePattern(`(?i)\bINTO[\s\v]+DUMPFILE\b`),
				compilePattern(`(?i)\bUTL_HTTP\b`),
				compilePattern(`(?i)\bDBMS_LDAP\b`),
				compilePattern(`(?i)\bEXEC[\s\v]+master\b`),
				compilePattern(`(?i)\bsp_oacreate\b`),
				// ClickHouse table functions that reach files, URLs, object
				// stores, other servers or external programs.
				compilePattern(`(?i)\b(?:FROM|JOIN)[\s\v]+(?:url|urlCluster|file|fileCluster|remote|remoteSecure|s3|s3Cluster|gcs|azureBlobStorage|hdfs|hdfsCluster|jdbc|odbc|mysql|postgresql|mongodb|redis|sqlite|executable)[\s\v]*\(`),
			},
			severity:   SeverityCritical,
			risk:       "Out-of-band data exfiltration or command execution",
			suggestion: "Review and sanitize SQL input",
		},

		// Dangerous functions that might indicate injection
		PatternDangerousFunc: {
			patterns: []compiledPattern{
				compilePattern(`(?i)\bEXEC[\s\v]*\(`),
				compilePattern(`(?i)\bEXECUTE[\s\v]+IMMEDIATE\b`),
				compilePattern(`(?i)\bsp_executesql\b`),
				compilePattern(`(?i)\bPREPARE[\s\v]+\w+[\s\v]+FROM\b`),
			},
			severity:   SeverityMedium,
			risk:       "Dynamic SQL execution vulnerability",
			suggestion: "Review and sanitize SQL input",
		},

		// Tautology patterns (always-true conditions used in SQL injection).
		// Note: Go's RE2 engine does not support backreferences, so equality-based
		// tautologies (1=1, 'a'='a') are handled by detectTautologyInSQL; only the
		// simple OR TRUE / || TRUE forms are matched here.
		PatternTautology: {
			patterns: []compiledPattern{
				// OR TRUE
				compilePattern(`(?i)\bOR[\s\v]+TRUE\b`),
				// || TRUE: || is logical OR in MySQL and MariaDB (#781), so
				// ' || TRUE -- is the same bypass as ' OR TRUE --.
				compilePattern(`(?i)\|\|[\s\v]*TRUE\b`),
			},
			severity:   SeverityCritical,
			risk:       "Authentication bypass via always-true condition",
			suggestion: "Use parameterized queries to prevent tautology injection",
		},

		// UNION injection fingerprints (CRITICAL): system table access or NULL-padding.
		// Also detects bare references to system catalogs, which are injection fingerprints
		// regardless of whether a UNION is present.
		PatternUnionInjection: {
			patterns: []compiledPattern{
				// System table access via UNION (injection fingerprint)
				compilePattern(`(?i)UNION[\s\v]+(ALL[\s\v]+)?SELECT.*\b(information_schema|pg_catalog|mysql\b|sys\.)\b`),
				// NULL-padded columns (classic injection to match column count)
				compilePattern(`(?i)UNION[\s\v]+(ALL[\s\v]+)?SELECT[\s\v]+(?:NULL,?[\s\v]*){2,}`),
				// Bare system catalog references (schema enumeration fingerprint)
				compilePattern(`(?i)\binformation_schema\b`),
			},
			severity:   SeverityCritical,
			risk:       "UNION-based SQL injection with injection fingerprint (system table or NULL padding)",
			suggestion: "Use parameterized queries and block system table access",
		},

		// Generic UNION SELECT (HIGH): may be legitimate or injection
		PatternUnionGeneric: {
			patterns: []compiledPattern{
				compilePattern(`(?i)\bUNION[\s\v]+(ALL[\s\v]+)?SELECT\b`),
			},
			severity:   SeverityHigh,
			risk:       "Possible UNION-based data extraction; review for legitimacy",
			suggestion: "Verify UNION is intentional and all inputs are parameterized",
		},

		// Stacked query injection patterns (destructive statements after semicolon)
		PatternStackedQuery: {
			patterns: []compiledPattern{
				compilePattern(`;[\s\v]*(?i)(DROP|DELETE|TRUNCATE|UPDATE|INSERT|ALTER)\b`),
				compilePattern(`;[\s\v]*(?i)EXEC\b`),
				compilePattern(`;[\s\v]*(?i)EXECUTE\b`),
			},
			severity:   SeverityCritical,
			risk:       "Stacked query injection with destructive operations",
			suggestion: "Block semicolons in user input or use parameterized queries",
		},
	}
}

// initCommentPatterns initializes comment detection patterns once.
func initCommentPatterns() {
	commentPatterns = []commentPattern{
		{compilePattern(`--[\s\v]*$`), "Trailing SQL comment may indicate injection", SeverityMedium},
		{compilePattern(`--[\s\v]*['")\]]`), "Comment after quote/bracket (potential bypass)", SeverityHigh},
		{compilePattern(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/[\s\v]*$`), "Unclosed or trailing block comment may indicate injection", SeverityMedium},
		{compilePattern(`(?is)/\*(?:M)?!.*\*/`), "MySQL conditional comment (version-specific execution)", SeverityMedium},
		{compilePattern(`#[\s\v]*$`), "Hash comment at end (MySQL)", SeverityMedium},
		{compilePattern(`;[\s\v]*--`), "Statement terminator followed by comment", SeverityHigh},
	}
}

// MaxScanInputSize matches tokenizer.MaxInputSize (10 MiB). Larger inputs are
// rejected with an unconditional CRITICAL finding before lexical processing or regex matching.
const MaxScanInputSize = 10 * 1024 * 1024

// initTautologyCapturePatterns initializes patterns used to detect raw-SQL tautologies.
// Because Go's RE2 engine does not support backreferences, each pattern captures both
// sides of an equality; detectTautologyInSQL then verifies the two captured groups
// are equal before reporting a finding.
func initTautologyCapturePatterns() {
	tautologyCapturePatterns = []compiledPattern{
		// Numeric: two identical digit sequences around '=' (bounded to prevent ReDoS)
		compilePattern(`(?i)\b(\d{1,6})[\s\v]*=[\s\v]*(\d{1,6})\b`),
		// String literal: 'value' = 'value' (max 50 chars per side, no backtracking risk)
		compilePattern(`(?i)('[^']{0,50}')[\s\v]*=[\s\v]*('[^']{0,50}')`),
		// Identifier: col = col (bounded length, word chars + dots)
		compilePattern(`(?i)\b([a-z_][a-z0-9_.]{0,50})[\s\v]*=[\s\v]*([a-z_][a-z0-9_.]{0,50})\b`),
	}
}

// System table prefixes for precise matching (avoids false positives)
var systemTablePrefixes = []string{
	"information_schema.",
	"sys.",
	"mysql.",
	"pg_catalog.",
	"pg_",
	"sqlite_",
	"master.dbo.",
	"msdb.",
	"tempdb.",
}

// Exact system table names
var systemTableNames = []string{
	"information_schema",
	"pg_catalog",
	"sys",
}

// PatternType categorizes the type of SQL injection pattern detected by the scanner.
// Each pattern type represents a specific attack vector or vulnerability class.
type PatternType string

const (
	// PatternInputTooLarge indicates input that was not scanned due to its size.
	PatternInputTooLarge PatternType = "INPUT_TOO_LARGE"

	// PatternTautology detects always-true conditions (1=1, 'a'='a') used to bypass authentication
	PatternTautology PatternType = "TAUTOLOGY"

	// PatternComment detects comment-based injection (--, /**/, #) to bypass validation
	PatternComment PatternType = "COMMENT_BYPASS"

	// PatternStackedQuery detects multiple statements with destructive operations (DROP, DELETE)
	PatternStackedQuery PatternType = "STACKED_QUERY"

	// PatternUnionBased detects UNION SELECT patterns for data extraction and schema enumeration
	PatternUnionBased PatternType = "UNION_BASED"

	// PatternUnionInjection detects UNION SELECT patterns with injection fingerprints (system
	// table access or NULL-column padding). This is a CRITICAL severity signal used by ScanSQL.
	PatternUnionInjection PatternType = "UNION_INJECTION"

	// PatternUnionGeneric detects any UNION SELECT pattern. HIGH severity - may be legitimate.
	// Used by ScanSQL to flag generic UNION SELECT for review.
	PatternUnionGeneric PatternType = "UNION_GENERIC"

	// PatternTimeBased detects time delay functions (SLEEP, WAITFOR, pg_sleep) for blind injection
	PatternTimeBased PatternType = "TIME_BASED"

	// PatternBooleanBased detects conditional logic exploitation for data extraction
	PatternBooleanBased PatternType = "BOOLEAN_BASED"

	// PatternOutOfBand detects external data exfiltration (xp_cmdshell, LOAD_FILE, UTL_HTTP)
	PatternOutOfBand PatternType = "OUT_OF_BAND"

	// PatternDangerousFunc detects dynamic SQL execution (EXEC, sp_executesql, PREPARE FROM)
	PatternDangerousFunc PatternType = "DANGEROUS_FUNCTION"
)

// Finding represents a single security finding from the scanner.
// It contains detailed information about a detected vulnerability including
// severity, pattern type, location, and remediation suggestions.
type Finding struct {
	// Severity indicates the risk level (CRITICAL, HIGH, MEDIUM, LOW)
	Severity Severity `json:"severity"`

	// Pattern indicates the type of injection pattern detected
	Pattern PatternType `json:"pattern"`

	// Description provides human-readable explanation of what was found
	Description string `json:"description"`

	// Risk describes the potential security impact
	Risk string `json:"risk"`

	// Line number where the issue was detected (if available)
	Line int `json:"line,omitempty"`

	// Column number where the issue was detected (if available)
	Column int `json:"column,omitempty"`

	// SQL contains the problematic SQL fragment (if available)
	SQL string `json:"sql,omitempty"`

	// Suggestion provides remediation advice
	Suggestion string `json:"suggestion,omitempty"`
}

// ScanResult contains all findings from a security scan along with summary statistics.
// Use the helper methods HasCritical(), HasHighOrAbove(), and IsClean() to
// quickly assess the scan results.
type ScanResult struct {
	// Findings contains all detected security issues
	Findings []Finding `json:"findings"`

	// TotalCount is the total number of findings across all severity levels
	TotalCount int `json:"total_count"`

	// CriticalCount is the number of CRITICAL severity findings
	CriticalCount int `json:"critical_count"`

	// HighCount is the number of HIGH severity findings
	HighCount int `json:"high_count"`

	// MediumCount is the number of MEDIUM severity findings
	MediumCount int `json:"medium_count"`

	// LowCount is the number of LOW severity findings
	LowCount int `json:"low_count"`
}

// Scanner performs security analysis on SQL ASTs and raw SQL strings.
// It detects SQL injection patterns using a combination of AST traversal,
// regex pattern matching, and heuristic analysis.
//
// Scanner is safe for concurrent use from multiple goroutines as it uses
// pre-compiled patterns and maintains no mutable state during scanning.
//
// Example usage:
//
//	scanner := security.NewScanner()
//	results := scanner.Scan(ast)
//	if results.HasCritical() {
//	    log.Fatal("Critical security issues detected")
//	}
type Scanner struct {
	// MinSeverity filters findings below this severity level.
	// Only findings with severity >= MinSeverity are included in results.
	MinSeverity Severity
}

// NewScanner creates a new security scanner with default settings.
// The default scanner reports all findings (MinSeverity = SeverityLow).
//
// The scanner is immediately ready to use and is safe for concurrent scanning
// from multiple goroutines.
//
// Example:
//
//	scanner := security.NewScanner()
//	results := scanner.Scan(ast)
func NewScanner() *Scanner {
	// Initialize package-level patterns once
	compiledPatternsOnce.Do(initCompiledPatterns)
	commentPatternsOnce.Do(initCommentPatterns)
	tautologyCaptureOnce.Do(initTautologyCapturePatterns)

	return &Scanner{
		MinSeverity: SeverityLow,
	}
}

// NewScannerWithSeverity creates a scanner filtering by minimum severity.
// Only findings at or above the specified severity level will be reported.
//
// Returns an error if the severity level is not recognized. Valid severity levels are:
// SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical.
//
// Example:
//
//	// Only report HIGH and CRITICAL findings
//	scanner, err := security.NewScannerWithSeverity(security.SeverityHigh)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	results := scanner.Scan(ast)
func NewScannerWithSeverity(minSeverity Severity) (*Scanner, error) {
	// Validate severity
	if !isValidSeverity(minSeverity) {
		return nil, fmt.Errorf("invalid severity level: %s", minSeverity)
	}

	s := NewScanner()
	s.MinSeverity = minSeverity
	return s, nil
}

// isValidSeverity checks if a severity level is recognized.
func isValidSeverity(severity Severity) bool {
	_, exists := severityOrder[severity]
	return exists
}

// Scan analyzes a parsed SQL AST for SQL injection patterns and vulnerabilities.
// It performs deep traversal of the AST to detect suspicious patterns including
// tautologies, dangerous functions, UNION-based injection, and other attack vectors.
//
// The method is safe for concurrent use as it does not modify the Scanner state.
//
// Returns a ScanResult containing all detected findings that meet the MinSeverity
// threshold, along with summary statistics by severity level.
//
// Example:
//
//	ast, err := parser.Parse(tokens)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	scanner := security.NewScanner()
//	results := scanner.Scan(ast)
//
//	fmt.Printf("Found %d security issues\n", results.TotalCount)
//	for _, finding := range results.Findings {
//	    fmt.Printf("[%s] %s\n", finding.Severity, finding.Description)
//	}
func (s *Scanner) Scan(tree *ast.AST) *ScanResult {
	result := &ScanResult{
		Findings: make([]Finding, 0),
	}

	if tree == nil {
		return result
	}

	// Ancestry is local to the scan, so concurrent scans share no walk state.
	// Preallocated so typical nesting depths need no regrowth.
	ancestors := make([]ast.Node, 0, 16)
	ast.Inspect(tree, func(node ast.Node) bool {
		if node == nil {
			ancestors = ancestors[:len(ancestors)-1]
			return false
		}
		var parent ast.Node
		if len(ancestors) > 0 {
			parent = ancestors[len(ancestors)-1]
		}
		if join, ok := parent.(*ast.JoinClause); ok && node == &join.Left {
			// Left repeats FROM or an earlier join's right reference,
			// including its subquery and table function.
			return false
		}
		switch n := node.(type) {
		case *ast.FunctionCall:
			s.scanFunctionCall(n, result)
			s.scanCondition(n.Filter, result)
		case *ast.TableReference:
			s.scanTableReference(n, result)
		case *ast.SetOperation:
			// Direct operands are already checked by the outer operation.
			// Operations inside CTEs and subqueries start a new check.
			if _, nested := parent.(*ast.SetOperation); !nested {
				s.checkUnionInjection(n, false, result)
			}
		case *ast.SelectStatement:
			s.scanCondition(n.Where, result)
			s.scanCondition(n.Having, result)
			s.scanCondition(n.Qualify, result)
			s.scanCondition(n.PrewhereClause, result)
			s.scanCondition(n.StartWith, result)
		case *ast.ConnectByClause:
			s.scanCondition(n.Condition, result)
		case *ast.JoinClause:
			s.scanCondition(n.Condition, result)
			s.scanCondition(n.MatchCondition, result)
		case *ast.UpdateStatement:
			s.scanCondition(n.Where, result)
		case *ast.Update:
			s.scanCondition(n.Where, result)
		case *ast.DeleteStatement:
			s.scanCondition(n.Where, result)
		case *ast.Delete:
			s.scanCondition(n.Where, result)
		case *ast.MergeStatement:
			s.scanCondition(n.OnCondition, result)
		case *ast.MergeWhenClause:
			s.scanCondition(n.Condition, result)
		case *ast.MergeAction:
			s.scanCondition(n.Where, result)
			s.scanCondition(n.DeleteWhere, result)
		case *ast.WhenClause:
			s.scanCondition(n.Condition, result)
		case *ast.OnConflict:
			s.scanCondition(n.TargetWhere, result)
			s.scanCondition(n.Action.Where, result)
		case *ast.Values:
			s.scanStatementText(n.SQL(), result)
			return false
		case *ast.UtilityStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.SetStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.TransactionStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.UseStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.UnsupportedStatement:
			s.scanStatementText(n.RawSQL, result)
			return false
		}
		ancestors = append(ancestors, node)
		return true
	})

	// Update counts
	s.updateCounts(result)

	return result
}

// ScanSQL analyzes raw SQL string for injection patterns using regex-based detection.
// This method is useful for detecting patterns that might not be visible in the AST,
// such as SQL comments, or when you don't have a parsed AST available.
//
// The method uses pre-compiled regex patterns to detect:
//   - Comment-based injection (--, /**/, #)
//   - Time-based blind injection (SLEEP, WAITFOR, pg_sleep, BENCHMARK)
//   - Out-of-band data exfiltration (xp_cmdshell, LOAD_FILE, UTL_HTTP,
//     ClickHouse FROM url/file/remote/s3/... table functions)
//   - Dangerous functions (EXEC, sp_executesql, PREPARE FROM)
//   - UNION-based injection (UNION SELECT, information_schema)
//   - Stacked query injection (semicolon-separated destructive statements)
//
// The method is safe for concurrent use.
//
// Example:
//
//	scanner := security.NewScanner()
//	results := scanner.ScanSQL("SELECT * FROM users WHERE id = 1 OR 1=1 --")
//
//	if results.HasCritical() {
//	    fmt.Println("CRITICAL security issue detected!")
//	    for _, finding := range results.Findings {
//	        fmt.Printf("  %s: %s\n", finding.Pattern, finding.Description)
//	    }
//	}
func (s *Scanner) ScanSQL(sql string) *ScanResult {
	return s.scanSQL(sql, true)
}

// scanSQL implements ScanSQL. With prefilter set, each regex is skipped when the
// case-folded input lacks one of the literals every match must contain. With
// prefilter unset every regex runs; tests use that path as the reference
// implementation to prove the prefilters never change findings.
func (s *Scanner) scanSQL(sql string, prefilter bool) *ScanResult {
	result := &ScanResult{
		Findings: make([]Finding, 0),
	}

	if len(sql) > MaxScanInputSize {
		result.Findings = append(result.Findings, Finding{
			Severity:    SeverityCritical,
			Pattern:     PatternInputTooLarge,
			Description: fmt.Sprintf("input exceeds maximum scannable size (%d bytes > %d bytes); not scanned", len(sql), MaxScanInputSize),
			Risk:        "SQL could not be checked for injection",
			Suggestion:  "Reject oversized SQL or reduce it below the scanning limit",
		})
		s.updateCounts(result)
		return result
	}

	// Strip dollar-quoted string content to prevent false positives
	sql = stripDollarQuotedStrings(sql)

	// Case-fold the whole stripped input once for the literal prefilters. A nil
	// folded slice disables prefiltering.
	var folded []byte
	if prefilter {
		bp := getFoldBuf()
		defer putFoldBuf(bp)
		// Folding never grows beyond the input length. Reserve once so large
		// inputs do not allocate a succession of increasingly large buffers.
		if cap(*bp) < len(sql) {
			*bp = make([]byte, 0, len(sql))
		}
		folded = foldASCII((*bp)[:0], sql)
		*bp = folded
	}

	// Check for comment-based bypass patterns in raw SQL
	s.detectCommentPatterns(sql, folded, result)

	// Normalized views only add matches. Required prefilter literals contain no
	// whitespace, so removing comments cannot introduce a literal absent in raw.
	views := append([]string{sql}, commentViews(sql)...)

	// Check for tautology patterns (OR 1=1, 'a'='a', etc.)
	// detectRegexPatterns handles the simple OR TRUE pattern; detectTautologyInSQL
	// handles equality-based tautologies using a two-step capture approach (RE2
	// does not support backreferences, so equality is verified programmatically).
	s.detectRegexPatterns(views, folded, PatternTautology, result)
	s.detectTautologyInSQL(views, folded, result)

	// Check for time-based patterns
	s.detectRegexPatterns(views, folded, PatternTimeBased, result)

	// Check for out-of-band patterns
	s.detectRegexPatterns(views, folded, PatternOutOfBand, result)

	// Check for dangerous function patterns
	s.detectRegexPatterns(views, folded, PatternDangerousFunc, result)

	// Check for UNION injection fingerprints (CRITICAL: system tables, NULL-padding)
	s.detectRegexPatterns(views, folded, PatternUnionInjection, result)

	// Check for generic UNION SELECT (HIGH: may be legitimate, but warrants review)
	s.detectRegexPatterns(views, folded, PatternUnionGeneric, result)

	// Check for stacked query patterns
	s.detectRegexPatterns(views, folded, PatternStackedQuery, result)

	// Update counts
	s.updateCounts(result)

	return result
}

// scanStatementText covers statements whose bodies are retained as text rather
// than expression nodes, including PREPARE/EXECUTE, T-SQL blocks and CREATE
// POLICY/TRIGGER. These nodes take only the text path, so AST and text checks
// cannot report the same occurrence twice. Counts are updated once by Scan.
func (s *Scanner) scanStatementText(text string, result *ScanResult) {
	findings := s.ScanSQL(text)
	result.Findings = append(result.Findings, findings.Findings...)
}

// scanTableReference checks a function-call table reference such as
// ClickHouse FROM url(...) or PostgreSQL FROM generate_series(...): the
// function name is checked against the out-of-band table functions. Inspect
// separately visits the FunctionCall and its arguments.
func (s *Scanner) scanTableReference(ref *ast.TableReference, result *ScanResult) {
	if ref == nil || ref.TableFunc == nil {
		return
	}
	if risk, found := outOfBandTableFuncNames[strings.ToUpper(ref.TableFunc.Name)]; found {
		finding := Finding{
			Severity:    SeverityCritical,
			Pattern:     PatternOutOfBand,
			Description: "Out-of-band table function detected: " + ref.TableFunc.Name,
			Risk:        risk,
			Suggestion:  "Block table functions that reach files, URLs or other servers, or use an allowlist",
		}
		if s.shouldInclude(finding.Severity) {
			result.Findings = append(result.Findings, finding)
		}
	}
}

// scanCondition checks tautologies through boolean expression structure only.
// Inspect separately handles functions and nested statements.
func (s *Scanner) scanCondition(expr ast.Expression, result *ScanResult) {
	switch e := expr.(type) {
	case *ast.BinaryExpression:
		s.scanBinaryExpression(e, result)
	case *ast.UnaryExpression:
		s.scanCondition(e.Expr, result)
	case *ast.ParenthesizedExpression:
		s.scanCondition(e.Expr, result)
	}
}

// scanBinaryExpression checks for tautologies and suspicious patterns.
func (s *Scanner) scanBinaryExpression(expr *ast.BinaryExpression, result *ScanResult) {
	if expr == nil {
		return
	}

	// Check for tautologies (always true conditions)
	if s.isTautology(expr) {
		finding := Finding{
			Severity:    SeverityCritical,
			Pattern:     PatternTautology,
			Description: "Always-true condition detected (tautology)",
			Risk:        "Authentication bypass, data extraction",
			Suggestion:  "Remove or replace with proper condition",
		}
		if s.shouldInclude(finding.Severity) {
			result.Findings = append(result.Findings, finding)
		}
	}

	// Check for OR-based injection patterns
	if strings.ToUpper(expr.Operator) == "OR" {
		s.checkOrInjection(expr, result)
	}

	// Recursively check sub-expressions
	s.scanCondition(expr.Left, result)
	s.scanCondition(expr.Right, result)
}

// isTautology checks if an expression is always true.
func (s *Scanner) isTautology(expr *ast.BinaryExpression) bool {
	if expr == nil {
		return false
	}

	op := strings.ToUpper(expr.Operator)
	if op != "=" && op != "==" {
		return false
	}

	// Check for LiteralValue tautologies: 1=1, 2=2, 'a'='a', etc.
	left, right := unwrapParens(expr.Left), unwrapParens(expr.Right)
	leftLit, leftIsLit := left.(*ast.LiteralValue)
	rightLit, rightIsLit := right.(*ast.LiteralValue)

	if leftIsLit && rightIsLit {
		// Same literal values
		leftVal := fmt.Sprintf("%v", leftLit.Value)
		rightVal := fmt.Sprintf("%v", rightLit.Value)
		if leftVal == rightVal {
			return true
		}
	}

	// Check for identifier tautologies: col=col
	leftIdent, leftIsIdent := left.(*ast.Identifier)
	rightIdent, rightIsIdent := right.(*ast.Identifier)

	if leftIsIdent && rightIsIdent {
		if leftIdent.Name == rightIdent.Name && leftIdent.Table == rightIdent.Table {
			return true
		}
	}

	return false
}

// checkOrInjection checks for OR-based injection patterns.
func (s *Scanner) checkOrInjection(expr *ast.BinaryExpression, result *ScanResult) {
	// Check if the OR condition contains a tautology
	if rightBin, ok := unwrapParens(expr.Right).(*ast.BinaryExpression); ok {
		if s.isTautology(rightBin) {
			finding := Finding{
				Severity:    SeverityCritical,
				Pattern:     PatternTautology,
				Description: "OR condition with tautology detected (e.g., OR 1=1)",
				Risk:        "Authentication bypass, unauthorized data access",
				Suggestion:  "Review and sanitize input parameters",
			}
			if s.shouldInclude(finding.Severity) {
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	if leftBin, ok := unwrapParens(expr.Left).(*ast.BinaryExpression); ok {
		if s.isTautology(leftBin) {
			finding := Finding{
				Severity:    SeverityCritical,
				Pattern:     PatternTautology,
				Description: "OR condition with tautology detected",
				Risk:        "Authentication bypass, unauthorized data access",
				Suggestion:  "Review and sanitize input parameters",
			}
			if s.shouldInclude(finding.Severity) {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
}

// unwrapParens strips any number of enclosing ParenthesizedExpression nodes so
// that grouping parentheses, e.g. `OR (1 = 1)`, do not hide injection patterns.
func unwrapParens(expr ast.Expression) ast.Expression {
	for {
		p, ok := expr.(*ast.ParenthesizedExpression)
		if !ok || p == nil {
			return expr
		}
		expr = p.Expr
	}
}

// checkUnionInjection analyzes UNION for potential data extraction. It walks
// the whole set-operation tree and checks every SELECT that appears anywhere in
// the right-hand operand of a UNION (inUnionRight), including the leftmost
// SELECT of a parenthesized group such as "x UNION (SELECT ... UNION ...)".
// Each SELECT is visited exactly once, so no finding is reported twice.
func (s *Scanner) checkUnionInjection(stmt *ast.SetOperation, inUnionRight bool, result *ScanResult) {
	isUnion := strings.EqualFold(stmt.Operator, "UNION")
	s.checkUnionOperand(stmt.Left, inUnionRight, result)
	s.checkUnionOperand(stmt.Right, inUnionRight || isUnion, result)
}

// checkUnionOperand dispatches one set-operation operand for checkUnionInjection.
func (s *Scanner) checkUnionOperand(operand ast.Statement, inUnionRight bool, result *ScanResult) {
	switch op := operand.(type) {
	case *ast.SetOperation:
		s.checkUnionInjection(op, inUnionRight, result)
	case *ast.SelectStatement:
		if inUnionRight {
			s.checkUnionSelect(op, result)
		}
	}
}

// checkUnionSelect checks a single SELECT used as a UNION operand.
func (s *Scanner) checkUnionSelect(rightSelect *ast.SelectStatement, result *ScanResult) {
	// Check for NULL placeholders (common in UNION injection)
	nullCount := 0
	for _, col := range rightSelect.Columns {
		if alias, ok := col.(*ast.AliasedExpression); ok && alias != nil {
			col = alias.Expr
		}
		if literal, ok := col.(*ast.LiteralValue); ok && literal != nil {
			if strings.EqualFold(literal.Type, "null") {
				nullCount++
			}
		} else if ident, ok := col.(*ast.Identifier); ok && ident != nil {
			if strings.EqualFold(ident.Name, "NULL") {
				nullCount++
			}
		}
	}

	// Multiple NULLs in UNION SELECT is suspicious
	if nullCount >= 2 {
		finding := Finding{
			Severity:    SeverityHigh,
			Pattern:     PatternUnionBased,
			Description: "UNION SELECT with multiple NULL columns detected",
			Risk:        "Data extraction via UNION-based injection",
			Suggestion:  "Verify UNION is intentional and inputs are sanitized",
		}
		if s.shouldInclude(finding.Severity) {
			result.Findings = append(result.Findings, finding)
		}
	}

	// Check for system table access using precise matching
	if rightSelect.TableName != "" {
		if s.isSystemTable(rightSelect.TableName) {
			finding := Finding{
				Severity:    SeverityCritical,
				Pattern:     PatternUnionBased,
				Description: "UNION SELECT accessing system tables detected",
				Risk:        "Database schema enumeration, privilege escalation",
				Suggestion:  "Block access to system tables from user queries",
			}
			if s.shouldInclude(finding.Severity) {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
}

// isSystemTable checks if a table name refers to a system table using precise matching.
// Uses prefix matching and exact name matching to avoid false positives.
func (s *Scanner) isSystemTable(tableName string) bool {
	tableLower := strings.ToLower(tableName)

	// Check exact matches first
	for _, name := range systemTableNames {
		if tableLower == name {
			return true
		}
	}

	// Check prefix matches (e.g., "information_schema.tables", "pg_class")
	for _, prefix := range systemTablePrefixes {
		if strings.HasPrefix(tableLower, prefix) {
			return true
		}
	}

	return false
}

// timeBasedFuncNames lists time-based blind injection functions (upper case).
// Read-only after package init; safe for concurrent use.
var timeBasedFuncNames = map[string]bool{
	"SLEEP":     true,
	"PG_SLEEP":  true,
	"BENCHMARK": true,
	"WAITFOR":   true,
}

// dangerousFuncNames maps out-of-band / dangerous functions (upper case) to their
// risk. Read-only after package init; safe for concurrent use.
var dangerousFuncNames = map[string]string{
	"LOAD_FILE":     "File system access",
	"LOAD DATA":     "File system access",
	"XP_CMDSHELL":   "Command execution",
	"SP_OACREATE":   "OLE automation",
	"UTL_HTTP":      "Network access",
	"DBMS_LDAP":     "LDAP access",
	"EXEC":          "Dynamic SQL execution",
	"SP_EXECUTESQL": "Dynamic SQL execution",
}

// outOfBandTableFuncNames maps ClickHouse table functions (upper case) that
// read from or write to files, URLs, object stores, other database servers or
// external programs to their risk. They are only matched on table-function
// references in FROM/JOIN, not on ordinary function calls, to avoid flagging
// unrelated scalar functions that share a name. Read-only after package init;
// safe for concurrent use.
var outOfBandTableFuncNames = map[string]string{
	"URL":              "Network access",
	"URLCLUSTER":       "Network access",
	"FILE":             "File system access",
	"FILECLUSTER":      "File system access",
	"REMOTE":           "Remote server access",
	"REMOTESECURE":     "Remote server access",
	"S3":               "Object storage access",
	"S3CLUSTER":        "Object storage access",
	"GCS":              "Object storage access",
	"AZUREBLOBSTORAGE": "Object storage access",
	"HDFS":             "Remote file system access",
	"HDFSCLUSTER":      "Remote file system access",
	"JDBC":             "Remote database access",
	"ODBC":             "Remote database access",
	"MYSQL":            "Remote database access",
	"POSTGRESQL":       "Remote database access",
	"MONGODB":          "Remote database access",
	"REDIS":            "Remote database access",
	"SQLITE":           "File system access",
	"EXECUTABLE":       "Command execution",
}

// scanFunctionCall checks only this call name; Inspect visits its children.
func (s *Scanner) scanFunctionCall(fn *ast.FunctionCall, result *ScanResult) {
	if fn == nil {
		return
	}

	funcName := strings.ToUpper(fn.Name)
	// A schema- or package-qualified call (pg_catalog.pg_sleep(5),
	// DBMS_LOCK.SLEEP(5), UTL_HTTP.REQUEST(...)) is matched on its last part,
	// and on its qualifiers for the package-level dangerous names.
	baseName, qualifiers := funcName, ""
	if i := strings.LastIndexByte(funcName, '.'); i >= 0 {
		baseName, qualifiers = funcName[i+1:], funcName[:i]
	}

	if timeBasedFuncNames[baseName] {
		finding := Finding{
			Severity:    SeverityHigh,
			Pattern:     PatternTimeBased,
			Description: "Time-based blind injection function detected: " + fn.Name,
			Risk:        "Time-based blind SQL injection, DoS",
			Suggestion:  "Block or restrict time delay functions",
		}
		if s.shouldInclude(finding.Severity) {
			result.Findings = append(result.Findings, finding)
		}
	}

	risk, found := dangerousFuncNames[baseName]
	for q := qualifiers; !found && q != ""; {
		part := q
		if i := strings.IndexByte(q, '.'); i >= 0 {
			part, q = q[:i], q[i+1:]
		} else {
			q = ""
		}
		risk, found = dangerousFuncNames[part]
	}
	if found {
		finding := Finding{
			Severity:    SeverityCritical,
			Pattern:     PatternOutOfBand,
			Description: "Dangerous function detected: " + fn.Name,
			Risk:        risk,
			Suggestion:  "Block dangerous functions or use allowlist",
		}
		if s.shouldInclude(finding.Severity) {
			result.Findings = append(result.Findings, finding)
		}
	}

}

// detectCommentPatterns checks raw SQL for comment-based injection. folded is the
// case-folded input used for literal prefiltering; nil disables prefiltering.
func (s *Scanner) detectCommentPatterns(sql string, folded []byte, result *ScanResult) {
	// Ensure patterns are initialized
	commentPatternsOnce.Do(initCommentPatterns)

	for _, p := range commentPatterns {
		if folded != nil && !containsAll(folded, p.lits) {
			continue
		}
		if p.re.MatchString(sql) {
			finding := Finding{
				Severity:    p.severity,
				Pattern:     PatternComment,
				Description: p.description,
				Risk:        "SQL injection via comment-based bypass",
				Suggestion:  "Sanitize input to remove SQL comments",
			}
			if s.shouldInclude(finding.Severity) {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
}

// detectTautologyInSQL checks raw and normalized views for tautology patterns (e.g. OR 1=1, 'a'='a').
// Because Go's RE2 engine does not support backreferences, equality of the two sides
// is verified programmatically after the regex captures both groups. folded is the
// case-folded input used for literal prefiltering; nil disables prefiltering.
func (s *Scanner) detectTautologyInSQL(views []string, folded []byte, result *ScanResult) {
	// Ensure patterns are initialized
	tautologyCaptureOnce.Do(initTautologyCapturePatterns)

	for patternIndex, p := range tautologyCapturePatterns {
		if folded != nil && !containsAll(folded, p.lits) {
			continue
		}
	viewsLoop:
		for _, input := range views {
			// Pattern zero captures whole numeric operands. Reject unequal
			// digit runs before invoking RE2 repeatedly: under race detection,
			// sync.Pool intentionally drops regex machines on frequent calls.
			// The unfiltered path remains the equivalence-test reference.
			if patternIndex == 0 && folded != nil && !hasEqualNumericPair(input) {
				continue
			}
			for rest := input; rest != ""; {
				// FindString uses a stack capture buffer; SubmatchIndex allocates
				// an index slice for every unequal pair on large inputs.
				m := p.re.FindString(rest)
				if m == "" {
					break
				}
				if equalSQLPair(m) {
					finding := Finding{
						Severity:    SeverityCritical,
						Pattern:     PatternTautology,
						Description: "Always-true condition detected (tautology): " + m,
						Risk:        "Authentication bypass via always-true condition",
						Suggestion:  "Use parameterized queries to prevent tautology injection",
					}
					if s.shouldInclude(finding.Severity) {
						result.Findings = append(result.Findings, finding)
					}
					// Report at most one tautology finding per pattern across all views.
					break viewsLoop
				}
				rest = rest[sqlPairMatchEnd(rest, m):]
			}
		}
	}
}

// sqlPairMatchEnd locates the exact capture-pattern match without allocating an
// index slice. Numeric/identifier patterns require ASCII word boundaries; an
// earlier occurrence of the same text inside an identifier is not that match.
// The quoted pattern has no boundary assertions. All patterns match nonempty
// text, and advancing to its actual end preserves the next match's boundary.
func sqlPairMatchEnd(sql, match string) int {
	for offset := 0; offset < len(sql); {
		relative := strings.Index(sql[offset:], match)
		if relative < 0 {
			break
		}
		start := offset + relative
		end := start + len(match)
		if match[0] == '\'' || sqlWordBoundary(sql, start) && sqlWordBoundary(sql, end) {
			return end
		}
		offset = start + 1
	}
	// FindString guarantees an occurrence satisfying these same boundaries.
	return len(sql)
}

// hasEqualNumericPair is a necessary condition for the numeric capture pattern
// to report a tautology. Ignoring word boundaries and operand length only adds
// candidates. Digit and whitespace runs are visited at most twice, so it is O(n).
func hasEqualNumericPair(sql string) bool {
	for offset := 0; offset < len(sql); {
		relative := strings.IndexByte(sql[offset:], '=')
		if relative < 0 {
			return false
		}
		eq := offset + relative
		offset = eq + 1
		left, right := eq, eq+1
		for left > 0 && sqlWhitespace(sql[left-1]) {
			left--
		}
		for right < len(sql) && sqlWhitespace(sql[right]) {
			right++
		}
		start, end := left, right
		for start > 0 && sql[start-1] >= '0' && sql[start-1] <= '9' {
			start--
		}
		for end < len(sql) && sql[end] >= '0' && sql[end] <= '9' {
			end++
		}
		if start < left && right < end && sql[start:left] == sql[right:end] {
			return true
		}
	}
	return false
}

// equalSQLPair compares the two operands in a capture-pattern match without
// allocating. The string-literal pattern permits '=' inside either operand;
// its first closing quote identifies where to start looking for the separator.
func equalSQLPair(match string) bool {
	start := 0
	if len(match) > 0 && match[0] == '\'' {
		end := strings.IndexByte(match[1:], '\'')
		if end < 0 {
			return false
		}
		start = end + 2
	}
	eq := strings.IndexByte(match[start:], '=')
	if eq < 0 {
		return false
	}
	eq += start
	const whitespace = " \t\r\n\f\v"
	return strings.EqualFold(strings.Trim(match[:eq], whitespace), strings.Trim(match[eq+1:], whitespace))
}

// detectRegexPatterns checks SQL against the compiled regex group for patternType.
// folded is the case-folded input used for literal prefiltering; nil disables
// prefiltering.
func (s *Scanner) detectRegexPatterns(views []string, folded []byte, patternType PatternType, result *ScanResult) {
	// Ensure patterns are initialized
	compiledPatternsOnce.Do(initCompiledPatterns)

	group, ok := regexGroups[patternType]
	if !ok {
		return
	}

	for _, p := range group.patterns {
		if folded != nil && !containsAll(folded, p.lits) {
			continue
		}
		// Every pattern requires a non-empty literal (asserted by
		// TestCompiledPatterns_AllHaveLiterals), so FindString returning "" means
		// no match, and a non-empty result is the same leftmost-first match that
		// FindStringSubmatch(sql)[0] would return.
		for _, sql := range views {
			if m := p.re.FindString(sql); m != "" {
				finding := Finding{
					Severity:    group.severity,
					Pattern:     patternType,
					Description: "Pattern detected: " + m,
					Risk:        group.risk,
					Suggestion:  group.suggestion,
				}
				if s.shouldInclude(finding.Severity) {
					result.Findings = append(result.Findings, finding)
				}
				break
			}
		}
	}
}

// shouldInclude checks if a finding meets the minimum severity threshold.
// Unknown severities are treated as highest priority (always included) for security.
func (s *Scanner) shouldInclude(severity Severity) bool {
	findingSeverity, findingExists := severityOrder[severity]
	minSeverity, minExists := severityOrder[s.MinSeverity]

	// Unknown severities are always included (fail-safe: don't hide potential issues)
	if !findingExists {
		return true
	}

	// If minimum severity is unknown, default to showing all
	if !minExists {
		return true
	}

	return findingSeverity >= minSeverity
}

// updateCounts updates the count fields in the result.
func (s *Scanner) updateCounts(result *ScanResult) {
	result.TotalCount = len(result.Findings)
	for _, f := range result.Findings {
		switch f.Severity {
		case SeverityCritical:
			result.CriticalCount++
		case SeverityHigh:
			result.HighCount++
		case SeverityMedium:
			result.MediumCount++
		case SeverityLow:
			result.LowCount++
		}
	}
}

// HasCritical returns true if any CRITICAL severity findings exist.
// Use this to quickly check for definite security vulnerabilities that
// require immediate attention.
//
// Example:
//
//	if results.HasCritical() {
//	    log.Fatal("CRITICAL security vulnerabilities detected - blocking deployment")
//	}
func (r *ScanResult) HasCritical() bool {
	return r.CriticalCount > 0
}

// HasHighOrAbove returns true if any HIGH or CRITICAL severity findings exist.
// Use this to check for issues that require security review before deployment.
//
// Example:
//
//	if results.HasHighOrAbove() {
//	    fmt.Println("WARNING: High-priority security issues require review")
//	    // Trigger security team notification
//	}
func (r *ScanResult) HasHighOrAbove() bool {
	return r.CriticalCount > 0 || r.HighCount > 0
}

// IsClean returns true if no findings of any severity level exist.
// A clean result indicates no security issues were detected.
//
// Example:
//
//	if results.IsClean() {
//	    fmt.Println("✓ No security issues detected")
//	} else {
//	    fmt.Printf("⚠ Found %d security issues\n", results.TotalCount)
//	}
func (r *ScanResult) IsClean() bool {
	return r.TotalCount == 0
}
