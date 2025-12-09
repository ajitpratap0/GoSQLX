// Package security provides SQL injection pattern detection and security scanning.
// It analyzes parsed SQL AST to identify common injection patterns and vulnerabilities.
//
// The scanner detects 8 pattern types:
//   - Tautologies: Always-true conditions like 1=1, 'a'='a'
//   - Comment-based bypasses: --, /**/, #, trailing comments
//   - UNION-based extraction: UNION SELECT patterns, information_schema access
//   - Stacked queries: Destructive statements after semicolon (DROP, DELETE, etc.)
//   - Time-based blind: SLEEP(), WAITFOR DELAY, pg_sleep(), BENCHMARK()
//   - Out-of-band: xp_cmdshell, LOAD_FILE(), UTL_HTTP, etc.
//   - Dangerous functions: EXEC(), sp_executesql, PREPARE FROM, etc.
//   - Boolean-based: Conditional logic exploitation
//
// Example usage:
//
//	scanner := security.NewScanner()
//	results := scanner.Scan(ast)
//	for _, finding := range results.Findings {
//	    fmt.Printf("%s: %s at line %d\n", finding.Severity, finding.Pattern, finding.Line)
//	}
package security

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Severity represents the severity level of a security finding.
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

// Pre-compiled regex patterns for performance (compiled once at package init)
var (
	compiledPatterns     map[PatternType][]*regexp.Regexp
	compiledPatternsOnce sync.Once

	// Comment detection patterns (pre-compiled)
	commentPatterns []struct {
		re          *regexp.Regexp
		description string
		severity    Severity
	}
	commentPatternsOnce sync.Once
)

// initCompiledPatterns initializes all regex patterns once at package level.
func initCompiledPatterns() {
	compiledPatterns = make(map[PatternType][]*regexp.Regexp)

	// Time-based blind injection functions
	compiledPatterns[PatternTimeBased] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bSLEEP\s*\(`),
		regexp.MustCompile(`(?i)\bWAITFOR\s+DELAY\b`),
		regexp.MustCompile(`(?i)\bpg_sleep\s*\(`),
		regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`),
		regexp.MustCompile(`(?i)\bDBMS_LOCK\.SLEEP\s*\(`),
	}

	// Out-of-band / dangerous functions
	compiledPatterns[PatternOutOfBand] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bxp_cmdshell\b`),
		regexp.MustCompile(`(?i)\bLOAD_FILE\s*\(`),
		regexp.MustCompile(`(?i)\bINTO\s+OUTFILE\b`),
		regexp.MustCompile(`(?i)\bINTO\s+DUMPFILE\b`),
		regexp.MustCompile(`(?i)\bUTL_HTTP\b`),
		regexp.MustCompile(`(?i)\bDBMS_LDAP\b`),
		regexp.MustCompile(`(?i)\bEXEC\s+master\b`),
		regexp.MustCompile(`(?i)\bsp_oacreate\b`),
	}

	// Dangerous functions that might indicate injection
	compiledPatterns[PatternDangerousFunc] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bEXEC\s*\(`),
		regexp.MustCompile(`(?i)\bEXECUTE\s+IMMEDIATE\b`),
		regexp.MustCompile(`(?i)\bsp_executesql\b`),
		regexp.MustCompile(`(?i)\bPREPARE\s+\w+\s+FROM\b`),
	}

	// UNION-based injection patterns
	compiledPatterns[PatternUnionBased] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`),
		regexp.MustCompile(`(?i)\binformation_schema\b`),
	}

	// Stacked query injection patterns (destructive statements after semicolon)
	compiledPatterns[PatternStackedQuery] = []*regexp.Regexp{
		regexp.MustCompile(`;\s*(?i)(DROP|DELETE|TRUNCATE|UPDATE|INSERT|ALTER)\b`),
		regexp.MustCompile(`;\s*(?i)EXEC\b`),
		regexp.MustCompile(`;\s*(?i)EXECUTE\b`),
	}
}

// initCommentPatterns initializes comment detection patterns once.
func initCommentPatterns() {
	commentPatterns = []struct {
		re          *regexp.Regexp
		description string
		severity    Severity
	}{
		{regexp.MustCompile(`--\s*$`), "Trailing SQL comment may indicate injection", SeverityMedium},
		{regexp.MustCompile(`--\s*['")\]]`), "Comment after quote/bracket (potential bypass)", SeverityHigh},
		{regexp.MustCompile(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/\s*$`), "Unclosed or trailing block comment may indicate injection", SeverityMedium},
		{regexp.MustCompile(`/\*!.*\*/`), "MySQL conditional comment (version-specific execution)", SeverityMedium},
		{regexp.MustCompile(`#\s*$`), "Hash comment at end (MySQL)", SeverityMedium},
		{regexp.MustCompile(`;\s*--`), "Statement terminator followed by comment", SeverityHigh},
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

// PatternType categorizes the type of injection pattern detected.
type PatternType string

const (
	PatternTautology     PatternType = "TAUTOLOGY"
	PatternComment       PatternType = "COMMENT_BYPASS"
	PatternStackedQuery  PatternType = "STACKED_QUERY"
	PatternUnionBased    PatternType = "UNION_BASED"
	PatternTimeBased     PatternType = "TIME_BASED"
	PatternBooleanBased  PatternType = "BOOLEAN_BASED"
	PatternOutOfBand     PatternType = "OUT_OF_BAND"
	PatternDangerousFunc PatternType = "DANGEROUS_FUNCTION"
)

// Finding represents a single security finding from the scanner.
type Finding struct {
	Severity    Severity    `json:"severity"`
	Pattern     PatternType `json:"pattern"`
	Description string      `json:"description"`
	Risk        string      `json:"risk"`
	Line        int         `json:"line,omitempty"`
	Column      int         `json:"column,omitempty"`
	SQL         string      `json:"sql,omitempty"`
	Suggestion  string      `json:"suggestion,omitempty"`
}

// ScanResult contains all findings from a security scan.
type ScanResult struct {
	Findings      []Finding `json:"findings"`
	TotalCount    int       `json:"total_count"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	MediumCount   int       `json:"medium_count"`
	LowCount      int       `json:"low_count"`
}

// Scanner performs security analysis on SQL AST.
type Scanner struct {
	// MinSeverity filters findings below this severity level
	MinSeverity Severity
}

// NewScanner creates a new security scanner with default settings.
func NewScanner() *Scanner {
	// Initialize package-level patterns once
	compiledPatternsOnce.Do(initCompiledPatterns)
	commentPatternsOnce.Do(initCommentPatterns)

	return &Scanner{
		MinSeverity: SeverityLow,
	}
}

// NewScannerWithSeverity creates a scanner filtering by minimum severity.
// Returns an error if the severity is not valid.
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

// Scan analyzes an AST for SQL injection patterns.
func (s *Scanner) Scan(tree *ast.AST) *ScanResult {
	result := &ScanResult{
		Findings: make([]Finding, 0),
	}

	if tree == nil {
		return result
	}

	for _, stmt := range tree.Statements {
		s.scanStatement(stmt, result)
	}

	// Update counts
	s.updateCounts(result)

	return result
}

// ScanSQL analyzes raw SQL string for injection patterns.
// This is useful for detecting patterns that might not be in the AST.
func (s *Scanner) ScanSQL(sql string) *ScanResult {
	result := &ScanResult{
		Findings: make([]Finding, 0),
	}

	// Check for comment-based bypass patterns in raw SQL
	s.detectCommentPatterns(sql, result)

	// Check for time-based patterns
	s.detectRegexPatterns(sql, PatternTimeBased, result)

	// Check for out-of-band patterns
	s.detectRegexPatterns(sql, PatternOutOfBand, result)

	// Check for dangerous function patterns
	s.detectRegexPatterns(sql, PatternDangerousFunc, result)

	// Check for UNION-based injection patterns
	s.detectRegexPatterns(sql, PatternUnionBased, result)

	// Check for stacked query patterns
	s.detectRegexPatterns(sql, PatternStackedQuery, result)

	// Update counts
	s.updateCounts(result)

	return result
}

// scanStatement analyzes a single statement for injection patterns.
func (s *Scanner) scanStatement(stmt ast.Statement, result *ScanResult) {
	switch st := stmt.(type) {
	case *ast.SelectStatement:
		s.scanSelectStatement(st, result)
	case *ast.InsertStatement:
		s.scanInsertStatement(st, result)
	case *ast.UpdateStatement:
		s.scanUpdateStatement(st, result)
	case *ast.DeleteStatement:
		s.scanDeleteStatement(st, result)
	case *ast.SetOperation:
		s.scanSetOperation(st, result)
	}
}

// scanSelectStatement analyzes SELECT for injection patterns.
func (s *Scanner) scanSelectStatement(stmt *ast.SelectStatement, result *ScanResult) {
	// Check WHERE clause for tautologies
	if stmt.Where != nil {
		s.scanExpression(stmt.Where, result, "WHERE clause")
	}

	// Check HAVING clause
	if stmt.Having != nil {
		s.scanExpression(stmt.Having, result, "HAVING clause")
	}

	// Check for suspicious function calls in columns
	for _, col := range stmt.Columns {
		s.scanExpressionForDangerousFunctions(col, result)
	}
}

// scanInsertStatement analyzes INSERT for injection patterns.
func (s *Scanner) scanInsertStatement(stmt *ast.InsertStatement, result *ScanResult) {
	// Check values for suspicious patterns
	for _, val := range stmt.Values {
		s.scanExpressionForDangerousFunctions(val, result)
	}
}

// scanUpdateStatement analyzes UPDATE for injection patterns.
func (s *Scanner) scanUpdateStatement(stmt *ast.UpdateStatement, result *ScanResult) {
	// Check WHERE clause
	if stmt.Where != nil {
		s.scanExpression(stmt.Where, result, "WHERE clause")
	}

	// Check SET values - use Assignments field
	for _, assignment := range stmt.Assignments {
		s.scanExpressionForDangerousFunctions(assignment.Value, result)
	}

	// Also check Updates field for backward compatibility
	for _, update := range stmt.Updates {
		s.scanExpressionForDangerousFunctions(update.Value, result)
	}
}

// scanDeleteStatement analyzes DELETE for injection patterns.
func (s *Scanner) scanDeleteStatement(stmt *ast.DeleteStatement, result *ScanResult) {
	// Check WHERE clause
	if stmt.Where != nil {
		s.scanExpression(stmt.Where, result, "WHERE clause")
	}
}

// scanSetOperation analyzes UNION/EXCEPT/INTERSECT for injection patterns.
func (s *Scanner) scanSetOperation(stmt *ast.SetOperation, result *ScanResult) {
	// UNION-based injection detection
	if strings.ToUpper(stmt.Operator) == "UNION" {
		// Check if UNION might be used for data extraction
		s.checkUnionInjection(stmt, result)
	}

	// Recursively scan left and right statements
	// Note: SetOperation.Left and .Right are already ast.Statement type
	if stmt.Left != nil {
		s.scanStatement(stmt.Left, result)
	}
	if stmt.Right != nil {
		s.scanStatement(stmt.Right, result)
	}
}

// scanExpression analyzes an expression for injection patterns.
func (s *Scanner) scanExpression(expr ast.Expression, result *ScanResult, context string) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.BinaryExpression:
		s.scanBinaryExpression(e, result, context)
	case *ast.FunctionCall:
		s.scanFunctionCall(e, result)
	case *ast.UnaryExpression:
		if e.Expr != nil {
			s.scanExpression(e.Expr, result, context)
		}
	}
}

// scanBinaryExpression checks for tautologies and suspicious patterns.
func (s *Scanner) scanBinaryExpression(expr *ast.BinaryExpression, result *ScanResult, context string) {
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
	s.scanExpression(expr.Left, result, context)
	s.scanExpression(expr.Right, result, context)
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
	leftLit, leftIsLit := expr.Left.(*ast.LiteralValue)
	rightLit, rightIsLit := expr.Right.(*ast.LiteralValue)

	if leftIsLit && rightIsLit {
		// Same literal values
		leftVal := fmt.Sprintf("%v", leftLit.Value)
		rightVal := fmt.Sprintf("%v", rightLit.Value)
		if leftVal == rightVal {
			return true
		}
	}

	// Check for identifier tautologies: col=col
	leftIdent, leftIsIdent := expr.Left.(*ast.Identifier)
	rightIdent, rightIsIdent := expr.Right.(*ast.Identifier)

	if leftIsIdent && rightIsIdent {
		if leftIdent.Name == rightIdent.Name {
			return true
		}
	}

	return false
}

// checkOrInjection checks for OR-based injection patterns.
func (s *Scanner) checkOrInjection(expr *ast.BinaryExpression, result *ScanResult) {
	// Check if the OR condition contains a tautology
	if rightBin, ok := expr.Right.(*ast.BinaryExpression); ok {
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

	if leftBin, ok := expr.Left.(*ast.BinaryExpression); ok {
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

// checkUnionInjection analyzes UNION for potential data extraction.
func (s *Scanner) checkUnionInjection(stmt *ast.SetOperation, result *ScanResult) {
	// Check if right side SELECT has suspicious patterns
	if rightSelect, ok := stmt.Right.(*ast.SelectStatement); ok {
		// Check for NULL placeholders (common in UNION injection)
		nullCount := 0
		for _, col := range rightSelect.Columns {
			if ident, ok := col.(*ast.Identifier); ok {
				if strings.ToUpper(ident.Name) == "NULL" {
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

// scanFunctionCall checks for dangerous function usage.
func (s *Scanner) scanFunctionCall(fn *ast.FunctionCall, result *ScanResult) {
	if fn == nil {
		return
	}

	funcName := strings.ToUpper(fn.Name)

	// Time-based blind injection functions
	timeBasedFuncs := map[string]bool{
		"SLEEP":     true,
		"PG_SLEEP":  true,
		"BENCHMARK": true,
		"WAITFOR":   true,
	}

	if timeBasedFuncs[funcName] {
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

	// Out-of-band / dangerous functions
	dangerousFuncs := map[string]string{
		"LOAD_FILE":     "File system access",
		"LOAD DATA":     "File system access",
		"XP_CMDSHELL":   "Command execution",
		"SP_OACREATE":   "OLE automation",
		"UTL_HTTP":      "Network access",
		"DBMS_LDAP":     "LDAP access",
		"EXEC":          "Dynamic SQL execution",
		"SP_EXECUTESQL": "Dynamic SQL execution",
	}

	if risk, found := dangerousFuncs[funcName]; found {
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

	// Recursively check function arguments
	for _, arg := range fn.Arguments {
		s.scanExpressionForDangerousFunctions(arg, result)
	}
}

// scanExpressionForDangerousFunctions recursively checks for dangerous functions.
func (s *Scanner) scanExpressionForDangerousFunctions(expr ast.Expression, result *ScanResult) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.FunctionCall:
		s.scanFunctionCall(e, result)
	case *ast.BinaryExpression:
		s.scanExpressionForDangerousFunctions(e.Left, result)
		s.scanExpressionForDangerousFunctions(e.Right, result)
	case *ast.UnaryExpression:
		s.scanExpressionForDangerousFunctions(e.Expr, result)
	}
}

// detectCommentPatterns checks raw SQL for comment-based injection.
func (s *Scanner) detectCommentPatterns(sql string, result *ScanResult) {
	// Ensure patterns are initialized
	commentPatternsOnce.Do(initCommentPatterns)

	for _, p := range commentPatterns {
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

// detectRegexPatterns checks SQL against compiled regex patterns.
func (s *Scanner) detectRegexPatterns(sql string, patternType PatternType, result *ScanResult) {
	// Ensure patterns are initialized
	compiledPatternsOnce.Do(initCompiledPatterns)

	patterns, ok := compiledPatterns[patternType]
	if !ok {
		return
	}

	severityMap := map[PatternType]Severity{
		PatternTimeBased:     SeverityHigh,
		PatternOutOfBand:     SeverityCritical,
		PatternDangerousFunc: SeverityMedium,
		PatternUnionBased:    SeverityCritical,
		PatternStackedQuery:  SeverityCritical,
	}

	riskMap := map[PatternType]string{
		PatternTimeBased:     "Time-based blind SQL injection",
		PatternOutOfBand:     "Out-of-band data exfiltration or command execution",
		PatternDangerousFunc: "Dynamic SQL execution vulnerability",
		PatternUnionBased:    "UNION-based SQL injection for data extraction",
		PatternStackedQuery:  "Stacked query injection with destructive operations",
	}

	suggestionMap := map[PatternType]string{
		PatternTimeBased:     "Review and sanitize SQL input",
		PatternOutOfBand:     "Review and sanitize SQL input",
		PatternDangerousFunc: "Review and sanitize SQL input",
		PatternUnionBased:    "Use parameterized queries and validate input",
		PatternStackedQuery:  "Block semicolons in user input or use parameterized queries",
	}

	severity := severityMap[patternType]
	risk := riskMap[patternType]
	suggestion := suggestionMap[patternType]

	for _, re := range patterns {
		if matches := re.FindStringSubmatch(sql); len(matches) > 0 {
			finding := Finding{
				Severity:    severity,
				Pattern:     patternType,
				Description: "Pattern detected: " + matches[0],
				Risk:        risk,
				Suggestion:  suggestion,
			}
			if s.shouldInclude(finding.Severity) {
				result.Findings = append(result.Findings, finding)
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

// HasCritical returns true if any critical findings exist.
func (r *ScanResult) HasCritical() bool {
	return r.CriticalCount > 0
}

// HasHighOrAbove returns true if any high or critical findings exist.
func (r *ScanResult) HasHighOrAbove() bool {
	return r.CriticalCount > 0 || r.HighCount > 0
}

// IsClean returns true if no findings exist.
func (r *ScanResult) IsClean() bool {
	return r.TotalCount == 0
}
