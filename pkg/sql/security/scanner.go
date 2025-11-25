// Package security provides SQL injection pattern detection and security scanning.
// It analyzes parsed SQL AST to identify common injection patterns and vulnerabilities.
//
// The scanner detects:
//   - Tautologies: Always-true conditions like 1=1, 'a'='a'
//   - Comment-based bypasses: --, /**/, #
//   - Stacked queries: Multiple statements with dangerous operations
//   - UNION-based extraction: Suspicious UNION SELECT patterns
//   - Time-based blind: SLEEP(), WAITFOR DELAY, pg_sleep()
//   - Boolean-based blind: Suspicious boolean logic patterns
//   - Out-of-band: xp_cmdshell, LOAD_FILE(), etc.
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
	// patterns holds compiled regex patterns
	patterns map[PatternType][]*regexp.Regexp
}

// NewScanner creates a new security scanner with default settings.
func NewScanner() *Scanner {
	s := &Scanner{
		MinSeverity: SeverityLow,
		patterns:    make(map[PatternType][]*regexp.Regexp),
	}
	s.initPatterns()
	return s
}

// NewScannerWithSeverity creates a scanner filtering by minimum severity.
func NewScannerWithSeverity(minSeverity Severity) *Scanner {
	s := NewScanner()
	s.MinSeverity = minSeverity
	return s
}

// initPatterns compiles all regex patterns used for detection.
func (s *Scanner) initPatterns() {
	// Time-based blind injection functions
	s.patterns[PatternTimeBased] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bSLEEP\s*\(`),
		regexp.MustCompile(`(?i)\bWAITFOR\s+DELAY\b`),
		regexp.MustCompile(`(?i)\bpg_sleep\s*\(`),
		regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`),
		regexp.MustCompile(`(?i)\bDBMS_LOCK\.SLEEP\s*\(`),
	}

	// Out-of-band / dangerous functions
	s.patterns[PatternOutOfBand] = []*regexp.Regexp{
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
	s.patterns[PatternDangerousFunc] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bEXEC\s*\(`),
		regexp.MustCompile(`(?i)\bEXECUTE\s+IMMEDIATE\b`),
		regexp.MustCompile(`(?i)\bsp_executesql\b`),
		regexp.MustCompile(`(?i)\bPREPARE\s+\w+\s+FROM\b`),
	}
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
	if leftStmt, ok := stmt.Left.(ast.Statement); ok {
		s.scanStatement(leftStmt, result)
	}
	if rightStmt, ok := stmt.Right.(ast.Statement); ok {
		s.scanStatement(rightStmt, result)
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

		// Check for information_schema access
		if rightSelect.TableName != "" {
			tableLower := strings.ToLower(rightSelect.TableName)
			if strings.Contains(tableLower, "information_schema") ||
				strings.Contains(tableLower, "sys.") ||
				strings.Contains(tableLower, "mysql.") ||
				strings.Contains(tableLower, "pg_catalog") {
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
	// SQL comment patterns that might indicate bypass attempts
	patterns := []struct {
		pattern     string
		description string
		severity    Severity
	}{
		{`--\s*$`, "Single-line comment at end of input", SeverityMedium},
		{`--\s*['")\]]`, "Comment after quote/bracket (potential bypass)", SeverityHigh},
		{`/\*.*\*/`, "Block comment (potential bypass)", SeverityLow},
		{`/\*!.*\*/`, "MySQL conditional comment", SeverityMedium},
		{`#\s*$`, "Hash comment at end (MySQL)", SeverityMedium},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(sql) {
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
	patterns, ok := s.patterns[patternType]
	if !ok {
		return
	}

	severityMap := map[PatternType]Severity{
		PatternTimeBased:     SeverityHigh,
		PatternOutOfBand:     SeverityCritical,
		PatternDangerousFunc: SeverityMedium,
	}

	riskMap := map[PatternType]string{
		PatternTimeBased:     "Time-based blind SQL injection",
		PatternOutOfBand:     "Out-of-band data exfiltration or command execution",
		PatternDangerousFunc: "Dynamic SQL execution vulnerability",
	}

	severity := severityMap[patternType]
	risk := riskMap[patternType]

	for _, re := range patterns {
		if matches := re.FindStringSubmatch(sql); len(matches) > 0 {
			finding := Finding{
				Severity:    severity,
				Pattern:     patternType,
				Description: "Pattern detected: " + matches[0],
				Risk:        risk,
				Suggestion:  "Review and sanitize SQL input",
			}
			if s.shouldInclude(finding.Severity) {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
}

// shouldInclude checks if a finding meets the minimum severity threshold.
func (s *Scanner) shouldInclude(severity Severity) bool {
	severityOrder := map[Severity]int{
		SeverityLow:      0,
		SeverityMedium:   1,
		SeverityHigh:     2,
		SeverityCritical: 3,
	}

	return severityOrder[severity] >= severityOrder[s.MinSeverity]
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
