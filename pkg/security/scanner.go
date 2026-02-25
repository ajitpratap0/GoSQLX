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

package security

import (
	"fmt"
	"regexp"
	"strings"
)

// Severity represents the severity level of a security finding.
//
// Deprecated: Use pkg/sql/security instead.
type Severity int

const (
	// Deprecated: Use pkg/sql/security instead.
	SeverityInfo Severity = iota
	// Deprecated: Use pkg/sql/security instead.
	SeverityWarning
	// Deprecated: Use pkg/sql/security instead.
	SeverityError
	// Deprecated: Use pkg/sql/security instead.
	SeverityCritical
)

// String returns the string representation of the severity level.
//
// Deprecated: Use pkg/sql/security instead.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Finding represents a security issue found in SQL.
//
// Deprecated: Use pkg/sql/security instead.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Position int      `json:"position"` // byte offset in the input
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Match    string   `json:"match"` // the matched text
}

// Rule defines a security scanning rule.
//
// Deprecated: Use pkg/sql/security instead.
type Rule interface {
	// ID returns the unique rule identifier.
	ID() string
	// Description returns a human-readable description.
	Description() string
	// Check scans the SQL and returns any findings.
	Check(sql string) []Finding
}

// Scanner scans SQL for security issues using registered rules.
//
// Deprecated: Use pkg/sql/security instead.
type Scanner struct {
	rules []Rule
}

// NewScanner creates a Scanner with the default rule set.
//
// Deprecated: Use pkg/sql/security instead.
func NewScanner() *Scanner {
	return &Scanner{
		rules: defaultRules(),
	}
}

// NewScannerWithRules creates a Scanner with the given rules.
//
// Deprecated: Use pkg/sql/security instead.
func NewScannerWithRules(rules ...Rule) *Scanner {
	return &Scanner{rules: rules}
}

// AddRule registers an additional rule.
//
// Deprecated: Use pkg/sql/security instead.
func (s *Scanner) AddRule(r Rule) {
	s.rules = append(s.rules, r)
}

// Scan checks the SQL string against all registered rules.
//
// Deprecated: Use pkg/sql/security instead.
func (s *Scanner) Scan(sql string) []Finding {
	var findings []Finding
	for _, r := range s.rules {
		findings = append(findings, r.Check(sql)...)
	}
	// Compute line/column for each finding
	for i := range findings {
		if findings[i].Position >= 0 && findings[i].Line == 0 {
			line, col := posToLineCol(sql, findings[i].Position)
			findings[i].Line = line
			findings[i].Column = col
		}
	}
	return findings
}

// Rules returns the registered rules (for introspection).
//
// Deprecated: Use pkg/sql/security instead.
func (s *Scanner) Rules() []Rule {
	return s.rules
}

func defaultRules() []Rule {
	return []Rule{
		&TautologyRule{},
		&LikeInjectionRule{},
		&UnionInjectionRule{},
	}
}

func posToLineCol(sql string, pos int) (int, int) {
	if pos > len(sql) {
		pos = len(sql)
	}
	line := 1
	col := 1
	for i := 0; i < pos; i++ {
		if sql[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// --- TautologyRule (blind injection) ---

// TautologyRule detects tautology patterns like OR 1=1, OR 'a'='a'.
//
// Deprecated: Use pkg/sql/security instead.
type TautologyRule struct{}

// ID returns the unique rule identifier.
//
// Deprecated: Use pkg/sql/security instead.
func (r *TautologyRule) ID() string { return "SEC001" }

// Description returns a human-readable description.
//
// Deprecated: Use pkg/sql/security instead.
func (r *TautologyRule) Description() string { return "Tautology / blind injection detection" }

var tautologyPatterns = []*regexp.Regexp{
	// OR 1=1 and variants
	regexp.MustCompile(`(?i)\bOR\s+1\s*=\s*1\b`),
	regexp.MustCompile(`(?i)\bOR\s+0\s*=\s*0\b`),
	// OR 'a'='a' and variants with single/double quotes
	regexp.MustCompile(`(?i)\bOR\s+'[^']*'\s*=\s*'[^']*'`),
	regexp.MustCompile(`(?i)\bOR\s+"[^"]*"\s*=\s*"[^"]*"`),
	// OR true
	regexp.MustCompile(`(?i)\bOR\s+true\b`),
	// OR ''=''
	regexp.MustCompile(`(?i)\bOR\s+''\s*=\s*''`),
}

// Check scans the SQL and returns any findings.
//
// Deprecated: Use pkg/sql/security instead.
func (r *TautologyRule) Check(sql string) []Finding {
	var findings []Finding
	upper := strings.ToUpper(sql)
	for _, pat := range tautologyPatterns {
		for _, loc := range pat.FindAllStringIndex(upper, -1) {
			// Verify it's actually a match on original (case insensitive regex already handles this)
			matched := sql[loc[0]:loc[1]]
			findings = append(findings, Finding{
				RuleID:   r.ID(),
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("Possible tautology/blind SQL injection: %s", matched),
				Position: loc[0],
				Match:    matched,
			})
		}
	}
	return findings
}

// --- LikeInjectionRule ---

// LikeInjectionRule detects LIKE with string concatenation patterns.
//
// Deprecated: Use pkg/sql/security instead.
type LikeInjectionRule struct{}

// ID returns the unique rule identifier.
//
// Deprecated: Use pkg/sql/security instead.
func (r *LikeInjectionRule) ID() string { return "SEC002" }

// Description returns a human-readable description.
//
// Deprecated: Use pkg/sql/security instead.
func (r *LikeInjectionRule) Description() string { return "LIKE injection detection" }

var likePatterns = []*regexp.Regexp{
	// LIKE '%' + expr + '%' (SQL Server style)
	regexp.MustCompile(`(?i)\bLIKE\s+'%'\s*\+\s*\S+\s*\+\s*'%'`),
	// LIKE '%' || expr || '%' (PostgreSQL/Oracle style)
	regexp.MustCompile(`(?i)\bLIKE\s+'%'\s*\|\|\s*\S+\s*\|\|\s*'%'`),
	// LIKE CONCAT('%', expr, '%')
	regexp.MustCompile(`(?i)\bLIKE\s+CONCAT\s*\(\s*'%'\s*,`),
}

// Check scans the SQL and returns any findings.
//
// Deprecated: Use pkg/sql/security instead.
func (r *LikeInjectionRule) Check(sql string) []Finding {
	var findings []Finding
	for _, pat := range likePatterns {
		for _, loc := range pat.FindAllStringIndex(sql, -1) {
			matched := sql[loc[0]:loc[1]]
			findings = append(findings, Finding{
				RuleID:   r.ID(),
				Severity: SeverityError,
				Message:  fmt.Sprintf("Possible LIKE injection via string concatenation: %s", matched),
				Position: loc[0],
				Match:    matched,
			})
		}
	}
	return findings
}

// --- UnionInjectionRule ---

// UnionInjectionRule detects suspicious UNION SELECT patterns.
//
// Deprecated: Use pkg/sql/security instead.
type UnionInjectionRule struct{}

// ID returns the unique rule identifier.
//
// Deprecated: Use pkg/sql/security instead.
func (r *UnionInjectionRule) ID() string { return "SEC003" }

// Description returns a human-readable description.
//
// Deprecated: Use pkg/sql/security instead.
func (r *UnionInjectionRule) Description() string { return "UNION-based injection detection" }

var unionPatterns = []*regexp.Regexp{
	// UNION SELECT with numeric literals (common injection probe)
	regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\s+\d+(\s*,\s*\d+)+`),
	// UNION SELECT null, null, ...
	regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\s+NULL(\s*,\s*NULL)+`),
	// UNION SELECT with information_schema
	regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\s+.*\binformation_schema\b`),
}

// Check scans the SQL and returns any findings.
//
// Deprecated: Use pkg/sql/security instead.
func (r *UnionInjectionRule) Check(sql string) []Finding {
	var findings []Finding
	for _, pat := range unionPatterns {
		for _, loc := range pat.FindAllStringIndex(sql, -1) {
			matched := sql[loc[0]:loc[1]]
			findings = append(findings, Finding{
				RuleID:   r.ID(),
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("Possible UNION-based SQL injection: %s", matched),
				Position: loc[0],
				Match:    matched,
			})
		}
	}
	return findings
}
