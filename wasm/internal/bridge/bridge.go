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

// Package bridge holds the platform-independent logic behind the playground's
// WebAssembly entry points (wasm/main.go). Keeping it free of syscall/js lets it
// be unit-tested with the normal Go toolchain.
//
// Every response type here is part of the contract with the website's
// playground components, so fields carry explicit snake_case JSON tags. The
// TypeScript mirror of these types is
// website/src/components/playground/bridgeTypes.ts. TestContractFixture keeps
// website/src/components/playground/bridgeContract.fixture.json in step,
// which bridgeContract.check.ts type-checks against those TS types during the
// website's typecheck. Changing a tag is a breaking change for the website and
// must be mirrored there.
package bridge

import (
	"github.com/ajitpratap0/GoSQLX/pkg/advisor"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

// Dialect resolves a playground dialect string. Any name accepted by
// keywords.IsValidDialect (see keywords.DialectNames) resolves to that
// dialect; unknown or empty values resolve to "" (the parser's default
// dialect).
func Dialect(name string) sqlkeywords.SQLDialect {
	if name == "" || !sqlkeywords.IsValidDialect(name) {
		return ""
	}
	return sqlkeywords.SQLDialect(name)
}

// Parse parses sql with the given playground dialect.
func Parse(sql, dialect string) (*ast.AST, error) {
	if d := Dialect(dialect); d != "" {
		return gosqlx.ParseWithDialect(sql, d)
	}
	return gosqlx.Parse(sql)
}

// LintViolation is one lint finding as the playground renders it.
type LintViolation struct {
	Rule       string `json:"rule"`
	RuleName   string `json:"rule_name"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Suggestion string `json:"suggestion,omitempty"`
}

// LintResponse is the result of Lint.
//
// ParseError is set when the SQL does not parse in the selected dialect, and
// ParseErrorSpan locates it when the error carries a position. The
// violations from rules that can still run (text- and token-level rules) are
// reported alongside it, but the SQL must never be presented as clean.
type LintResponse struct {
	ParseError     string          `json:"parse_error,omitempty"`
	ParseErrorSpan *ErrorSpan      `json:"parse_error_span,omitempty"`
	Error          string          `json:"error,omitempty"`
	Violations     []LintViolation `json:"violations"`
}

// Lint runs the full built-in rule set that gosqlx.Lint ships (L001-L030)
// with the selected dialect, so AST-level rules see dialect-specific syntax,
// and reports whether the SQL parses in that dialect.
func Lint(sql, dialect string) LintResponse {
	resp := LintResponse{Violations: []LintViolation{}}

	if _, err := Parse(sql, dialect); err != nil {
		resp.ParseError = err.Error()
		resp.ParseErrorSpan = errorSpan(sql, err)
	}

	result, err := gosqlx.LintWithDialect(sql, Dialect(dialect))
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	for _, v := range result.Violations {
		resp.Violations = append(resp.Violations, LintViolation{
			Rule:       v.Rule,
			RuleName:   v.RuleName,
			Severity:   string(v.Severity),
			Message:    v.Message,
			Line:       v.Location.Line,
			Column:     v.Location.Column,
			Suggestion: v.Suggestion,
		})
	}
	return resp
}

// SecurityFinding is one security scanner finding.
type SecurityFinding struct {
	Severity    string `json:"severity"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Risk        string `json:"risk,omitempty"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	SQL         string `json:"sql,omitempty"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// SecurityReport summarises the security scan. Findings always lists every
// finding counted in the totals.
type SecurityReport struct {
	Findings      []SecurityFinding `json:"findings"`
	TotalCount    int               `json:"total_count"`
	CriticalCount int               `json:"critical_count"`
	HighCount     int               `json:"high_count"`
	MediumCount   int               `json:"medium_count"`
	LowCount      int               `json:"low_count"`
}

// OptimizationSuggestion is one advisor suggestion.
type OptimizationSuggestion struct {
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	Detail       string `json:"detail,omitempty"`
	Line         int    `json:"line,omitempty"`
	Column       int    `json:"column,omitempty"`
	OriginalSQL  string `json:"original_sql,omitempty"`
	SuggestedSQL string `json:"suggested_sql,omitempty"`
}

// OptimizationReport is the advisor's result.
type OptimizationReport struct {
	Score       int                      `json:"score"`
	Complexity  string                   `json:"complexity"`
	Suggestions []OptimizationSuggestion `json:"suggestions"`
}

// AnalyzeResponse is the result of Analyze. When the SQL does not parse,
// only ParseError (and ParseErrorSpan, when the error has a position) is set:
// no score is computed for SQL that fails to parse.
type AnalyzeResponse struct {
	ParseError     string              `json:"parse_error,omitempty"`
	ParseErrorSpan *ErrorSpan          `json:"parse_error_span,omitempty"`
	Security       *SecurityReport     `json:"security,omitempty"`
	Optimization   *OptimizationReport `json:"optimization,omitempty"`
}

// Analyze runs the security scanner and the optimization advisor on sql.
func Analyze(sql, dialect string) AnalyzeResponse {
	tree, err := Parse(sql, dialect)
	if err != nil {
		return AnalyzeResponse{ParseError: err.Error(), ParseErrorSpan: errorSpan(sql, err)}
	}

	scan := security.NewScanner().ScanSQL(sql)
	sec := &SecurityReport{
		Findings:      make([]SecurityFinding, 0, len(scan.Findings)),
		TotalCount:    scan.TotalCount,
		CriticalCount: scan.CriticalCount,
		HighCount:     scan.HighCount,
		MediumCount:   scan.MediumCount,
		LowCount:      scan.LowCount,
	}
	for _, f := range scan.Findings {
		sec.Findings = append(sec.Findings, SecurityFinding{
			Severity:    string(f.Severity),
			Pattern:     string(f.Pattern),
			Description: f.Description,
			Risk:        f.Risk,
			Line:        f.Line,
			Column:      f.Column,
			SQL:         f.SQL,
			Suggestion:  f.Suggestion,
		})
	}

	res := advisor.New().Analyze(tree)
	opt := &OptimizationReport{
		Score:       res.Score,
		Complexity:  res.QueryComplexity,
		Suggestions: make([]OptimizationSuggestion, 0, len(res.Suggestions)),
	}
	for _, s := range res.Suggestions {
		opt.Suggestions = append(opt.Suggestions, OptimizationSuggestion{
			RuleID:       s.RuleID,
			Severity:     s.Severity,
			Message:      s.Message,
			Detail:       s.Detail,
			Line:         s.Line,
			Column:       s.Column,
			OriginalSQL:  s.OriginalSQL,
			SuggestedSQL: s.SuggestedSQL,
		})
	}

	return AnalyzeResponse{Security: sec, Optimization: opt}
}
