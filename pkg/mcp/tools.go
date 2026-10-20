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

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	mcpmcp "github.com/mark3labs/mcp-go/mcp"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

// ---------------------------------------------------------------------------
// Internal result functions
// These return map[string]any so that handleAnalyzeSQL can fan-out
// concurrently and collect results without JSON round-trips.
// ---------------------------------------------------------------------------

// validateSQLInternal validates a SQL string, optionally against a specific dialect.
// Parse/validate failures are represented as {valid: false, error: ...} with a nil
// error return (tool-semantic failure, not a protocol error).
// A missing/empty sql argument returns a non-nil error (protocol error).
func validateSQLInternal(sql, dialect string) (map[string]any, error) {
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	if dialect != "" {
		_, err := gosqlx.ParseWithDialect(sql, sqlkeywords.SQLDialect(dialect))
		if err != nil {
			return map[string]any{
				"valid":   false,
				"dialect": dialect,
				"error":   err.Error(),
			}, nil
		}
		return map[string]any{
			"valid":   true,
			"dialect": dialect,
		}, nil
	}

	err := gosqlx.Validate(sql)
	if err != nil {
		return map[string]any{
			"valid": false,
			"error": err.Error(),
		}, nil
	}
	return map[string]any{
		"valid": true,
	}, nil
}

// formatSQLInternal formats a SQL string using the provided options.
//
// gosqlx.Format always emits clause keywords (SELECT, FROM, WHERE, ...) in
// upper case and leaves the case of other keywords (and, in, case, ...) to the
// AST, so its UppercaseKeywords option alone changes nothing visible. When
// uppercaseKeywords is true the remaining keywords are therefore upper-cased
// here (data type names are left alone); when false the output is
// gosqlx.Format's, unchanged. indentSize 0 puts each statement on one line;
// positive values only indent nested blocks such as CREATE TABLE columns.
func formatSQLInternal(sql string, indentSize int, uppercaseKeywords, addSemicolon bool) (map[string]any, error) {
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	opts := gosqlx.FormatOptions{
		IndentSize:        indentSize,
		UppercaseKeywords: uppercaseKeywords,
		AddSemicolon:      addSemicolon,
	}

	formatted, err := gosqlx.Format(sql, opts)
	if err != nil {
		return nil, fmt.Errorf("format failed: %w", err)
	}
	if uppercaseKeywords {
		formatted = uppercaseSQLKeywords(formatted)
	}

	return map[string]any{
		"formatted_sql": formatted,
		"options": map[string]any{
			"indent_size":        indentSize,
			"uppercase_keywords": uppercaseKeywords,
			"add_semicolon":      addSemicolon,
		},
	}, nil
}

// keywordCaseRule is lint_sql's L007 rule; its keyword list decides, together
// with the generic reserved words, which words uppercaseSQLKeywords changes,
// so format_sql output with uppercase_keywords passes L007.
var (
	keywordCaseRule = keywords.NewKeywordCaseRule(keywords.CaseUpper)
	genericKeywords = sqlkeywords.New(sqlkeywords.DialectGeneric, true)
)

// isUppercasableKeyword reports whether word is a SQL keyword that
// uppercaseSQLKeywords should upper-case.
func isUppercasableKeyword(word string) bool {
	if genericKeywords.IsReserved(word) {
		return true
	}
	// L007's Fix upper-cases exactly the words in its keyword list.
	lower := strings.ToLower(word)
	fixed, err := keywordCaseRule.Fix(lower, nil)
	return err == nil && fixed != lower
}

// uppercaseSQLKeywords upper-cases the SQL keywords in formatted SQL. String
// literals, quoted identifiers ("x", `x`, [x]), dollar-quoted bodies,
// comments, numbers, parameters (:p, @v, $1) and qualified-name parts (t.key)
// are copied unchanged.
func uppercaseSQLKeywords(sql string) string {
	isWord := func(c byte) bool {
		return c == '_' || c == '$' || c >= 0x80 ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}
	// skipQuoted returns the index just past the closing quote of the
	// quoted text starting at i; a doubled closing quote is an escape.
	skipQuoted := func(i int, closing byte, backslash bool) int {
		for j := i + 1; j < len(sql); j++ {
			switch {
			case backslash && sql[j] == '\\':
				j++
			case sql[j] == closing:
				if j+1 < len(sql) && sql[j+1] == closing && closing != ']' {
					j++
					continue
				}
				return j + 1
			}
		}
		return len(sql)
	}

	var sb strings.Builder
	sb.Grow(len(sql))
	for i := 0; i < len(sql); {
		c := sql[i]
		end := i + 1
		switch {
		case c == '\'':
			end = skipQuoted(i, '\'', true)
		case c == '"' || c == '`':
			end = skipQuoted(i, c, false)
		case c == '[':
			end = skipQuoted(i, ']', false)
		case c == '-' && strings.HasPrefix(sql[i:], "--"):
			if nl := strings.IndexByte(sql[i:], '\n'); nl >= 0 {
				end = i + nl
			} else {
				end = len(sql)
			}
		case c == '/' && strings.HasPrefix(sql[i:], "/*"):
			if close := strings.Index(sql[i+2:], "*/"); close >= 0 {
				end = i + 2 + close + 2
			} else {
				end = len(sql)
			}
		case c == '$':
			// $tag$ ... $tag$ (tag may be empty); $1 and $name are copied as words.
			j := i + 1
			for j < len(sql) && sql[j] != '$' && isWord(sql[j]) {
				j++
			}
			if j < len(sql) && sql[j] == '$' && (j == i+1 || sql[i+1] < '0' || sql[i+1] > '9') {
				tag := sql[i : j+1]
				if close := strings.Index(sql[j+1:], tag); close >= 0 {
					end = j + 1 + close + len(tag)
				} else {
					end = len(sql)
				}
			} else {
				end = j
			}
		case isWord(c):
			for end < len(sql) && isWord(sql[end]) {
				end++
			}
			word := sql[i:end]
			prev, next := byte(0), byte(0)
			if i > 0 {
				prev = sql[i-1]
			}
			if end < len(sql) {
				next = sql[end]
			}
			qualified := prev == '.' || next == '.' || prev == ':' || prev == '@'
			if !qualified && (c < '0' || c > '9') && isUppercasableKeyword(word) {
				word = strings.ToUpper(word)
			}
			sb.WriteString(word)
			i = end
			continue
		}
		sb.WriteString(sql[i:end])
		i = end
	}
	return sb.String()
}

// parseSQLInternal parses a SQL string and returns statement count and types.
func parseSQLInternal(sql string) (map[string]any, error) {
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	stmtTypes := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		stmtTypes = append(stmtTypes, fmt.Sprintf("%T", stmt))
	}

	return map[string]any{
		"statement_count": len(tree.Statements),
		"statement_types": stmtTypes,
	}, nil
}

// extractMetadataInternal parses a SQL string and extracts tables, columns, and functions.
func extractMetadataInternal(sql string) (map[string]any, error) {
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	meta := gosqlx.ExtractMetadata(tree)

	tables := meta.Tables
	if tables == nil {
		tables = []string{}
	}
	columns := meta.Columns
	if columns == nil {
		columns = []string{}
	}
	functions := meta.Functions
	if functions == nil {
		functions = []string{}
	}

	return map[string]any{
		"tables":    tables,
		"columns":   columns,
		"functions": functions,
	}, nil
}

// securityScanInternal scans a SQL string for injection patterns and other threats.
func securityScanInternal(sql string) (map[string]any, error) {
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	scanner := security.NewScanner()
	result := scanner.ScanSQL(sql)

	findings := make([]map[string]any, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, map[string]any{
			"severity":    string(f.Severity),
			"pattern":     string(f.Pattern),
			"description": f.Description,
			"risk":        f.Risk,
			"suggestion":  f.Suggestion,
		})
	}

	return map[string]any{
		"is_clean":       result.IsClean(),
		"has_critical":   result.HasCritical(),
		"has_high":       result.HasHighOrAbove(),
		"total_count":    result.TotalCount,
		"critical_count": result.CriticalCount,
		"high_count":     result.HighCount,
		"medium_count":   result.MediumCount,
		"low_count":      result.LowCount,
		"findings":       findings,
	}, nil
}

// lintSQLInternal runs the full linter rule set against a SQL string.
func lintSQLInternal(sql string) (map[string]any, error) {
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	result := newFullLinter().LintString(sql, "<mcp>")

	violations := make([]map[string]any, 0, len(result.Violations))
	for _, v := range result.Violations {
		violations = append(violations, map[string]any{
			"rule":       v.Rule,
			"rule_name":  v.RuleName,
			"severity":   string(v.Severity),
			"message":    v.Message,
			"line":       v.Location.Line,
			"column":     v.Location.Column,
			"suggestion": v.Suggestion,
		})
	}

	return map[string]any{
		"violation_count": len(result.Violations),
		"violations":      violations,
	}, nil
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// newFullLinter mirrors createLinter() from cmd/gosqlx/cmd/lint.go exactly,
// using a fixed line-length of 100 for the MCP context.
func newFullLinter() *linter.Linter {
	return linter.New(
		whitespace.NewTrailingWhitespaceRule(),     // L001
		whitespace.NewMixedIndentationRule(),       // L002
		whitespace.NewConsecutiveBlankLinesRule(1), // L003
		whitespace.NewIndentationDepthRule(4, 4),   // L004
		whitespace.NewLongLinesRule(100),           // L005
		whitespace.NewRedundantWhitespaceRule(),    // L010

		style.NewColumnAlignmentRule(),                   // L006
		style.NewCommaPlacementRule(style.CommaTrailing), // L008
		style.NewAliasingConsistencyRule(true),           // L009

		keywords.NewKeywordCaseRule(keywords.CaseUpper), // L007
	)
}

// toolResult marshals a map[string]any result into an MCP CallToolResult.
//
// The JSON is returned twice: as the text content (unchanged, for clients that
// only read content) and as structuredContent, which MCP Apps hosts and
// ChatGPT hand to both the model and the UI widget.
func toolResult(data map[string]any) (*mcpmcp.CallToolResult, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}
	return mcpmcp.NewToolResultStructured(data, string(b)), nil
}

// ---------------------------------------------------------------------------
// MCP handler functions
// ---------------------------------------------------------------------------

// handleValidateSQL is the MCP tool handler for "validate_sql".
func handleValidateSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql := req.GetString("sql", "")
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}
	dialect := req.GetString("dialect", "")
	result, err := validateSQLInternal(sql, dialect)
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// handleFormatSQL is the MCP tool handler for "format_sql".
func handleFormatSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql := req.GetString("sql", "")
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}
	indentSize := req.GetInt("indent_size", 2)
	uppercaseKeywords := req.GetBool("uppercase_keywords", false)
	addSemicolon := req.GetBool("add_semicolon", false)
	result, err := formatSQLInternal(sql, indentSize, uppercaseKeywords, addSemicolon)
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// handleParseSQL is the MCP tool handler for "parse_sql".
func handleParseSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql := req.GetString("sql", "")
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}
	result, err := parseSQLInternal(sql)
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// handleExtractMetadata is the MCP tool handler for "extract_metadata".
func handleExtractMetadata(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql := req.GetString("sql", "")
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}
	result, err := extractMetadataInternal(sql)
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// handleSecurityScan is the MCP tool handler for "security_scan".
func handleSecurityScan(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql := req.GetString("sql", "")
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}
	result, err := securityScanInternal(sql)
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// handleLintSQL is the MCP tool handler for "lint_sql".
func handleLintSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql := req.GetString("sql", "")
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}
	result, err := lintSQLInternal(sql)
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// handleAnalyzeSQL is the MCP tool handler for "analyze_sql".
// It fans out all six analysis tools concurrently and merges the results.
func handleAnalyzeSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql := req.GetString("sql", "")
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	type namedResult struct {
		name string
		data map[string]any
		err  error
	}

	tasks := []struct {
		name string
		fn   func() (map[string]any, error)
	}{
		{"validate", func() (map[string]any, error) { return validateSQLInternal(sql, "") }},
		{"parse", func() (map[string]any, error) { return parseSQLInternal(sql) }},
		{"metadata", func() (map[string]any, error) { return extractMetadataInternal(sql) }},
		{"security", func() (map[string]any, error) { return securityScanInternal(sql) }},
		{"lint", func() (map[string]any, error) { return lintSQLInternal(sql) }},
		{"format", func() (map[string]any, error) { return formatSQLInternal(sql, 2, false, false) }},
	}

	results := make(chan namedResult, len(tasks))
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(t struct {
			name string
			fn   func() (map[string]any, error)
		}) {
			defer wg.Done()
			data, err := t.fn()
			results <- namedResult{name: t.name, data: data, err: err}
		}(t)
	}
	wg.Wait()
	close(results)

	combined := make(map[string]any, len(tasks)+1)
	errs := make(map[string]string)
	for r := range results {
		if r.err != nil {
			errs[r.name] = r.err.Error()
		} else {
			combined[r.name] = r.data
		}
	}
	if len(errs) > 0 {
		combined["errors"] = errs
	}
	return toolResult(combined)
}
