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

	return map[string]any{
		"formatted_sql": formatted,
		"options": map[string]any{
			"indent_size":        indentSize,
			"uppercase_keywords": uppercaseKeywords,
			"add_semicolon":      addSemicolon,
		},
	}, nil
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
func toolResult(data map[string]any) (*mcpmcp.CallToolResult, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}
	return mcpmcp.NewToolResultText(string(b)), nil
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
