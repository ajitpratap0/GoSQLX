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
	"math"
	"strconv"
	"strings"
	"sync"

	mcpmcp "github.com/mark3labs/mcp-go/mcp"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
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
// upper case and leaves the case of other keywords (like, case, ...) to the
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
func parseSQLInternal(sql, dialect string) (map[string]any, error) {
	if sql == "" {
		return nil, fmt.Errorf("parameter 'sql' is required and must not be empty")
	}

	var tree *ast.AST
	var err error
	if dialect == "" {
		tree, err = gosqlx.Parse(sql)
	} else {
		// ParseWithDialect validates against keywords.IsValidDialect, as validate_sql does.
		tree, err = gosqlx.ParseWithDialect(sql, sqlkeywords.SQLDialect(dialect))
	}
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	stmtTypes := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		if _, ok := stmt.(*ast.BatchSeparator); ok {
			continue // a GO line is a client directive, not a statement
		}
		stmtTypes = append(stmtTypes, fmt.Sprintf("%T", stmt))
	}

	return map[string]any{
		"statement_count": len(stmtTypes),
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

// newFullLinter builds the rule set of the `gosqlx lint` CLI command (the
// core rules L001-L010 from rules.CoreRules with the CLI's configuration,
// L005 limit 100).
func newFullLinter() *linter.Linter {
	return linter.New(rules.CoreRules(rules.DefaultCoreConfig())...)
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

// maxIndentSize bounds format_sql's indent_size so a request cannot ask the
// formatter for multi-megabyte indentation strings.
const maxIndentSize = 16

// errSQLRequired is the tool error for a missing, null or empty sql argument.
const errSQLRequired = "parameter 'sql' is required and must not be empty"

// jsonTypeName names the JSON type of a decoded argument value for error messages.
func jsonTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64, float32, int, int64, int32, json.Number:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// sqlArg returns the required "sql" argument. When it is missing, null,
// empty or not a string, it returns an isError tool result instead, so the
// model sees an actionable message rather than a JSON-RPC internal error.
func sqlArg(req mcpmcp.CallToolRequest) (string, *mcpmcp.CallToolResult) {
	v, ok := req.GetArguments()["sql"]
	if !ok || v == nil {
		return "", mcpmcp.NewToolResultError(errSQLRequired)
	}
	sql, ok := v.(string)
	if !ok {
		return "", mcpmcp.NewToolResultError(fmt.Sprintf("parameter 'sql' must be a string, got %s", jsonTypeName(v)))
	}
	if sql == "" {
		return "", mcpmcp.NewToolResultError(errSQLRequired)
	}
	return sql, nil
}

// optionalString returns the string argument name, or def when it is absent or null.
func optionalString(req mcpmcp.CallToolRequest, name, def string) (string, error) {
	v, ok := req.GetArguments()[name]
	if !ok || v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter '%s' must be a string, got %s", name, jsonTypeName(v))
	}
	return s, nil
}

// optionalBool returns the boolean argument name, or def when it is absent or
// null. The strings "true" and "false" are accepted because some clients
// stringify scalar arguments; anything else is an error.
func optionalBool(req mcpmcp.CallToolRequest, name string, def bool) (bool, error) {
	v, ok := req.GetArguments()[name]
	if !ok || v == nil {
		return def, nil
	}
	switch b := v.(type) {
	case bool:
		return b, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("parameter '%s' must be a boolean, got %s %s", name, jsonTypeName(v), shortJSON(v))
}

// optionalInt returns the integer argument name, or def when it is absent or
// null. Whole-number JSON numbers and decimal strings are accepted; the value
// must lie in [min, max].
func optionalInt(req mcpmcp.CallToolRequest, name string, def, min, max int) (int, error) {
	v, ok := req.GetArguments()[name]
	if !ok || v == nil {
		return def, nil
	}
	var f float64
	valid := true
	switch n := v.(type) {
	case float64:
		f = n
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case json.Number:
		parsed, err := n.Float64()
		f, valid = parsed, err == nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(n))
		f, valid = float64(parsed), err == nil
	default:
		valid = false
	}
	if !valid || f != math.Trunc(f) || f < float64(min) || f > float64(max) {
		return 0, fmt.Errorf("parameter '%s' must be an integer between %d and %d, got %s %s",
			name, min, max, jsonTypeName(v), shortJSON(v))
	}
	return int(f), nil
}

// shortJSON renders v for an error message, truncated to keep messages small.
func shortJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	const maxLen = 40
	if len(b) > maxLen {
		return string(b[:maxLen]) + "…"
	}
	return string(b)
}

// toolOutcome converts an internal result into a tool result. Errors from
// the *Internal functions are input problems (unparseable or unformattable
// SQL), so they become isError results; only marshalling failures in
// toolResult remain Go errors (JSON-RPC internal errors).
func toolOutcome(result map[string]any, err error) (*mcpmcp.CallToolResult, error) {
	if err != nil {
		return mcpmcp.NewToolResultError(err.Error()), nil
	}
	return toolResult(result)
}

// handleValidateSQL is the MCP tool handler for "validate_sql".
func handleValidateSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql, errRes := sqlArg(req)
	if errRes != nil {
		return errRes, nil
	}
	dialect, err := optionalString(req, "dialect", "")
	if err != nil {
		return mcpmcp.NewToolResultError(err.Error()), nil
	}
	return toolOutcome(validateSQLInternal(sql, dialect))
}

// handleFormatSQL is the MCP tool handler for "format_sql".
func handleFormatSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql, errRes := sqlArg(req)
	if errRes != nil {
		return errRes, nil
	}
	indentSize, err := optionalInt(req, "indent_size", 2, 0, maxIndentSize)
	if err != nil {
		return mcpmcp.NewToolResultError(err.Error()), nil
	}
	uppercaseKeywords, err := optionalBool(req, "uppercase_keywords", false)
	if err != nil {
		return mcpmcp.NewToolResultError(err.Error()), nil
	}
	addSemicolon, err := optionalBool(req, "add_semicolon", false)
	if err != nil {
		return mcpmcp.NewToolResultError(err.Error()), nil
	}
	return toolOutcome(formatSQLInternal(sql, indentSize, uppercaseKeywords, addSemicolon))
}

// handleParseSQL is the MCP tool handler for "parse_sql".
func handleParseSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql, errRes := sqlArg(req)
	if errRes != nil {
		return errRes, nil
	}
	dialect, err := optionalString(req, "dialect", "")
	if err != nil {
		return mcpmcp.NewToolResultError(err.Error()), nil
	}
	return toolOutcome(parseSQLInternal(sql, dialect))
}

// handleExtractMetadata is the MCP tool handler for "extract_metadata".
func handleExtractMetadata(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql, errRes := sqlArg(req)
	if errRes != nil {
		return errRes, nil
	}
	return toolOutcome(extractMetadataInternal(sql))
}

// handleSecurityScan is the MCP tool handler for "security_scan".
func handleSecurityScan(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql, errRes := sqlArg(req)
	if errRes != nil {
		return errRes, nil
	}
	return toolOutcome(securityScanInternal(sql))
}

// handleLintSQL is the MCP tool handler for "lint_sql".
func handleLintSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql, errRes := sqlArg(req)
	if errRes != nil {
		return errRes, nil
	}
	return toolOutcome(lintSQLInternal(sql))
}

// handleAnalyzeSQL is the MCP tool handler for "analyze_sql".
// It fans out all six analysis tools concurrently and merges the results.
func handleAnalyzeSQL(ctx context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
	sql, errRes := sqlArg(req)
	if errRes != nil {
		return errRes, nil
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
		{"parse", func() (map[string]any, error) { return parseSQLInternal(sql, "") }},
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
