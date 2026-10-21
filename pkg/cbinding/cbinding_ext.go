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

// This file holds the dialect-aware variants of the original exports and the
// analysis exports (lint, security scan, transpile, dialect list). It also
// holds the shared helpers both the original and the new exports go through,
// so a dialect-less call of a *_dialect export and the original export always
// produce the same JSON.

package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	lintkeywords "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

// errCodeUnsupportedDialect is the "error_code" every export reports for a
// dialect name that keywords.IsValidDialect rejects.
var errCodeUnsupportedDialect = string(goerrors.ErrCodeUnsupportedDialect)

// errCodeInvalidOptions is the "error_code" gosqlx_lint reports for an
// options_json argument that is not a valid options object.
const errCodeInvalidOptions = "INVALID_OPTIONS"

// formatLineWidth is the line width gosqlx.DefaultFormatOptions sets. It is
// spelled out because the FormatOptions field that carries it is deprecated.
const formatLineWidth = 80

// defaultLintMaxLineLength mirrors the default of `gosqlx lint --max-length`.
const defaultLintMaxLineLength = 100

// unsupportedDialectError is the error dialectError returns, so callers can
// tell an unknown dialect apart from a parse failure.
type unsupportedDialectError struct{ dialect string }

func (e *unsupportedDialectError) Error() string {
	return fmt.Sprintf("unknown SQL dialect %q; valid dialects: %s",
		e.dialect, strings.Join(keywords.DialectNames(), ", "))
}

// dialectError returns nil when dialect is empty or a name accepted by
// keywords.IsValidDialect, and otherwise an error naming the valid dialects in
// the same words the CLI uses.
func dialectError(dialect string) error {
	if keywords.IsValidDialect(dialect) {
		return nil
	}
	return &unsupportedDialectError{dialect: dialect}
}

// errorCodeFor returns the "error_code" value for err: E4002 for an unknown
// dialect, empty otherwise (parse errors keep reporting only the message and
// position, exactly as the original exports always have).
func errorCodeFor(err error) string {
	var de *unsupportedDialectError
	if errors.As(err, &de) {
		return errCodeUnsupportedDialect
	}
	return ""
}

// parseFor parses sql with the given dialect. An empty dialect goes through
// gosqlx.Parse, the path the original exports have always used.
func parseFor(sql, dialect string) (*ast.AST, error) {
	if err := dialectError(dialect); err != nil {
		return nil, err
	}
	if dialect == "" {
		return gosqlx.Parse(sql)
	}
	return gosqlx.ParseWithDialect(sql, keywords.SQLDialect(dialect))
}

// parseResultFor builds the gosqlx_parse / gosqlx_parse_dialect result.
func parseResultFor(sql, dialect string) ParseResult {
	tree, err := parseFor(sql, dialect)
	if err != nil {
		line, col := extractErrorPosition(err.Error())
		return ParseResult{
			Success:     false,
			Error:       err.Error(),
			ErrorLine:   line,
			ErrorColumn: col,
			ErrorCode:   errorCodeFor(err),
		}
	}

	stmtTypes := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		stmtTypes = append(stmtTypes, statementTypeName(stmt))
	}
	return ParseResult{
		Success:   true,
		StmtCount: len(tree.Statements),
		StmtTypes: stmtTypes,
	}
}

// validateFor validates sql with the given dialect. An empty dialect goes
// through gosqlx.Validate; otherwise the dialect-aware validation fast path is
// used with the same empty-input rule and error wrapping as gosqlx.Validate.
func validateFor(sql, dialect string) error {
	if err := dialectError(dialect); err != nil {
		return err
	}
	if dialect == "" {
		return gosqlx.Validate(sql)
	}
	if strings.TrimSpace(sql) == "" {
		return fmt.Errorf("%w: empty input", gosqlx.ErrSyntax)
	}
	if err := parser.ValidateWithDialect(sql, keywords.SQLDialect(dialect)); err != nil {
		return fmt.Errorf("%w: %w", gosqlx.ErrSyntax, err)
	}
	return nil
}

// validationResultFor builds the gosqlx_validate / gosqlx_validate_dialect result.
func validationResultFor(sql, dialect string) ValidationResult {
	if err := validateFor(sql, dialect); err != nil {
		line, col := extractErrorPosition(err.Error())
		return ValidationResult{
			Valid:       false,
			Error:       err.Error(),
			ErrorLine:   line,
			ErrorColumn: col,
			ErrorCode:   errorCodeFor(err),
		}
	}
	return ValidationResult{Valid: true}
}

// formatFor formats sql with gosqlx.DefaultFormatOptions. An empty dialect goes
// through gosqlx.Format; otherwise the SQL is parsed with the dialect and
// rendered with the same option mapping gosqlx.Format uses, plus the dialect so
// dialect-specific constructs are rendered for that dialect.
func formatFor(sql, dialect string) (string, error) {
	if err := dialectError(dialect); err != nil {
		return "", err
	}
	opts := gosqlx.DefaultFormatOptions()
	if dialect == "" {
		return gosqlx.Format(sql, opts)
	}
	tree, err := gosqlx.ParseWithDialect(sql, keywords.SQLDialect(dialect))
	if err != nil {
		return "", fmt.Errorf("cannot format invalid SQL: %w", err)
	}
	kwCase := ast.KeywordPreserve
	if opts.UppercaseKeywords {
		kwCase = ast.KeywordUpper
	}
	return formatter.FormatAST(tree, ast.FormatOptions{
		IndentStyle:      ast.IndentSpaces,
		IndentWidth:      opts.IndentSize,
		KeywordCase:      kwCase,
		LineWidth:        formatLineWidth,
		NewlinePerClause: opts.IndentSize > 0,
		AddSemicolon:     opts.AddSemicolon,
		Dialect:          dialect,
	}), nil
}

// formatResultFor builds the gosqlx_format / gosqlx_format_dialect result.
func formatResultFor(sql, dialect string) FormatResult {
	formatted, err := formatFor(sql, dialect)
	if err != nil {
		return FormatResult{
			Success:   false,
			Error:     err.Error(),
			ErrorCode: errorCodeFor(err),
		}
	}
	return FormatResult{Success: true, Formatted: formatted}
}

// extractListFor builds the JSON object of the gosqlx_extract_{tables,columns,
// functions}[_dialect] exports: {key: [...]} on success, {"error": ...} (plus
// "error_code" for an unknown dialect) on failure.
func extractListFor(sql, dialect, key string, extract func(*ast.AST) []string) map[string]interface{} {
	tree, err := parseFor(sql, dialect)
	if err != nil {
		out := map[string]interface{}{"error": err.Error()}
		if code := errorCodeFor(err); code != "" {
			out["error_code"] = code
		}
		return out
	}
	items := extract(tree)
	if items == nil {
		items = []string{}
	}
	return map[string]interface{}{key: items}
}

// metadataFor builds the gosqlx_extract_metadata[_dialect] result.
func metadataFor(sql, dialect string) MetadataResult {
	tree, err := parseFor(sql, dialect)
	if err != nil {
		return MetadataResult{Error: err.Error(), ErrorCode: errorCodeFor(err)}
	}

	metadata := gosqlx.ExtractMetadata(tree)

	tablesQualified := make([]QualifiedNameJSON, 0, len(metadata.TablesQualified))
	for _, tq := range metadata.TablesQualified {
		tablesQualified = append(tablesQualified, QualifiedNameJSON{
			Schema: tq.Schema,
			Table:  tq.Table,
			Name:   tq.Name,
		})
	}

	columnsQualified := make([]QualifiedNameJSON, 0, len(metadata.ColumnsQualified))
	for _, cq := range metadata.ColumnsQualified {
		columnsQualified = append(columnsQualified, QualifiedNameJSON{
			Schema: cq.Schema,
			Table:  cq.Table,
			Name:   cq.Name,
		})
	}

	// Ensure non-nil slices for consistent JSON output.
	tables := metadata.Tables
	if tables == nil {
		tables = []string{}
	}
	columns := metadata.Columns
	if columns == nil {
		columns = []string{}
	}
	functions := metadata.Functions
	if functions == nil {
		functions = []string{}
	}

	return MetadataResult{
		Tables:           tables,
		TablesQualified:  tablesQualified,
		Columns:          columns,
		ColumnsQualified: columnsQualified,
		Functions:        functions,
	}
}

// ---------------------------------------------------------------------------
// Dialect-aware variants of the original exports
// ---------------------------------------------------------------------------

// gosqlx_parse_dialect is gosqlx_parse with a SQL dialect (one of the names
// returned by gosqlx_dialects). A NULL or empty dialect behaves exactly like
// gosqlx_parse. An unknown dialect returns {"success": false, "error": ...,
// "error_code": "E4002"}.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_parse_dialect
func gosqlx_parse_dialect(sql, dialect *C.char) *C.char {
	return toJSON(parseResultFor(C.GoString(sql), C.GoString(dialect)))
}

// gosqlx_validate_dialect is gosqlx_validate with a SQL dialect. A NULL or
// empty dialect behaves exactly like gosqlx_validate. An unknown dialect
// returns {"valid": false, "error": ..., "error_code": "E4002"}.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_validate_dialect
func gosqlx_validate_dialect(sql, dialect *C.char) *C.char {
	return toJSON(validationResultFor(C.GoString(sql), C.GoString(dialect)))
}

// gosqlx_format_dialect is gosqlx_format with a SQL dialect: the SQL is parsed
// with the dialect and rendered for it. A NULL or empty dialect behaves exactly
// like gosqlx_format. An unknown dialect returns {"success": false, "error":
// ..., "error_code": "E4002"}.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_format_dialect
func gosqlx_format_dialect(sql, dialect *C.char) *C.char {
	return toJSON(formatResultFor(C.GoString(sql), C.GoString(dialect)))
}

// gosqlx_extract_tables_dialect is gosqlx_extract_tables with a SQL dialect.
// A NULL or empty dialect behaves exactly like gosqlx_extract_tables. An
// unknown dialect returns {"error": ..., "error_code": "E4002"}.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_tables_dialect
func gosqlx_extract_tables_dialect(sql, dialect *C.char) *C.char {
	return toJSON(extractListFor(C.GoString(sql), C.GoString(dialect), "tables", gosqlx.ExtractTables))
}

// gosqlx_extract_columns_dialect is gosqlx_extract_columns with a SQL dialect.
// A NULL or empty dialect behaves exactly like gosqlx_extract_columns. An
// unknown dialect returns {"error": ..., "error_code": "E4002"}.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_columns_dialect
func gosqlx_extract_columns_dialect(sql, dialect *C.char) *C.char {
	return toJSON(extractListFor(C.GoString(sql), C.GoString(dialect), "columns", gosqlx.ExtractColumns))
}

// gosqlx_extract_functions_dialect is gosqlx_extract_functions with a SQL
// dialect. A NULL or empty dialect behaves exactly like
// gosqlx_extract_functions. An unknown dialect returns {"error": ...,
// "error_code": "E4002"}.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_functions_dialect
func gosqlx_extract_functions_dialect(sql, dialect *C.char) *C.char {
	return toJSON(extractListFor(C.GoString(sql), C.GoString(dialect), "functions", gosqlx.ExtractFunctions))
}

// gosqlx_extract_metadata_dialect is gosqlx_extract_metadata with a SQL
// dialect. A NULL or empty dialect behaves exactly like
// gosqlx_extract_metadata. An unknown dialect returns {"error": ...,
// "error_code": "E4002"}.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_metadata_dialect
func gosqlx_extract_metadata_dialect(sql, dialect *C.char) *C.char {
	return toJSON(metadataFor(C.GoString(sql), C.GoString(dialect)))
}

// ---------------------------------------------------------------------------
// gosqlx_lint
// ---------------------------------------------------------------------------

// LintOptions is the options_json object accepted by gosqlx_lint. Unknown
// fields are rejected so a misspelt option is an error, not a silent no-op.
type LintOptions struct {
	// Dialect selects the tokenizer/parser dialect (empty = default).
	Dialect string `json:"dialect"`
	// MaxLineLength is the L005 limit; omitted or null means 100, the
	// `gosqlx lint --max-length` default. It must be positive when set.
	MaxLineLength *int `json:"max_line_length"`
}

// LintViolationJSON is one lint violation in the gosqlx_lint result.
type LintViolationJSON struct {
	Rule       string `json:"rule"`
	RuleName   string `json:"rule_name"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Suggestion string `json:"suggestion,omitempty"`
	CanAutoFix bool   `json:"can_auto_fix"`
}

// LintResult is the JSON result of gosqlx_lint.
type LintResult struct {
	Success        bool                `json:"success"`
	ViolationCount int                 `json:"violation_count"`
	Violations     []LintViolationJSON `json:"violations"`
	Error          string              `json:"error,omitempty"`
	ErrorCode      string              `json:"error_code,omitempty"`
}

// parseLintOptions decodes options_json. An empty string (or NULL) means all
// defaults.
func parseLintOptions(raw string) (LintOptions, error) {
	var opts LintOptions
	if strings.TrimSpace(raw) == "" {
		return opts, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&opts); err != nil {
		return opts, fmt.Errorf("invalid options_json: %w", err)
	}
	if dec.More() {
		return opts, errors.New("invalid options_json: trailing data after the options object")
	}
	if opts.MaxLineLength != nil && *opts.MaxLineLength <= 0 {
		return opts, fmt.Errorf("invalid options_json: max_line_length must be positive, got %d", *opts.MaxLineLength)
	}
	return opts, nil
}

// newLinter builds the rule set of the `gosqlx lint` CLI command
// (createLinter in cmd/gosqlx/cmd/lint.go, also mirrored by pkg/mcp's
// newFullLinter): L001-L010 with the CLI's rule configuration. Keep the three
// in sync when the CLI's default rule set changes.
func newLinter(maxLineLength int, dialect string) *linter.Linter {
	l := linter.New(
		// Whitespace rules (L001, L002, L003, L004, L005, L010)
		whitespace.NewTrailingWhitespaceRule(),     // L001
		whitespace.NewMixedIndentationRule(),       // L002
		whitespace.NewConsecutiveBlankLinesRule(1), // L003
		whitespace.NewIndentationDepthRule(4, 4),   // L004
		whitespace.NewLongLinesRule(maxLineLength), // L005
		whitespace.NewRedundantWhitespaceRule(),    // L010

		// Style rules (L006, L008, L009)
		style.NewColumnAlignmentRule(),                   // L006
		style.NewCommaPlacementRule(style.CommaTrailing), // L008
		style.NewAliasingConsistencyRule(true),           // L009

		// Keyword rules (L007)
		lintkeywords.NewKeywordCaseRule(lintkeywords.CaseUpper), // L007
	)
	if dialect != "" {
		l.SetDialect(keywords.SQLDialect(dialect))
	}
	return l
}

// lintFor runs the CLI lint rule set over sql.
func lintFor(sql, optionsJSON string) LintResult {
	fail := func(err error, code string) LintResult {
		return LintResult{
			Success:    false,
			Violations: []LintViolationJSON{},
			Error:      err.Error(),
			ErrorCode:  code,
		}
	}

	opts, err := parseLintOptions(optionsJSON)
	if err != nil {
		return fail(err, errCodeInvalidOptions)
	}
	if err := dialectError(opts.Dialect); err != nil {
		return fail(err, errorCodeFor(err))
	}
	maxLen := defaultLintMaxLineLength
	if opts.MaxLineLength != nil {
		maxLen = *opts.MaxLineLength
	}

	fileResult := newLinter(maxLen, opts.Dialect).LintString(sql, "<input>")
	if fileResult.Error != nil {
		return fail(fileResult.Error, "")
	}

	violations := make([]LintViolationJSON, 0, len(fileResult.Violations))
	for _, v := range fileResult.Violations {
		violations = append(violations, LintViolationJSON{
			Rule:       v.Rule,
			RuleName:   v.RuleName,
			Severity:   string(v.Severity),
			Message:    v.Message,
			Line:       v.Location.Line,
			Column:     v.Location.Column,
			Suggestion: v.Suggestion,
			CanAutoFix: v.CanAutoFix,
		})
	}
	return LintResult{
		Success:        true,
		ViolationCount: len(violations),
		Violations:     violations,
	}
}

// gosqlx_lint lints a SQL string with the rule set of the `gosqlx lint` CLI
// command (L001-L010, L005 limit 100 by default).
//
// Parameters:
//   - sql: a C string containing the SQL to lint.
//   - options_json: NULL, "" or a JSON object with the optional fields
//     "dialect" (a name from gosqlx_dialects) and "max_line_length" (positive
//     integer, default 100). Unknown fields are rejected.
//
// The result is {"success": true, "violation_count": N, "violations": [...]}
// where each violation has rule, rule_name, severity, message, line, column,
// suggestion and can_auto_fix. Invalid options return {"success": false,
// "error": ..., "error_code": "INVALID_OPTIONS"}; an unknown dialect uses
// error_code "E4002". SQL that does not parse is still linted: the text and
// token rules run and no error is reported.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_lint
func gosqlx_lint(sql, options_json *C.char) *C.char {
	return toJSON(lintFor(C.GoString(sql), C.GoString(options_json)))
}

// ---------------------------------------------------------------------------
// gosqlx_security_scan
// ---------------------------------------------------------------------------

// SecurityScanResult is the JSON result of gosqlx_security_scan.
type SecurityScanResult struct {
	Success       bool               `json:"success"`
	IsClean       bool               `json:"is_clean"`
	HasCritical   bool               `json:"has_critical"`
	HasHigh       bool               `json:"has_high"`
	TotalCount    int                `json:"total_count"`
	CriticalCount int                `json:"critical_count"`
	HighCount     int                `json:"high_count"`
	MediumCount   int                `json:"medium_count"`
	LowCount      int                `json:"low_count"`
	Findings      []security.Finding `json:"findings"`
}

// securityScanFor scans sql with security.Scanner.ScanSQL, the raw-text scan
// the MCP security_scan tool uses. It needs no parse, so injection payloads
// that are not valid SQL are still scanned.
func securityScanFor(sql string) SecurityScanResult {
	result := security.NewScanner().ScanSQL(sql)
	findings := result.Findings
	if findings == nil {
		findings = []security.Finding{}
	}
	return SecurityScanResult{
		Success:       true,
		IsClean:       result.IsClean(),
		HasCritical:   result.HasCritical(),
		HasHigh:       result.HasHighOrAbove(),
		TotalCount:    result.TotalCount,
		CriticalCount: result.CriticalCount,
		HighCount:     result.HighCount,
		MediumCount:   result.MediumCount,
		LowCount:      result.LowCount,
		Findings:      findings,
	}
}

// gosqlx_security_scan scans a SQL string for SQL injection patterns
// (tautologies, comment bypass, stacked queries, UNION injection, time-based
// and out-of-band techniques, dangerous functions) using pkg/sql/security.
//
// The result is {"success": true, "is_clean": ..., "has_critical": ...,
// "has_high": ..., "total_count": N, "critical_count": ..., "high_count": ...,
// "medium_count": ..., "low_count": ..., "findings": [...]} where each finding
// has severity, pattern, description, risk and optional line, column, sql and
// suggestion. Empty input is clean.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_security_scan
func gosqlx_security_scan(sql *C.char) *C.char {
	return toJSON(securityScanFor(C.GoString(sql)))
}

// ---------------------------------------------------------------------------
// gosqlx_transpile
// ---------------------------------------------------------------------------

// TranspileResult is the JSON result of gosqlx_transpile.
type TranspileResult struct {
	Success   bool   `json:"success"`
	SQL       string `json:"sql,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// transpileFor converts sql between two dialects with gosqlx.Transpile. Both
// dialects are required and must be names from keywords.DialectNames.
func transpileFor(sql, from, to string) TranspileResult {
	for _, d := range [...]struct{ role, name string }{{"source", from}, {"target", to}} {
		if d.name == "" {
			return TranspileResult{
				Error: fmt.Sprintf("%s dialect is required; valid dialects: %s",
					d.role, strings.Join(keywords.DialectNames(), ", ")),
				ErrorCode: errCodeUnsupportedDialect,
			}
		}
		if err := dialectError(d.name); err != nil {
			return TranspileResult{Error: err.Error(), ErrorCode: errorCodeFor(err)}
		}
	}
	out, err := gosqlx.Transpile(sql, keywords.SQLDialect(from), keywords.SQLDialect(to))
	if err != nil {
		return TranspileResult{Error: err.Error()}
	}
	return TranspileResult{Success: true, SQL: out}
}

// gosqlx_transpile converts SQL from one dialect to another with
// gosqlx.Transpile. Dialect pairs without dedicated rewrite rules are parsed
// with the source dialect and re-rendered unchanged.
//
// Parameters:
//   - sql: a C string containing the SQL to convert.
//   - from: the source dialect (a name from gosqlx_dialects; required).
//   - to: the target dialect (a name from gosqlx_dialects; required).
//
// The result is {"success": true, "sql": "..."} or {"success": false,
// "error": ...}; a missing or unknown dialect sets "error_code": "E4002".
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_transpile
func gosqlx_transpile(sql, from, to *C.char) *C.char {
	return toJSON(transpileFor(C.GoString(sql), C.GoString(from), C.GoString(to)))
}

// ---------------------------------------------------------------------------
// gosqlx_dialects
// ---------------------------------------------------------------------------

// DialectsResult is the JSON result of gosqlx_dialects.
type DialectsResult struct {
	Dialects []string `json:"dialects"`
}

// gosqlx_dialects returns {"dialects": [...]}, the dialect names accepted by
// every *_dialect export, gosqlx_lint and gosqlx_transpile, in the stable order
// of keywords.DialectNames.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_dialects
func gosqlx_dialects() *C.char {
	return toJSON(DialectsResult{Dialects: keywords.DialectNames()})
}
