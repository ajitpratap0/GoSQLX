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

// Package main is compiled as a C-shared library (libgosqlx) that exposes the GoSQLX
// SQL parsing engine to non-Go languages via a plain C FFI.
//
// The library is built with "go build -buildmode=c-shared" (see build.sh) and produces
// a platform-native shared object - libgosqlx.so on Linux, libgosqlx.dylib on macOS,
// and libgosqlx.dll on Windows - together with a generated C header (libgosqlx.h).
// The primary consumer is the Python package pygosqlx, which loads the library at
// runtime via ctypes, but any language with a C FFI (Ruby, Node.js via N-API, Rust FFI,
// etc.) can call the exported symbols directly.
//
// All exported functions follow the same contract: they accept C strings (null-terminated
// UTF-8) and return a newly allocated C string containing a JSON-encoded result object.
// Callers must free every returned string with gosqlx_free to avoid memory leaks.
//
// Exported symbols:
//
//	gosqlx_parse(sql)             - parse SQL, return ParseResult JSON
//	gosqlx_validate(sql)          - validate SQL syntax, return ValidationResult JSON
//	gosqlx_format(sql)            - format SQL, return FormatResult JSON
//	gosqlx_extract_tables(sql)    - extract referenced table names as JSON array
//	gosqlx_extract_columns(sql)   - extract referenced column names as JSON array
//	gosqlx_extract_functions(sql) - extract referenced function names as JSON array
//	gosqlx_extract_metadata(sql)  - extract tables, columns, functions with schema qualification
//	gosqlx_version()              - return the library version string (e.g. "1.10.0")
//	gosqlx_free(ptr)              - free a string previously returned by any gosqlx_* function
//
// Dialect-aware and analysis exports (added for pygosqlx 0.3.0; see cbinding_ext.go):
//
//	gosqlx_parse_dialect(sql, dialect)             - gosqlx_parse with a SQL dialect
//	gosqlx_validate_dialect(sql, dialect)          - gosqlx_validate with a SQL dialect
//	gosqlx_format_dialect(sql, dialect)            - gosqlx_format with a SQL dialect
//	gosqlx_extract_tables_dialect(sql, dialect)    - gosqlx_extract_tables with a SQL dialect
//	gosqlx_extract_columns_dialect(sql, dialect)   - gosqlx_extract_columns with a SQL dialect
//	gosqlx_extract_functions_dialect(sql, dialect) - gosqlx_extract_functions with a SQL dialect
//	gosqlx_extract_metadata_dialect(sql, dialect)  - gosqlx_extract_metadata with a SQL dialect
//	gosqlx_lint(sql, options_json)                 - run the `gosqlx lint` rule set (L001-L010)
//	gosqlx_security_scan(sql)                      - scan SQL for injection patterns
//	gosqlx_transpile(sql, from, to)                - convert SQL between dialects
//	gosqlx_dialects()                              - list the accepted dialect names
//
// The *_dialect variants take the dialect as a plain C string rather than an
// options JSON object: a dialect is the only option those operations accept, so
// a second string argument keeps the ABI as simple as the original exports. A
// NULL or empty dialect behaves exactly like the original export. An unknown
// dialect yields the operation's normal error shape with "error_code" set to
// "E4002" (pkg/errors.ErrCodeUnsupportedDialect) and the error message listing
// the valid names from gosqlx_dialects. Exports that genuinely take several
// options (gosqlx_lint) accept an options JSON object instead.
//
// The original exports are ABI-stable: their names, signatures and JSON output
// are unchanged. New fields are only ever added with omitempty so existing
// consumers see byte-identical results.
package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"regexp"
	"strconv"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// VERSION is the version of the GoSQLX C binding library,
// sourced from the gosqlx package to avoid hardcoded duplication.
var VERSION = gosqlx.Version

// errorPositionRegex matches "line X, column Y" patterns in error messages.
var errorPositionRegex = regexp.MustCompile(`line\s+(\d+),\s*column\s+(\d+)`)

// ParseResult represents the result of parsing SQL.
type ParseResult struct {
	Success     bool     `json:"success"`
	Error       string   `json:"error,omitempty"`
	ErrorLine   int      `json:"error_line,omitempty"`
	ErrorColumn int      `json:"error_column,omitempty"`
	StmtCount   int      `json:"statement_count"`
	StmtTypes   []string `json:"statement_types"`
	// ErrorCode is set only by the *_dialect exports for an unknown dialect.
	ErrorCode string `json:"error_code,omitempty"`
}

// ValidationResult represents the result of validating SQL.
type ValidationResult struct {
	Valid       bool   `json:"valid"`
	Error       string `json:"error,omitempty"`
	ErrorLine   int    `json:"error_line,omitempty"`
	ErrorColumn int    `json:"error_column,omitempty"`
	// ErrorCode is set only by the *_dialect exports for an unknown dialect.
	ErrorCode string `json:"error_code,omitempty"`
}

// FormatResult represents the result of formatting SQL.
type FormatResult struct {
	Success   bool   `json:"success"`
	Formatted string `json:"formatted,omitempty"`
	Error     string `json:"error,omitempty"`
	// ErrorCode is set only by the *_dialect exports for an unknown dialect.
	ErrorCode string `json:"error_code,omitempty"`
}

// QualifiedNameJSON represents a qualified name for JSON serialization.
type QualifiedNameJSON struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
	Name   string `json:"name"`
}

// MetadataResult represents the result of extracting metadata from SQL.
type MetadataResult struct {
	Tables           []string            `json:"tables"`
	TablesQualified  []QualifiedNameJSON `json:"tables_qualified"`
	Columns          []string            `json:"columns"`
	ColumnsQualified []QualifiedNameJSON `json:"columns_qualified"`
	Functions        []string            `json:"functions"`
	Error            string              `json:"error,omitempty"`
	// ErrorCode is set only by the *_dialect exports for an unknown dialect.
	ErrorCode string `json:"error_code,omitempty"`
}

// extractErrorPosition extracts line and column numbers from an error message string.
// Returns (0, 0) if the pattern is not found.
func extractErrorPosition(errMsg string) (int, int) {
	matches := errorPositionRegex.FindStringSubmatch(errMsg)
	if len(matches) == 3 {
		line, errL := strconv.Atoi(matches[1])
		col, errC := strconv.Atoi(matches[2])
		if errL == nil && errC == nil {
			return line, col
		}
	}
	return 0, 0
}

// toJSON marshals the value to a JSON C string. If marshaling fails, it returns
// a fallback error JSON string with the error message properly escaped.
func toJSON(v interface{}) *C.char {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		// Marshal the error message separately to ensure proper JSON escaping.
		errMsg, marshalErr := json.Marshal("json marshal failed: " + err.Error())
		if marshalErr != nil {
			// Both marshals failed; return a safe static fallback.
			return C.CString(`{"error":"json marshal failed"}`)
		}
		fallback := `{"error":` + string(errMsg) + `}`
		return C.CString(fallback)
	}
	return C.CString(string(jsonBytes))
}

// statementTypeName returns the string name for a given AST statement type.
func statementTypeName(stmt ast.Statement) string {
	switch stmt.(type) {
	case *ast.SelectStatement:
		return "SELECT"
	case *ast.InsertStatement:
		return "INSERT"
	case *ast.UpdateStatement:
		return "UPDATE"
	case *ast.DeleteStatement:
		return "DELETE"
	case *ast.CreateTableStatement:
		return "CREATE_TABLE"
	case *ast.CreateViewStatement:
		return "CREATE_VIEW"
	case *ast.CreateIndexStatement:
		return "CREATE_INDEX"
	case *ast.AlterTableStatement: //nolint:staticcheck // AlterTableStatement kept for backward compatibility
		return "ALTER_TABLE"
	case *ast.DropStatement:
		return "DROP"
	case *ast.MergeStatement:
		return "MERGE"
	case *ast.TruncateStatement:
		return "TRUNCATE"
	default:
		return "OTHER"
	}
}

// gosqlx_parse parses a SQL string and returns a JSON-encoded ParseResult.
// The result contains success status, statement count, statement types, and
// error details (with line/column) on failure.
//
// Parameters:
//   - sql: a C string containing the SQL to parse.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_parse
func gosqlx_parse(sql *C.char) *C.char {
	return toJSON(parseResultFor(C.GoString(sql), ""))
}

// gosqlx_validate validates a SQL string for syntactic correctness and returns
// a JSON-encoded ValidationResult. The result contains a valid flag and error
// details (with line/column) on failure.
//
// Parameters:
//   - sql: a C string containing the SQL to validate.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_validate
func gosqlx_validate(sql *C.char) *C.char {
	return toJSON(validationResultFor(C.GoString(sql), ""))
}

// gosqlx_format formats a SQL string using default formatting options and
// returns a JSON-encoded FormatResult. The result contains the formatted SQL
// on success or an error message on failure.
//
// Parameters:
//   - sql: a C string containing the SQL to format.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_format
func gosqlx_format(sql *C.char) *C.char {
	return toJSON(formatResultFor(C.GoString(sql), ""))
}

// gosqlx_extract_tables parses a SQL string and extracts all referenced table
// names. Returns a JSON object with a "tables" array on success or an "error"
// field on failure.
//
// Parameters:
//   - sql: a C string containing the SQL to analyze.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_tables
func gosqlx_extract_tables(sql *C.char) *C.char {
	return toJSON(extractListFor(C.GoString(sql), "", "tables", gosqlx.ExtractTables))
}

// gosqlx_extract_columns parses a SQL string and extracts all referenced column
// names. Returns a JSON object with a "columns" array on success or an "error"
// field on failure.
//
// Parameters:
//   - sql: a C string containing the SQL to analyze.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_columns
func gosqlx_extract_columns(sql *C.char) *C.char {
	return toJSON(extractListFor(C.GoString(sql), "", "columns", gosqlx.ExtractColumns))
}

// gosqlx_extract_functions parses a SQL string and extracts all referenced
// function names (e.g., COUNT, SUM). Returns a JSON object with a "functions"
// array on success or an "error" field on failure.
//
// Parameters:
//   - sql: a C string containing the SQL to analyze.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_functions
func gosqlx_extract_functions(sql *C.char) *C.char {
	return toJSON(extractListFor(C.GoString(sql), "", "functions", gosqlx.ExtractFunctions))
}

// gosqlx_extract_metadata parses a SQL string and extracts comprehensive
// metadata including tables, columns, and functions with both simple name
// lists and schema-qualified variants. Returns a JSON-encoded MetadataResult.
//
// Parameters:
//   - sql: a C string containing the SQL to analyze.
//
// Returns a C string with the JSON result. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_extract_metadata
func gosqlx_extract_metadata(sql *C.char) *C.char {
	return toJSON(metadataFor(C.GoString(sql), ""))
}

// gosqlx_free releases memory allocated by the C binding functions.
// Passing NULL is a no-op (free(NULL) is defined by the C standard).
// Every C string returned by any other gosqlx_* export (gosqlx_parse,
// gosqlx_validate, gosqlx_format, the gosqlx_extract_* functions, every
// *_dialect variant, gosqlx_lint, gosqlx_security_scan, gosqlx_transpile,
// gosqlx_dialects and gosqlx_version) must be freed exactly once with this
// function to avoid memory leaks.
//
// Parameters:
//   - ptr: a C string pointer previously returned by a gosqlx_* function.
//
//export gosqlx_free
func gosqlx_free(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

// gosqlx_version returns the current GoSQLX library version as a C string.
// The version follows semantic versioning (e.g., "1.8.0").
//
// Returns a newly allocated C string with the version on every call. Like every
// other gosqlx_* result, the caller owns it and must free it exactly once with
// gosqlx_free. (Earlier releases returned a process-wide cached pointer here,
// which made the documented free a double free on the second call.)
//
//export gosqlx_version
func gosqlx_version() *C.char {
	return C.CString(VERSION)
}

func main() {}
