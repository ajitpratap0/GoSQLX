package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"regexp"
	"strconv"
	"sync"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// VERSION is the version of the GoSQLX C binding library,
// sourced from the gosqlx package to avoid hardcoded duplication.
var VERSION = gosqlx.Version

// errorPositionRegex matches "line X, column Y" patterns in error messages.
var errorPositionRegex = regexp.MustCompile(`line\s+(\d+),\s*column\s+(\d+)`)

// cachedVersion is a process-lifetime C string for gosqlx_version().
// Allocated once via sync.Once to avoid leaking memory on every call.
var (
	cachedVersion     *C.char
	cachedVersionOnce sync.Once
)

// ParseResult represents the result of parsing SQL.
type ParseResult struct {
	Success     bool     `json:"success"`
	Error       string   `json:"error,omitempty"`
	ErrorLine   int      `json:"error_line,omitempty"`
	ErrorColumn int      `json:"error_column,omitempty"`
	StmtCount   int      `json:"statement_count"`
	StmtTypes   []string `json:"statement_types"`
}

// ValidationResult represents the result of validating SQL.
type ValidationResult struct {
	Valid       bool   `json:"valid"`
	Error       string `json:"error,omitempty"`
	ErrorLine   int    `json:"error_line,omitempty"`
	ErrorColumn int    `json:"error_column,omitempty"`
}

// FormatResult represents the result of formatting SQL.
type FormatResult struct {
	Success   bool   `json:"success"`
	Formatted string `json:"formatted,omitempty"`
	Error     string `json:"error,omitempty"`
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
	case *ast.AlterTableStatement:
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
	goSQL := C.GoString(sql)

	tree, err := gosqlx.Parse(goSQL)
	if err != nil {
		line, col := extractErrorPosition(err.Error())
		result := ParseResult{
			Success:     false,
			Error:       err.Error(),
			ErrorLine:   line,
			ErrorColumn: col,
		}
		return toJSON(result)
	}

	stmtTypes := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		stmtTypes = append(stmtTypes, statementTypeName(stmt))
	}

	result := ParseResult{
		Success:   true,
		StmtCount: len(tree.Statements),
		StmtTypes: stmtTypes,
	}
	return toJSON(result)
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
	goSQL := C.GoString(sql)

	err := gosqlx.Validate(goSQL)
	if err != nil {
		line, col := extractErrorPosition(err.Error())
		result := ValidationResult{
			Valid:       false,
			Error:       err.Error(),
			ErrorLine:   line,
			ErrorColumn: col,
		}
		return toJSON(result)
	}

	result := ValidationResult{Valid: true}
	return toJSON(result)
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
	goSQL := C.GoString(sql)

	opts := gosqlx.DefaultFormatOptions()
	formatted, err := gosqlx.Format(goSQL, opts)
	if err != nil {
		result := FormatResult{
			Success: false,
			Error:   err.Error(),
		}
		return toJSON(result)
	}

	result := FormatResult{
		Success:   true,
		Formatted: formatted,
	}
	return toJSON(result)
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
	goSQL := C.GoString(sql)

	tree, err := gosqlx.Parse(goSQL)
	if err != nil {
		return toJSON(map[string]interface{}{"error": err.Error()})
	}

	tables := gosqlx.ExtractTables(tree)
	if tables == nil {
		tables = []string{}
	}
	return toJSON(map[string]interface{}{"tables": tables})
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
	goSQL := C.GoString(sql)

	tree, err := gosqlx.Parse(goSQL)
	if err != nil {
		return toJSON(map[string]interface{}{"error": err.Error()})
	}

	columns := gosqlx.ExtractColumns(tree)
	if columns == nil {
		columns = []string{}
	}
	return toJSON(map[string]interface{}{"columns": columns})
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
	goSQL := C.GoString(sql)

	tree, err := gosqlx.Parse(goSQL)
	if err != nil {
		return toJSON(map[string]interface{}{"error": err.Error()})
	}

	functions := gosqlx.ExtractFunctions(tree)
	if functions == nil {
		functions = []string{}
	}
	return toJSON(map[string]interface{}{"functions": functions})
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
	goSQL := C.GoString(sql)

	tree, err := gosqlx.Parse(goSQL)
	if err != nil {
		return toJSON(map[string]interface{}{"error": err.Error()})
	}

	metadata := gosqlx.ExtractMetadata(tree)

	// Convert qualified tables
	tablesQualified := make([]QualifiedNameJSON, 0, len(metadata.TablesQualified))
	for _, tq := range metadata.TablesQualified {
		tablesQualified = append(tablesQualified, QualifiedNameJSON{
			Schema: tq.Schema,
			Table:  tq.Table,
			Name:   tq.Name,
		})
	}

	// Convert qualified columns
	columnsQualified := make([]QualifiedNameJSON, 0, len(metadata.ColumnsQualified))
	for _, cq := range metadata.ColumnsQualified {
		columnsQualified = append(columnsQualified, QualifiedNameJSON{
			Schema: cq.Schema,
			Table:  cq.Table,
			Name:   cq.Name,
		})
	}

	// Ensure non-nil slices for consistent JSON output
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

	result := MetadataResult{
		Tables:           tables,
		TablesQualified:  tablesQualified,
		Columns:          columns,
		ColumnsQualified: columnsQualified,
		Functions:        functions,
	}
	return toJSON(result)
}

// gosqlx_free releases memory allocated by the C binding functions.
// Every C string returned by gosqlx_parse, gosqlx_validate, gosqlx_format,
// gosqlx_extract_tables, gosqlx_extract_columns, gosqlx_extract_functions,
// gosqlx_extract_metadata, and gosqlx_version must be freed with this function
// to avoid memory leaks.
//
// Parameters:
//   - ptr: a C string pointer previously returned by a gosqlx_* function.
//
//export gosqlx_free
func gosqlx_free(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

// gosqlx_version returns the current GoSQLX library version as a C string.
// The version follows semantic versioning (e.g., "1.7.0").
//
// Returns a C string with the version. The caller must free the returned
// pointer with gosqlx_free.
//
//export gosqlx_version
func gosqlx_version() *C.char {
	cachedVersionOnce.Do(func() {
		cachedVersion = C.CString(VERSION)
	})
	return cachedVersion
}

func main() {}
