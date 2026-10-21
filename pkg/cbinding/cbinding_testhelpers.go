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

// This file provides pure-Go wrappers around the CGo-exported functions so
// that test files (which cannot use CGo directly in package main) can exercise
// the real exported functions through a thin Go-level adapter.
//
// These wrappers are compiled into every build (including the c-shared build)
// and are intentionally unexported to avoid polluting the C symbol table.

package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"unsafe"
)

// parseSQL calls the real gosqlx_parse C export and returns the decoded result.
func parseSQL(sql string) ParseResult {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_parse(cSQL)
	defer gosqlx_free(cResult)
	var result ParseResult
	_ = json.Unmarshal([]byte(C.GoString(cResult)), &result)
	return result
}

// validateSQL calls the real gosqlx_validate C export and returns the decoded result.
func validateSQL(sql string) ValidationResult {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_validate(cSQL)
	defer gosqlx_free(cResult)
	var result ValidationResult
	_ = json.Unmarshal([]byte(C.GoString(cResult)), &result)
	return result
}

// formatSQL calls the real gosqlx_format C export and returns the decoded result.
func formatSQL(sql string) FormatResult {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_format(cSQL)
	defer gosqlx_free(cResult)
	var result FormatResult
	_ = json.Unmarshal([]byte(C.GoString(cResult)), &result)
	return result
}

// extractTables calls the real gosqlx_extract_tables C export and returns the decoded map.
func extractTables(sql string) map[string]interface{} {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_extract_tables(cSQL)
	defer gosqlx_free(cResult)
	var result map[string]interface{}
	_ = json.Unmarshal([]byte(C.GoString(cResult)), &result)
	return result
}

// extractColumns calls the real gosqlx_extract_columns C export and returns the decoded map.
func extractColumns(sql string) map[string]interface{} {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_extract_columns(cSQL)
	defer gosqlx_free(cResult)
	var result map[string]interface{}
	_ = json.Unmarshal([]byte(C.GoString(cResult)), &result)
	return result
}

// extractFunctions calls the real gosqlx_extract_functions C export and returns the decoded map.
func extractFunctions(sql string) map[string]interface{} {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_extract_functions(cSQL)
	defer gosqlx_free(cResult)
	var result map[string]interface{}
	_ = json.Unmarshal([]byte(C.GoString(cResult)), &result)
	return result
}

// extractMetadata calls the real gosqlx_extract_metadata C export and returns the decoded result.
func extractMetadata(sql string) MetadataResult {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_extract_metadata(cSQL)
	defer gosqlx_free(cResult)
	var result MetadataResult
	_ = json.Unmarshal([]byte(C.GoString(cResult)), &result)
	return result
}

// extractMetadataRaw calls gosqlx_extract_metadata and returns the raw JSON string.
func extractMetadataRaw(sql string) string {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cResult := gosqlx_extract_metadata(cSQL)
	defer gosqlx_free(cResult)
	return C.GoString(cResult)
}

// getVersion calls the real gosqlx_version C export and returns the version string,
// freeing the returned C string as the documented ownership contract requires.
func getVersion() string {
	cResult := gosqlx_version()
	defer gosqlx_free(cResult)
	return C.GoString(cResult)
}

// versionTwiceFreed calls gosqlx_version twice, checks that each call returned a
// distinct caller-owned allocation, and frees both results with gosqlx_free. It
// returns both decoded strings and whether the two pointers were distinct. A
// regression to a cached pointer makes the second gosqlx_free a double free.
func versionTwiceFreed() (string, string, bool) {
	p1 := gosqlx_version()
	p2 := gosqlx_version()
	distinct := p1 != p2
	v1 := C.GoString(p1)
	v2 := C.GoString(p2)
	gosqlx_free(p1)
	if distinct {
		gosqlx_free(p2)
	}
	return v1, v2, distinct
}

// freeNil calls gosqlx_free with a NULL pointer, which must be a no-op.
func freeNil() {
	gosqlx_free(nil)
}

// toJSONString calls the real toJSON helper and returns the JSON as a Go string,
// freeing the intermediate C string.
func toJSONString(v interface{}) string {
	cStr := toJSON(v)
	defer gosqlx_free(cStr)
	return C.GoString(cStr)
}

// export identifies one of the original single-argument exports that has a
// *_dialect variant, so tests can call either form through one helper.
type export int

const (
	exportParse export = iota
	exportValidate
	exportFormat
	exportExtractTables
	exportExtractColumns
	exportExtractFunctions
	exportExtractMetadata
)

// allExports lists every export that has a *_dialect variant.
var allExports = []export{
	exportParse, exportValidate, exportFormat,
	exportExtractTables, exportExtractColumns, exportExtractFunctions, exportExtractMetadata,
}

func (e export) String() string {
	return [...]string{"parse", "validate", "format", "extract_tables",
		"extract_columns", "extract_functions", "extract_metadata"}[e]
}

// cString converts s to a C string the caller frees with C.free; a nil s
// yields NULL.
func cString(s *string) *C.char {
	if s == nil {
		return nil
	}
	return C.CString(*s)
}

func freeCString(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

// takeResult decodes a returned C string and frees it with gosqlx_free, as
// the ownership contract requires of every result.
func takeResult(p *C.char) string {
	defer gosqlx_free(p)
	return C.GoString(p)
}

// callLegacyRaw calls the original export e and returns its raw JSON. A nil sql
// passes NULL.
func callLegacyRaw(e export, sql *string) string {
	cSQL := cString(sql)
	defer freeCString(cSQL)
	switch e {
	case exportParse:
		return takeResult(gosqlx_parse(cSQL))
	case exportValidate:
		return takeResult(gosqlx_validate(cSQL))
	case exportFormat:
		return takeResult(gosqlx_format(cSQL))
	case exportExtractTables:
		return takeResult(gosqlx_extract_tables(cSQL))
	case exportExtractColumns:
		return takeResult(gosqlx_extract_columns(cSQL))
	case exportExtractFunctions:
		return takeResult(gosqlx_extract_functions(cSQL))
	default:
		return takeResult(gosqlx_extract_metadata(cSQL))
	}
}

// callDialectRaw calls the *_dialect variant of e and returns its raw JSON. A
// nil sql or dialect passes NULL.
func callDialectRaw(e export, sql, dialect *string) string {
	cSQL := cString(sql)
	defer freeCString(cSQL)
	cDialect := cString(dialect)
	defer freeCString(cDialect)
	switch e {
	case exportParse:
		return takeResult(gosqlx_parse_dialect(cSQL, cDialect))
	case exportValidate:
		return takeResult(gosqlx_validate_dialect(cSQL, cDialect))
	case exportFormat:
		return takeResult(gosqlx_format_dialect(cSQL, cDialect))
	case exportExtractTables:
		return takeResult(gosqlx_extract_tables_dialect(cSQL, cDialect))
	case exportExtractColumns:
		return takeResult(gosqlx_extract_columns_dialect(cSQL, cDialect))
	case exportExtractFunctions:
		return takeResult(gosqlx_extract_functions_dialect(cSQL, cDialect))
	default:
		return takeResult(gosqlx_extract_metadata_dialect(cSQL, cDialect))
	}
}

// lintRaw calls gosqlx_lint and returns its raw JSON. A nil options passes NULL.
func lintRaw(sql string, options *string) string {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))
	cOpts := cString(options)
	defer freeCString(cOpts)
	return takeResult(gosqlx_lint(cSQL, cOpts))
}

// securityScanRaw calls gosqlx_security_scan and returns its raw JSON. A nil
// sql passes NULL.
func securityScanRaw(sql *string) string {
	cSQL := cString(sql)
	defer freeCString(cSQL)
	return takeResult(gosqlx_security_scan(cSQL))
}

// transpileRaw calls gosqlx_transpile and returns its raw JSON. A nil argument
// passes NULL.
func transpileRaw(sql, from, to *string) string {
	cSQL := cString(sql)
	defer freeCString(cSQL)
	cFrom := cString(from)
	defer freeCString(cFrom)
	cTo := cString(to)
	defer freeCString(cTo)
	return takeResult(gosqlx_transpile(cSQL, cFrom, cTo))
}

// dialectsRaw calls gosqlx_dialects and returns its raw JSON.
func dialectsRaw() string {
	return takeResult(gosqlx_dialects())
}
