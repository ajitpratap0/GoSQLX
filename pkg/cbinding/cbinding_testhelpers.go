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
