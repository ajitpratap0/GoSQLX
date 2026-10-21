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

package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func strPtr(s string) *string { return &s }

func decodeMap(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("result is not a JSON object: %v\n%s", err, raw)
	}
	return m
}

// errorOf returns the error message of a decoded result, or "" when none.
func errorOf(m map[string]interface{}) string {
	s, _ := m["error"].(string)
	return s
}

// succeeded reports whether a decoded result of export e describes success.
func succeeded(e export, m map[string]interface{}) bool {
	switch e {
	case exportParse, exportFormat:
		ok, _ := m["success"].(bool)
		return ok
	case exportValidate:
		ok, _ := m["valid"].(bool)
		return ok
	default:
		return errorOf(m) == ""
	}
}

// TestDialectVariants_MatchLegacyWithoutDialect pins ABI stability: a NULL or
// empty dialect must produce byte-identical JSON to the original export.
func TestDialectVariants_MatchLegacyWithoutDialect(t *testing.T) {
	inputs := []*string{
		nil,
		strPtr(""),
		strPtr("   "),
		strPtr("SELECT id, UPPER(name) FROM public.users u WHERE u.id = 1"),
		strPtr("INSERT INTO t (a) VALUES (1); DELETE FROM t WHERE a = 2"),
		strPtr("SELECT * FROM"),
		strPtr("SELEC 1"),
	}
	for _, e := range allExports {
		for _, in := range inputs {
			name := "NULL"
			if in != nil {
				name = fmt.Sprintf("%q", *in)
			}
			t.Run(e.String()+"/"+name, func(t *testing.T) {
				legacy := callLegacyRaw(e, in)
				if got := callDialectRaw(e, in, nil); got != legacy {
					t.Errorf("NULL dialect differs from legacy export:\n got: %s\nwant: %s", got, legacy)
				}
				if got := callDialectRaw(e, in, strPtr("")); got != legacy {
					t.Errorf("empty dialect differs from legacy export:\n got: %s\nwant: %s", got, legacy)
				}
				if strings.Contains(legacy, "error_code") {
					t.Errorf("legacy export must not emit error_code: %s", legacy)
				}
			})
		}
	}
}

func TestDialectVariants_EveryDialectParsesPortableSQL(t *testing.T) {
	const sql = "SELECT id, COUNT(*) FROM orders WHERE total > 10 GROUP BY id"
	for _, d := range keywords.DialectNames() {
		for _, e := range allExports {
			t.Run(d+"/"+e.String(), func(t *testing.T) {
				m := decodeMap(t, callDialectRaw(e, strPtr(sql), strPtr(d)))
				if !succeeded(e, m) {
					t.Fatalf("dialect %s rejected portable SQL: %v", d, m)
				}
			})
		}
	}
}

func TestDialectVariants_DialectChangesParsing(t *testing.T) {
	// SQL Server TOP and bracketed identifiers need the sqlserver dialect.
	const sql = "SELECT TOP 5 [id] FROM [dbo].[users]"
	m := decodeMap(t, callDialectRaw(exportParse, strPtr(sql), strPtr("sqlserver")))
	if ok, _ := m["success"].(bool); !ok {
		t.Fatalf("sqlserver parse failed: %v", m)
	}
	if n, _ := m["statement_count"].(float64); n != 1 {
		t.Errorf("statement_count = %v, want 1", m["statement_count"])
	}

	tables := decodeMap(t, callDialectRaw(exportExtractTables, strPtr(sql), strPtr("sqlserver")))
	list, _ := tables["tables"].([]interface{})
	if len(list) != 1 || !strings.Contains(fmt.Sprint(list[0]), "users") {
		t.Errorf("sqlserver tables = %v, want [users]", tables["tables"])
	}

	v := decodeMap(t, callDialectRaw(exportValidate, strPtr(sql), strPtr("sqlserver")))
	if ok, _ := v["valid"].(bool); !ok {
		t.Errorf("sqlserver validate = %v, want valid", v)
	}

	f := decodeMap(t, callDialectRaw(exportFormat, strPtr(sql), strPtr("sqlserver")))
	if ok, _ := f["success"].(bool); !ok {
		t.Fatalf("sqlserver format failed: %v", f)
	}
	if out, _ := f["formatted"].(string); !strings.Contains(strings.ToUpper(out), "TOP") {
		t.Errorf("formatted output lost TOP: %q", out)
	}
}

// TestFormatDialect_GenericMatchesLegacy guards formatFor's copy of the
// gosqlx.Format option mapping: the generic dialect must render portable SQL
// exactly like gosqlx_format.
func TestFormatDialect_GenericMatchesLegacy(t *testing.T) {
	for _, sql := range []string{
		"select id, name from users where id = 1 order by name",
		"WITH c AS (SELECT a FROM t) SELECT a, COUNT(*) FROM c GROUP BY a HAVING COUNT(*) > 1",
		"insert into t (a, b) values (1, 'x'); update t set a = 2 where b = 'x'",
	} {
		legacy := callLegacyRaw(exportFormat, strPtr(sql))
		if got := callDialectRaw(exportFormat, strPtr(sql), strPtr("generic")); got != legacy {
			t.Errorf("generic format differs from gosqlx_format for %q:\n got: %s\nwant: %s", sql, got, legacy)
		}
	}
}

func TestDialectVariants_UnknownDialect(t *testing.T) {
	for _, e := range allExports {
		for _, d := range []string{"fakesql", "MySQL", " postgresql"} {
			t.Run(e.String()+"/"+d, func(t *testing.T) {
				m := decodeMap(t, callDialectRaw(e, strPtr("SELECT 1"), strPtr(d)))
				if succeeded(e, m) {
					t.Fatalf("unknown dialect %q accepted: %v", d, m)
				}
				if m["error_code"] != "E4002" {
					t.Errorf("error_code = %v, want E4002", m["error_code"])
				}
				msg := errorOf(m)
				if !strings.Contains(msg, fmt.Sprintf("%q", d)) || !strings.Contains(msg, "valid dialects: generic") {
					t.Errorf("error should name the dialect and list valid ones, got %q", msg)
				}
			})
		}
	}
}

func TestDialectVariants_EmptyAndInvalidInput(t *testing.T) {
	for _, e := range allExports {
		for _, in := range []*string{nil, strPtr(""), strPtr("SELECT * FROM")} {
			m := decodeMap(t, callDialectRaw(e, in, strPtr("postgresql")))
			if succeeded(e, m) {
				t.Errorf("%s accepted empty/invalid input %v: %v", e, in, m)
			}
			if errorOf(m) == "" {
				t.Errorf("%s: missing error message: %v", e, m)
			}
			if _, ok := m["error_code"]; ok {
				t.Errorf("%s: parse errors must not carry error_code: %v", e, m)
			}
		}
	}
}

func TestDialectVariants_ParseErrorPosition(t *testing.T) {
	m := decodeMap(t, callDialectRaw(exportParse, strPtr("SELECT *\nFROM users WHERE"), strPtr("mysql")))
	if ok, _ := m["success"].(bool); ok {
		t.Fatalf("expected failure: %v", m)
	}
	if line, _ := m["error_line"].(float64); line < 1 {
		t.Errorf("error_line = %v, want >= 1 (%s)", m["error_line"], errorOf(m))
	}
}

// ---------------------------------------------------------------------------
// gosqlx_lint
// ---------------------------------------------------------------------------

func decodeLint(t *testing.T, raw string) LintResult {
	t.Helper()
	var r LintResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("lint result is not valid JSON: %v\n%s", err, raw)
	}
	return r
}

func hasRule(r LintResult, id string) bool {
	for _, v := range r.Violations {
		if v.Rule == id {
			return true
		}
	}
	return false
}

func TestLint_DefaultRuleSet(t *testing.T) {
	r := decodeLint(t, lintRaw("select id from users  ", nil))
	if !r.Success {
		t.Fatalf("lint failed: %+v", r)
	}
	if r.ViolationCount != len(r.Violations) {
		t.Errorf("violation_count %d != len(violations) %d", r.ViolationCount, len(r.Violations))
	}
	for _, id := range []string{"L001", "L007"} {
		if !hasRule(r, id) {
			t.Errorf("expected %s violation, got %+v", id, r.Violations)
		}
	}
	for _, v := range r.Violations {
		if v.Line < 1 || v.Severity == "" || v.RuleName == "" || v.Message == "" {
			t.Errorf("incomplete violation: %+v", v)
		}
		// Only the CLI rule set (L001-L010) runs.
		if v.Rule > "L010" {
			t.Errorf("rule %s is outside the `gosqlx lint` rule set", v.Rule)
		}
	}
}

func TestLint_CleanSQLAndEmptyOptions(t *testing.T) {
	for _, opts := range []*string{nil, strPtr(""), strPtr("  "), strPtr("{}"), strPtr(`{"dialect": ""}`)} {
		r := decodeLint(t, lintRaw("SELECT id FROM users", opts))
		if !r.Success || r.ViolationCount != 0 || r.Violations == nil {
			t.Errorf("options %v: want success with empty violations array, got %+v", opts, r)
		}
	}
}

func TestLint_EmptyInput(t *testing.T) {
	raw := lintRaw("", nil)
	r := decodeLint(t, raw)
	if !r.Success || r.ViolationCount != 0 {
		t.Errorf("empty input: want success with no violations, got %+v", r)
	}
	if !strings.Contains(raw, `"violations":[]`) {
		t.Errorf("violations must encode as [], got %s", raw)
	}
}

func TestLint_InvalidSQLStillLinted(t *testing.T) {
	r := decodeLint(t, lintRaw("select * from  ", nil))
	if !r.Success {
		t.Fatalf("unparseable SQL must still lint: %+v", r)
	}
	if !hasRule(r, "L001") {
		t.Errorf("text rules should still run, got %+v", r.Violations)
	}
}

func TestLint_MaxLineLength(t *testing.T) {
	sql := "SELECT " + strings.Repeat("a", 60) + " FROM t"
	if r := decodeLint(t, lintRaw(sql, nil)); hasRule(r, "L005") {
		t.Errorf("default limit 100 should not flag a %d-char line: %+v", len(sql), r.Violations)
	}
	r := decodeLint(t, lintRaw(sql, strPtr(`{"max_line_length": 40}`)))
	if !r.Success || !hasRule(r, "L005") {
		t.Errorf("max_line_length 40 should flag L005: %+v", r)
	}
}

func TestLint_Dialect(t *testing.T) {
	r := decodeLint(t, lintRaw("SELECT TOP 5 [id] FROM [users]", strPtr(`{"dialect":"sqlserver"}`)))
	if !r.Success {
		t.Fatalf("sqlserver lint failed: %+v", r)
	}
}

func TestLint_ErrorPaths(t *testing.T) {
	cases := []struct {
		name, opts, code, contains string
	}{
		{"malformed", `{"dialect":`, "INVALID_OPTIONS", "invalid options_json"},
		{"not an object", `[1]`, "INVALID_OPTIONS", "invalid options_json"},
		{"unknown field", `{"max_length": 10}`, "INVALID_OPTIONS", "max_length"},
		{"wrong type", `{"max_line_length": "10"}`, "INVALID_OPTIONS", "invalid options_json"},
		{"zero length", `{"max_line_length": 0}`, "INVALID_OPTIONS", "must be positive"},
		{"negative length", `{"max_line_length": -5}`, "INVALID_OPTIONS", "must be positive"},
		{"trailing data", `{} {}`, "INVALID_OPTIONS", "trailing data"},
		{"unknown dialect", `{"dialect":"fakesql"}`, "E4002", "valid dialects"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := lintRaw("SELECT 1", strPtr(tc.opts))
			r := decodeLint(t, raw)
			if r.Success {
				t.Fatalf("expected failure, got %s", raw)
			}
			if r.ErrorCode != tc.code {
				t.Errorf("error_code = %q, want %q", r.ErrorCode, tc.code)
			}
			if !strings.Contains(r.Error, tc.contains) {
				t.Errorf("error %q does not contain %q", r.Error, tc.contains)
			}
			if r.Violations == nil {
				t.Errorf("violations must be [] on error, got null")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// gosqlx_security_scan
// ---------------------------------------------------------------------------

func decodeScan(t *testing.T, raw string) SecurityScanResult {
	t.Helper()
	var r SecurityScanResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("scan result is not valid JSON: %v\n%s", err, raw)
	}
	return r
}

func TestSecurityScan_DetectsInjection(t *testing.T) {
	r := decodeScan(t, securityScanRaw(strPtr("SELECT * FROM users WHERE id = 1 OR 1=1 --")))
	if !r.Success || r.IsClean || r.TotalCount == 0 || len(r.Findings) != r.TotalCount {
		t.Fatalf("expected findings, got %+v", r)
	}
	if r.CriticalCount+r.HighCount+r.MediumCount+r.LowCount != r.TotalCount {
		t.Errorf("severity counts do not add up: %+v", r)
	}
	for _, f := range r.Findings {
		if f.Severity == "" || f.Pattern == "" || f.Description == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
	}
	if !r.HasHigh {
		t.Errorf("tautology with comment should be at least HIGH: %+v", r)
	}
}

func TestSecurityScan_CleanAndEmpty(t *testing.T) {
	for _, in := range []*string{nil, strPtr(""), strPtr("SELECT id FROM users WHERE id = $1")} {
		raw := securityScanRaw(in)
		r := decodeScan(t, raw)
		if !r.Success || !r.IsClean || r.TotalCount != 0 || r.HasCritical || r.HasHigh {
			t.Errorf("input %v: want clean result, got %s", in, raw)
		}
		if !strings.Contains(raw, `"findings":[]`) {
			t.Errorf("findings must encode as [], got %s", raw)
		}
	}
}

func TestSecurityScan_UnparseablePayload(t *testing.T) {
	// The scan is text based, so payloads that do not parse are still scanned.
	r := decodeScan(t, securityScanRaw(strPtr("'; DROP TABLE users; --")))
	if r.IsClean {
		t.Errorf("stacked-query payload should not be clean: %+v", r)
	}
}

// ---------------------------------------------------------------------------
// gosqlx_transpile
// ---------------------------------------------------------------------------

func decodeTranspile(t *testing.T, raw string) TranspileResult {
	t.Helper()
	var r TranspileResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("transpile result is not valid JSON: %v\n%s", err, raw)
	}
	return r
}

func TestTranspile_MySQLToPostgres(t *testing.T) {
	r := decodeTranspile(t, transpileRaw(
		strPtr("CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)"),
		strPtr("mysql"), strPtr("postgresql")))
	if !r.Success {
		t.Fatalf("transpile failed: %+v", r)
	}
	if !strings.Contains(strings.ToUpper(r.SQL), "SERIAL") || strings.Contains(strings.ToUpper(r.SQL), "AUTO_INCREMENT") {
		t.Errorf("expected AUTO_INCREMENT -> SERIAL, got %q", r.SQL)
	}
}

func TestTranspile_PassthroughPair(t *testing.T) {
	r := decodeTranspile(t, transpileRaw(strPtr("SELECT a FROM t"), strPtr("generic"), strPtr("snowflake")))
	if !r.Success || !strings.Contains(strings.ToUpper(r.SQL), "SELECT") {
		t.Errorf("passthrough transpile failed: %+v", r)
	}
}

func TestTranspile_ErrorPaths(t *testing.T) {
	cases := []struct {
		name          string
		sql, from, to *string
		code          string
	}{
		{"null from", strPtr("SELECT 1"), nil, strPtr("mysql"), "E4002"},
		{"empty to", strPtr("SELECT 1"), strPtr("mysql"), strPtr(""), "E4002"},
		{"unknown from", strPtr("SELECT 1"), strPtr("fakesql"), strPtr("mysql"), "E4002"},
		{"unknown to", strPtr("SELECT 1"), strPtr("mysql"), strPtr("postgres"), "E4002"},
		{"invalid sql", strPtr("SELECT * FROM"), strPtr("mysql"), strPtr("postgresql"), ""},
		{"empty sql", strPtr(""), strPtr("mysql"), strPtr("postgresql"), ""},
		{"null sql", nil, strPtr("mysql"), strPtr("postgresql"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := transpileRaw(tc.sql, tc.from, tc.to)
			r := decodeTranspile(t, raw)
			if r.Success || r.Error == "" || r.SQL != "" {
				t.Fatalf("expected error without sql, got %s", raw)
			}
			if r.ErrorCode != tc.code {
				t.Errorf("error_code = %q, want %q", r.ErrorCode, tc.code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// gosqlx_dialects
// ---------------------------------------------------------------------------

func TestDialects(t *testing.T) {
	var r DialectsResult
	raw := dialectsRaw()
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	if !reflect.DeepEqual(r.Dialects, keywords.DialectNames()) {
		t.Errorf("dialects = %v, want %v", r.Dialects, keywords.DialectNames())
	}
	for _, d := range r.Dialects {
		if !keywords.IsValidDialect(d) {
			t.Errorf("listed dialect %q is not accepted", d)
		}
	}
	// Each call returns a fresh caller-owned allocation; both are freed.
	if dialectsRaw() != raw {
		t.Errorf("gosqlx_dialects is not stable across calls")
	}
}

// TestNewExports_Concurrent exercises every new export from many goroutines;
// run under -race (task test:cbinding) it checks the shared linter, scanner
// and parser paths are race free and every result is freed exactly once.
func TestNewExports_Concurrent(t *testing.T) {
	const workers = 16
	const iterations = 25
	dialects := keywords.DialectNames()
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			d := dialects[w%len(dialects)]
			for i := 0; i < iterations; i++ {
				for _, e := range allExports {
					if raw := callDialectRaw(e, strPtr("SELECT a FROM t WHERE b = 1"), strPtr(d)); !json.Valid([]byte(raw)) {
						errs <- fmt.Sprintf("%s/%s: invalid JSON %s", e, d, raw)
						return
					}
				}
				if raw := lintRaw("select a from t", strPtr(`{"dialect":"`+d+`"}`)); !json.Valid([]byte(raw)) {
					errs <- "lint: invalid JSON " + raw
					return
				}
				_ = securityScanRaw(strPtr("SELECT * FROM t WHERE 1=1 OR 'a'='a'"))
				_ = transpileRaw(strPtr("SELECT a FROM t"), strPtr("mysql"), strPtr(d))
				_ = dialectsRaw()
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
