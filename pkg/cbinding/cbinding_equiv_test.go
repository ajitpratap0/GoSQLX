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
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type equivalenceInput struct{ name, sql, dialect string }

func edgeEquivalenceInputs() []equivalenceInput {
	return []equivalenceInput{
		{"empty", "", ""}, {"semicolon", ";", ""},
		{"zero-statements", "GO", "sqlserver"}, {"batch", "SELECT 1\nGO\n", "sqlserver"},
		{"comment", "-- only a comment", ""}, {"escaping", "SELECT '<&>\u2028\u2029'", ""},
		{"invalid-utf8", "SELECT '\xff'", ""}, {"syntax-error", "SELECT 1 FROM", ""},
		{"unknown-dialect", "SELECT 1", "nope"},
		{"large", "SELECT '" + strings.Repeat("<&>", 70<<10) + "'", ""},
	}
}

func corpusEquivalenceInputs(t *testing.T) []equivalenceInput {
	t.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	statements := append(set.All(), set.Excluded()...)
	inputs := make([]equivalenceInput, 0, len(statements))
	for _, s := range statements {
		dialect := s.Dialect
		if dialect == benchcorpus.GenericDialect {
			dialect = ""
		}
		inputs = append(inputs, equivalenceInput{s.Key(), s.SQL, dialect})
	}
	return inputs
}

// refExtractListFor preserves the old map result and its sorted JSON keys.
func refExtractListFor(sql, dialect, key string, extract func(*ast.AST) []string) map[string]interface{} {
	tree, err := parseFor(sql, dialect)
	if err != nil {
		out := map[string]interface{}{"error": err.Error()}
		if code := errorCodeFor(err); code != "" {
			out["error_code"] = code
		}
		return out
	}
	// The old result builder did not release tree. Keeping this reference exact
	// also makes allocation comparisons account for the original ownership path.
	items := extract(tree)
	if items == nil {
		items = []string{}
	}
	return map[string]interface{}{key: items}
}

func referenceExport(e export, sql, dialect string) any {
	switch e {
	case exportParse:
		return parseResultFor(sql, dialect)
	case exportValidate:
		return validationResultFor(sql, dialect)
	case exportFormat:
		return formatResultFor(sql, dialect)
	case exportExtractTables:
		return refExtractListFor(sql, dialect, "tables", gosqlx.ExtractTables)
	case exportExtractColumns:
		return refExtractListFor(sql, dialect, "columns", gosqlx.ExtractColumns)
	case exportExtractFunctions:
		return refExtractListFor(sql, dialect, "functions", gosqlx.ExtractFunctions)
	default:
		return metadataFor(sql, dialect)
	}
}

func marshalReference(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jsonDifference(got, want string) string {
	if got == want {
		return ""
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	endGot, endWant := min(i+100, len(got)), min(i+100, len(want))
	return fmt.Sprintf("first difference at byte %d (lengths %d/%d): got %q, want %q", i, len(got), len(want), got[i:endGot], want[i:endWant])
}

func assertJSONEqual(t *testing.T, label, got, want string) {
	t.Helper()
	if difference := jsonDifference(got, want); difference != "" {
		t.Fatalf("%s: %s", label, difference)
	}
}

func TestCBindingJSONEquivalence(t *testing.T) {
	inputs := append(corpusEquivalenceInputs(t), edgeEquivalenceInputs()...)
	// Inputs are independent, so run them in parallel chunks; the parent
	// subtest group waits for all of them.
	const chunks = 16
	t.Run("inputs", func(t *testing.T) {
		for c := 0; c < chunks; c++ {
			t.Run(fmt.Sprintf("chunk%d", c), func(t *testing.T) {
				t.Parallel()
				for i := c; i < len(inputs); i += chunks {
					in := inputs[i]
					for _, e := range allExports {
						want := marshalReference(t, referenceExport(e, in.sql, ""))
						label := in.name + "/" + e.String()
						assertJSONEqual(t, label+"/legacy", callLegacyRaw(e, &in.sql), want)
						empty := ""
						assertJSONEqual(t, label+"/empty-dialect", callDialectRaw(e, &in.sql, &empty), want)
						want = marshalReference(t, referenceExport(e, in.sql, in.dialect))
						assertJSONEqual(t, label+"/own-dialect", callDialectRaw(e, &in.sql, &in.dialect), want)
					}
					// Analysis exports share toJSON and must preserve bytes over the same corpus.
					assertJSONEqual(t, in.name+"/security", securityScanRaw(&in.sql), marshalReference(t, securityScanFor(in.sql)))
					from, to := "postgresql", "mysql"
					assertJSONEqual(t, in.name+"/transpile", transpileRaw(&in.sql, &from, &to), marshalReference(t, transpileFor(in.sql, from, to)))
					assertJSONEqual(t, in.name+"/lint", lintRaw(in.sql, nil), marshalReference(t, freshLintReference(in.sql, 100, "")))
				}
			})
		}
	})
	assertJSONEqual(t, "dialects", dialectsRaw(), marshalReference(t, DialectsResult{Dialects: keywords.DialectNames()}))
	// Unsupported values must retain the original fallback bytes as well.
	for _, v := range []any{make(chan int), complex(1, 2)} {
		assertJSONEqual(t, "fallback", toJSONString(v), legacyJSONStringForTest(v))
	}
}

func TestCBindingScratchReuse(t *testing.T) {
	initial := getScratch()
	if initial.stmtTypes == nil {
		t.Fatal("new scratch must have a non-nil statement slice")
	}
	putScratch(initial)
	inputs := []equivalenceInput{{"first-error", "SELECT 1 FROM", ""}, {"success", "SELECT 1; SELECT 2", ""}, {"zero", "GO", "sqlserver"}, {"other-error", "SELECT @", ""}, {"success-again", "SELECT 3", ""}}
	for repeat := 0; repeat < 10; repeat++ {
		for _, in := range inputs {
			for _, e := range []export{exportParse, exportValidate, exportFormat} {
				assertJSONEqual(t, in.name+"/"+e.String(), callDialectRaw(e, &in.sql, &in.dialect), marshalReference(t, referenceExport(e, in.sql, in.dialect)))
			}
		}
	}
	// Pool hygiene protects SQL-bearing errors even when the next assignment
	// overwrites the whole struct and would conceal missing zeroing externally.
	sc := getScratch()
	sc.parse = ParseResult{Error: "private SQL", ErrorLine: 7}
	sc.valid = ValidationResult{Error: "private SQL", ErrorColumn: 9}
	sc.format = FormatResult{Error: "private SQL", Formatted: "SELECT private"}
	sc.stmtTypes = append(sc.stmtTypes, "SELECT")
	putScratch(sc)
	if sc.parse.Error != "" || sc.parse.ErrorLine != 0 || sc.valid.Error != "" || sc.valid.ErrorColumn != 0 || sc.format.Error != "" || sc.format.Formatted != "" {
		t.Fatal("putScratch retained result state")
	}
	if sc.stmtTypes == nil || len(sc.stmtTypes) != 0 {
		t.Fatal("putScratch must retain a non-nil empty statement slice")
	}
}

func freshLintReference(sql string, maxLen int, dialect string) LintResult {
	return lintResultFrom(newLinter(maxLen, dialect).LintString(sql, "<input>"))
}

func resetLintCacheForTest() {
	lintCache.Range(func(key, value any) bool { lintCache.Delete(key); return true })
	lintCacheLen.Store(0)
}

func TestCBindingCachedLinterEquivalence(t *testing.T) {
	resetLintCacheForTest()
	defer resetLintCacheForTest()
	corpus := corpusEquivalenceInputs(t)
	inputs := append([]equivalenceInput(nil), edgeEquivalenceInputs()...)
	// A deterministic spread includes dialect-specific statements throughout the corpus.
	count := min(200, len(corpus))
	for i := 0; i < count; i++ {
		inputs = append(inputs, corpus[i*len(corpus)/count])
	}
	t.Run("matrix", func(t *testing.T) {
		for _, dialect := range append(keywords.DialectNames(), "") {
			for _, maxLen := range []int{1, 40, 80, 100, 120} {
				t.Run(fmt.Sprintf("%s/%d", dialect, maxLen), func(t *testing.T) {
					t.Parallel()
					opts := fmt.Sprintf(`{"dialect":%q,"max_line_length":%d}`, dialect, maxLen)
					for _, in := range inputs {
						assertJSONEqual(t, fmt.Sprintf("%s/%s/%d", in.name, dialect, maxLen), lintRaw(in.sql, &opts), marshalReference(t, freshLintReference(in.sql, maxLen, dialect)))
					}
				})
			}
		}
	})
}

func TestCBindingLintCacheBound(t *testing.T) {
	resetLintCacheForTest()
	defer resetLintCacheForTest()
	sql := "SELECT some_column, another_column FROM example_table"
	for limit := 1; limit <= 200; limit++ {
		opts := fmt.Sprintf(`{"max_line_length":%d}`, limit)
		assertJSONEqual(t, fmt.Sprintf("limit %d", limit), marshalReference(t, lintFor(sql, opts)), marshalReference(t, freshLintReference(sql, limit, "")))
	}
	entries := 0
	lintCache.Range(func(key, value any) bool { entries++; return true })
	if entries > maxCachedLinters {
		t.Fatalf("cache has %d entries, cap %d", entries, maxCachedLinters)
	}
	if got := lintCacheLen.Load(); got != int32(entries) {
		t.Fatalf("cache counter %d, entries %d", got, entries)
	}
}

func TestCBindingConcurrentEquivalence(t *testing.T) {
	resetLintCacheForTest()
	defer resetLintCacheForTest()
	type callCase struct {
		call func() string
		want string
	}
	var cases []callCase
	for _, in := range []equivalenceInput{{"success", benchQueries[1].sql, "postgresql"}, {"error", "SELECT 1 FROM", ""}, {"zero", "GO", "sqlserver"}, {"escaping", "SELECT '<&>\u2028'", ""}} {
		for _, e := range []export{exportParse, exportExtractMetadata, exportFormat} {
			cases = append(cases, callCase{func() string { return callDialectRaw(e, &in.sql, &in.dialect) }, marshalReference(t, referenceExport(e, in.sql, in.dialect))})
		}
		for _, limit := range []int{1, 80, 120} {
			opts := fmt.Sprintf(`{"max_line_length":%d}`, limit)
			cases = append(cases, callCase{func() string { return lintRaw(in.sql, &opts) }, marshalReference(t, freshLintReference(in.sql, limit, ""))})
		}
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				index := (worker + i) % len(cases)
				c := cases[index]
				if difference := jsonDifference(c.call(), c.want); difference != "" {
					t.Errorf("worker %d iteration %d case %d: %s", worker, i, index, difference)
					return
				}
			}
		}()
	}
	wg.Wait()
	entries := 0
	lintCache.Range(func(key, value any) bool { entries++; return true })
	if entries > maxCachedLinters || lintCacheLen.Load() != int32(entries) {
		t.Fatalf("concurrent cache entries=%d counter=%d", entries, lintCacheLen.Load())
	}
}

func TestCBindingKeepScratch(t *testing.T) {
	for _, tc := range []struct {
		buf, stmt int
		keep      bool
	}{{0, 0, true}, {64 << 10, 1024, true}, {(64 << 10) + 1, 1024, false}, {64 << 10, 1025, false}, {(64 << 10) - 1, 1023, true}} {
		if got := keepScratch(tc.buf, tc.stmt); got != tc.keep {
			t.Errorf("keepScratch(%d,%d)=%v, want %v", tc.buf, tc.stmt, got, tc.keep)
		}
	}
}
