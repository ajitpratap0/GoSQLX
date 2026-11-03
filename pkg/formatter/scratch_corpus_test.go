// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

type scratchFormatCase struct {
	name, sql, dialect string
}

type scratchFormatResult struct {
	text, err string
}

func scratchFormatResultOf(text string, err error) scratchFormatResult {
	result := scratchFormatResult{text: text}
	if err != nil {
		result.err = err.Error()
	}
	return result
}

func scratchFormatCorpus(t *testing.T) []scratchFormatCase {
	t.Helper()
	var cases []scratchFormatCase
	for _, root := range []string{"realworld", "corpus"} {
		dir := filepath.Join("..", "..", "testdata", root)
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".sql" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			dialect := ""
			if root == "realworld" {
				dialect = strings.Split(filepath.ToSlash(rel), "/")[0]
			}
			name := root + "/" + filepath.ToSlash(rel)
			cases = append(cases, scratchFormatCase{name + "/whole", string(data), dialect})
			for i, stmt := range gosqlx.SplitStatements(string(data), dialect) {
				if strings.TrimSpace(stmt) != "" {
					cases = append(cases, scratchFormatCase{fmt.Sprintf("%s/statement_%d", name, i), stmt, dialect})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("load %s: %v", dir, err)
		}
	}
	if len(cases) == 0 {
		t.Fatal("empty SQL corpus")
	}
	return cases
}

func TestScratchFormatDifferentialCorpus(t *testing.T) {
	cases := scratchFormatCorpus(t)
	successes := 0
	for _, tc := range cases {
		variants := []formatter.Options{
			{Dialect: tc.dialect},
			{Dialect: tc.dialect, Compact: true, Uppercase: true, IndentSize: 4},
			{Dialect: "unknown-dialect", Uppercase: true},
		}
		for i, opts := range variants {
			want := scratchFormatResultOf(formatter.LegacyFormatForScratchTest(tc.sql, opts))
			got := scratchFormatResultOf(formatter.New(opts).Format(tc.sql))
			if got != want {
				t.Errorf("%s/options_%d: scratch and public tokenizer differ\ngot: %#v\nwant: %#v", tc.name, i, got, want)
			}
			if got.err == "" && got.text != "" {
				successes++
			}
		}
	}
	if successes == 0 {
		t.Fatal("no corpus statements formatted successfully")
	}
	t.Logf("compared %d corpus inputs with three formatting options; %d successful results", len(cases), successes)
}

func TestScratchFormatConcurrentCorpusAndRetainedResults(t *testing.T) {
	cases := scratchFormatCorpus(t)
	baseline := make([]scratchFormatResult, len(cases))
	// Clone the reference so retaining it cannot hide corruption through a shared backing store.
	for i, tc := range cases {
		result := scratchFormatResultOf(formatter.New(formatter.Options{Dialect: tc.dialect, Uppercase: true}).Format(tc.sql))
		baseline[i] = scratchFormatResult{strings.Clone(result.text), strings.Clone(result.err)}
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			retained := make([]scratchFormatResult, len(cases))
			for step := range cases {
				i := (step + worker) % len(cases)
				tc := cases[i]
				// Each goroutine owns its Formatter, as required by its API contract.
				got := scratchFormatResultOf(formatter.New(formatter.Options{Dialect: tc.dialect, Uppercase: true}).Format(tc.sql))
				if got != baseline[i] {
					t.Errorf("worker %d %s: result differs from sequential run", worker, tc.name)
				}
				retained[i] = got
			}
			// All strings remain live while further calls return and reuse pooled buffers.
			for i, got := range retained {
				if got != baseline[i] {
					t.Errorf("worker %d %s: retained output changed after pool reuse", worker, cases[i].name)
				}
			}
		}(worker)
	}
	wg.Wait()
}
