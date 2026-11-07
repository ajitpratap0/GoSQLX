// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

type scratchResult struct{ normalized, fingerprint, err string }

func scratchRun(sql string, mode fingerprint.Mode) scratchResult {
	n, e := fingerprint.NormalizeWithOptions(sql, fingerprint.Options{Mode: mode})
	f, fe := fingerprint.FingerprintWithOptions(sql, fingerprint.Options{Mode: mode})
	if fmt.Sprint(e) != fmt.Sprint(fe) {
		return scratchResult{n, f, "inconsistent errors"}
	}
	return scratchResult{n, f, fmt.Sprint(e)}
}
func scratchCorpus(t *testing.T) []string {
	t.Helper()
	var queries []string
	for _, root := range []string{"../../testdata/realworld", "../../testdata/corpus"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(path) != ".sql" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			queries = append(queries, string(data))
			queries = append(queries, gosqlx.SplitStatements(string(data), "")...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(queries) == 0 {
		t.Fatal("empty corpus")
	}
	return queries
}
func TestScratchDifferential(t *testing.T) {
	for i, sql := range scratchCorpus(t) {
		want, err := fingerprint.LegacyNormalizeForScratchTest(sql)
		got := scratchRun(sql, fingerprint.ModeLegacy)
		hash := ""
		if err == nil {
			hash = fmt.Sprintf("%x", sha256.Sum256([]byte(want)))
		}
		if got != (scratchResult{want, hash, fmt.Sprint(err)}) {
			t.Fatalf("query %d mismatch: got %#v, want %q, %q, %v", i, got, want, hash, err)
		}
	}
}
func TestScratchConcurrentAndRetainedResults(t *testing.T) {
	for _, mode := range []fingerprint.Mode{fingerprint.ModeTokens, fingerprint.ModeLegacy} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			queries := scratchCorpus(t)
			want := make([]scratchResult, len(queries))
			for i, q := range queries {
				result := scratchRun(q, mode)
				want[i] = scratchResult{strings.Clone(result.normalized), strings.Clone(result.fingerprint), strings.Clone(result.err)}
			}
			var wg sync.WaitGroup
			for worker := 0; worker < 8; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					retained := make([]scratchResult, len(queries))
					for i, q := range queries {
						retained[i] = scratchRun(q, mode)
						if retained[i] != want[i] {
							t.Errorf("concurrent query %d mismatch", i)
							return
						}
					}
					// Further calls recycle pooled token/Word storage while earlier strings stay live.
					for _, q := range queries {
						scratchRun(q, mode)
					}
					for i, got := range retained {
						if got != want[i] {
							t.Errorf("retained query %d changed", i)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}
