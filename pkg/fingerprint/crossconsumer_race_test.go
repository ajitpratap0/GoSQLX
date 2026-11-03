// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/transform"
)

// TestCrossConsumerSharedTokenizerPool runs every consumer of the shared
// tokenizer pool and its pooled token scratch (gosqlx.Parse, formatter.Format,
// fingerprint.Normalize, transform.ParseSQL) in parallel and checks that each
// result matches its single-goroutine baseline. Under -race this catches a
// consumer that reads scratch memory after the tokenizer went back to the pool.
func TestCrossConsumerSharedTokenizerPool(t *testing.T) {
	queries := []string{
		"SELECT id, name FROM users WHERE id = 42 AND status IN ('a','b')",
		"SELECT u.id, o.total FROM users u JOIN orders o ON o.user_id = u.id WHERE o.total > 100 ORDER BY o.total DESC LIMIT 10",
		"WITH t AS (SELECT a, SUM(b) AS s FROM x GROUP BY a) SELECT a, s FROM t WHERE s > 5 -- trailing comment",
		"INSERT INTO t (a, b) VALUES (1, 'x'), (2, 'y')",
		"UPDATE t SET a = 1, b = 'z' WHERE id = 7",
	}
	f := formatter.New(formatter.Options{})

	type base struct{ norm, formatted string }
	want := make([]base, len(queries))
	for i, q := range queries {
		n, err := fingerprint.Normalize(q)
		if err != nil {
			t.Fatalf("baseline Normalize(%q): %v", q, err)
		}
		s, err := f.Format(q)
		if err != nil {
			t.Fatalf("baseline Format(%q): %v", q, err)
		}
		want[i] = base{n, s}
	}

	const goroutines, iters = 16, 60
	var wg sync.WaitGroup
	errs := make(chan string, goroutines*iters)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				idx := (g + i) % len(queries)
				q := queries[idx]
				switch (g + i) % 4 {
				case 0:
					if _, err := gosqlx.Parse(q); err != nil {
						errs <- "gosqlx.Parse: " + err.Error()
					}
				case 1:
					if got, err := f.Format(q); err != nil || got != want[idx].formatted {
						errs <- "formatter.Format mismatch for " + q
					}
				case 2:
					if got, err := fingerprint.Normalize(q); err != nil || got != want[idx].norm {
						errs <- "fingerprint.Normalize mismatch for " + q
					}
				default:
					if _, err := transform.ParseSQL(q); err != nil {
						errs <- "transform.ParseSQL: " + err.Error()
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
