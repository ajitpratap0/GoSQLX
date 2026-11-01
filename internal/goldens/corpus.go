// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package goldens

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Corpus returns every benchmark corpus statement after checking that the
// corpus still matches testdata/bench/MANIFEST.sha256, so a golden mismatch
// is never caused by an unnoticed corpus edit. A statement's golden row is
// its File.
func Corpus(t testing.TB) []benchcorpus.Statement {
	t.Helper()
	root, err := benchcorpus.FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := benchcorpus.Verify(root); err != nil {
		t.Fatalf("goldens: corpus drifted, fix the manifest first: %v", err)
	}
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	return set.All()
}

// Dialects returns every dialect the library accepts (keywords.AllDialects),
// the column set of the tokenizer and parser goldens. It includes bigquery
// and redshift, which have no corpus of their own.
func Dialects() []string { return benchcorpus.Dialects() }

// TranspileDialects is the transpiler's 9x9 rule matrix
// (pkg/transpiler/dialect_rules.go), the column set of the transpile golden.
func TranspileDialects() []keywords.SQLDialect {
	return []keywords.SQLDialect{
		keywords.DialectGeneric, keywords.DialectMySQL, keywords.DialectPostgreSQL,
		keywords.DialectSQLite, keywords.DialectSQLServer, keywords.DialectOracle,
		keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectMariaDB,
	}
}

// Parallel runs fn(0..n-1) on GOMAXPROCS workers and returns when all are
// done. Outputs must be keyed by index, so results stay deterministic; running
// the library concurrently also exercises its pools under -race.
func Parallel(n int, fn func(i int)) {
	workers := min(runtime.GOMAXPROCS(0), n)
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}

// Safe returns f(), or a "PANIC: ..." line if f panics, so a panic introduced
// by a change shows up as a golden diff on the statement that triggers it
// instead of aborting the whole test binary.
func Safe(f func() string) (out string) {
	defer func() {
		if p := recover(); p != nil {
			// No stack: goroutine ids and addresses would make the output
			// nondeterministic. Reproduce the statement to get one.
			out = fmt.Sprintf("PANIC: %v", p)
		}
	}()
	return f()
}
