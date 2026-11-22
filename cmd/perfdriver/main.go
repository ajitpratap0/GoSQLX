// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Command perfdriver runs one fixed parse workload a fixed number of times, so
// that an external counter can measure the instructions it retires. The perf
// gate (scripts/perf/ab.sh) runs it under `perf stat -e instructions:u`,
// `valgrind --tool=cachegrind` or `/usr/bin/time -l`, at two iteration counts,
// and divides the difference by the difference in iterations. That cancels
// process start-up and corpus loading, leaving instructions per operation.
//
// Benchmarks cannot be used for this: they run for a fixed time, so the number
// of operations, and with it the instruction total, changes from run to run.
//
// Run it with GOGC=off, GOMAXPROCS=1 and GODEBUG=asyncpreemptoff=1 so that GC
// and preemption work do not leak into the count (ab.sh sets all three).
//
// Usage:
//
//	perfdriver -list
//	perfdriver -case e2e/join -n 2000
//
// It must run inside the repository (or a source tree of it), because it loads
// the benchmark corpus through internal/benchcorpus.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// rwStatements caps the real-world case the same way BenchmarkParseRW does:
// the first N statements of the bucket, in corpus order.
const rwStatements = 64

// workload is one case: a dialect ("" for gosqlx.Parse) and the statements one
// operation parses.
type workload struct {
	dialect keywords.SQLDialect
	sqls    []string
}

// rwCases are the real-world cells measured besides the portable queries.
var rwCases = []struct {
	dialect string
	bucket  benchcorpus.Bucket
}{
	{"postgresql", benchcorpus.Medium},
}

// workloads builds every case from the corpus: e2e/<query> for each portable
// query (Parse + ReleaseAST, as BenchmarkParseE2E) and rw/<dialect>/<bucket>
// (ParseWithDialect over the bucket, as BenchmarkParseRW).
func workloads(set *benchcorpus.Set) map[string]workload {
	out := make(map[string]workload)
	for _, q := range set.Portable() {
		out["e2e/"+q.ID] = workload{sqls: []string{q.SQL}}
	}
	for _, c := range rwCases {
		var sqls []string
		for _, st := range benchcorpus.InBucket(set.RealWorld(c.dialect), c.bucket) {
			if len(sqls) == rwStatements {
				break
			}
			sqls = append(sqls, st.SQL)
		}
		if len(sqls) > 0 {
			out["rw/"+c.dialect+"/"+c.bucket.String()] = workload{dialect: keywords.SQLDialect(c.dialect), sqls: sqls}
		}
	}
	return out
}

func caseNames(w map[string]workload) []string {
	names := make([]string, 0, len(w))
	for name := range w {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// run performs n operations of the named case.
func run(w workload, n int) error {
	for i := 0; i < n; i++ {
		for _, sql := range w.sqls {
			var (
				tree *ast.AST
				err  error
			)
			if w.dialect == "" {
				tree, err = gosqlx.Parse(sql)
			} else {
				tree, err = gosqlx.ParseWithDialect(sql, w.dialect)
			}
			if err != nil {
				return err
			}
			ast.ReleaseAST(tree)
		}
	}
	return nil
}

func main() {
	if err := realMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "perfdriver:", err)
		os.Exit(1)
	}
}

func realMain(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("perfdriver", flag.ContinueOnError)
	list := fs.Bool("list", false, "print the case names, one per line, and exit")
	name := fs.String("case", "", "case to run (see -list)")
	n := fs.Int("n", 1000, "operations to run (0 runs only start-up and corpus loading)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	set, err := benchcorpus.Default()
	if err != nil {
		return err
	}
	cases := workloads(set)
	if *list {
		for _, c := range caseNames(cases) {
			fmt.Fprintln(stdout, c)
		}
		return nil
	}
	if *name == "" {
		return errors.New("-case is required (see -list)")
	}
	if *n < 0 {
		return fmt.Errorf("-n must be >= 0, got %d", *n)
	}
	w, ok := cases[*name]
	if !ok {
		return fmt.Errorf("unknown case %q (see -list)", *name)
	}
	if err := run(w, *n); err != nil {
		return fmt.Errorf("case %s: %w", *name, err)
	}
	return nil
}
