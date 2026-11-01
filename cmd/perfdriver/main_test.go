// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
)

// wantCases is the fixed instruction-count suite the perf gate relies on.
// Renaming a case breaks the A/B comparison against older bases, so a change
// here must be deliberate.
var wantCases = []string{
	"e2e/aggregate", "e2e/complex", "e2e/cte", "e2e/delete", "e2e/insert",
	"e2e/join", "e2e/select_where", "e2e/simple_select", "e2e/subquery",
	"e2e/update", "e2e/window", "rw/postgresql/medium",
}

func TestListPrintsTheFixedSuite(t *testing.T) {
	var out bytes.Buffer
	if err := realMain([]string{"-list"}, &out); err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(out.String())
	if strings.Join(got, " ") != strings.Join(wantCases, " ") {
		t.Fatalf("cases:\n got %v\nwant %v", got, wantCases)
	}
}

func TestEveryCaseParses(t *testing.T) {
	for _, c := range wantCases {
		t.Run(c, func(t *testing.T) {
			if err := realMain([]string{"-case", c, "-n", "2"}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestZeroIterationsIsAllowed(t *testing.T) {
	// n=0 is the start-up-only baseline some counters subtract.
	if err := realMain([]string{"-case", "e2e/join", "-n", "0"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsBadInput(t *testing.T) {
	for _, args := range [][]string{
		{},                                 // no case
		{"-case", "e2e/nope"},              // unknown case
		{"-case", "e2e/join", "-n", "-1"},  // negative count
		{"-case", "e2e/join", "stray-arg"}, // positional argument
	} {
		if err := realMain(args, &bytes.Buffer{}); err == nil {
			t.Errorf("realMain(%q) succeeded, want an error", args)
		}
	}
}

func TestRealWorldCaseIsCapped(t *testing.T) {
	set := mustCorpus(t)
	w, ok := workloads(set)["rw/postgresql/medium"]
	if !ok {
		t.Fatal("rw/postgresql/medium missing")
	}
	if len(w.sqls) == 0 || len(w.sqls) > rwStatements {
		t.Fatalf("rw/postgresql/medium has %d statements, want 1..%d", len(w.sqls), rwStatements)
	}
	if w.dialect != "postgresql" {
		t.Fatalf("dialect = %q, want postgresql", w.dialect)
	}
}

func mustCorpus(t *testing.T) *benchcorpus.Set {
	t.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	return set
}
