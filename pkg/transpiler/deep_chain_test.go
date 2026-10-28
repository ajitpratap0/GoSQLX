// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestTranspileDeepChainFast(t *testing.T) {
	checkDeepChain(t, "OR", 50000, keywords.DialectPostgreSQL, keywords.DialectMySQL)
}

func TestTranspileDeepChains(t *testing.T) {
	// Each near-ceiling case takes seconds; under -race the matrix alone
	// approaches the repository's 120s package timeout. The 50k case above
	// still runs everywhere.
	if testing.Short() || raceEnabled {
		t.Skip("near-ceiling chains skipped under -short and -race")
	}
	pairs := [][2]keywords.SQLDialect{
		{keywords.DialectPostgreSQL, keywords.DialectMySQL},
		{keywords.DialectPostgreSQL, keywords.DialectSQLServer},
		{keywords.DialectMySQL, keywords.DialectPostgreSQL},
		{keywords.DialectSQLServer, keywords.DialectPostgreSQL},
		{keywords.DialectPostgreSQL, keywords.DialectPostgreSQL},
	}
	for _, terms := range []int{490000, 500000} {
		for _, pair := range pairs {
			for _, op := range []string{"OR", "AND", "+", "||", "^", "#"} {
				// OR covers every dialect pipeline below the token ceiling;
				// PostgreSQL -> MySQL additionally covers every operator rewrite.
				// Keep the full 500k safety matrix without multiplying the heavy
				// near-ceiling cases in each normal/race repository test run.
				if terms == 490000 && op != "OR" && pair != pairs[0] {
					continue
				}
				// # is PostgreSQL XOR; other source dialects do not parse it as XOR.
				if op == "#" && pair[0] != keywords.DialectPostgreSQL {
					continue
				}
				t.Run(fmt.Sprintf("%d/%s_%s_%s", terms, pair[0], pair[1], op), func(t *testing.T) {
					checkDeepChain(t, op, terms, pair[0], pair[1])
				})
			}
		}
	}
}

func checkDeepChain(t *testing.T, op string, terms int, from, to keywords.SQLDialect) {
	t.Helper()
	sql := "SELECT 1" + strings.Repeat(" "+op+" 1", terms)
	started := time.Now()
	out, err := transpiler.Transpile(sql, from, to)
	if elapsed := time.Since(started); elapsed > 60*time.Second {
		t.Errorf("transpile took %v, bound 60s", elapsed)
	}
	// Nested call/parenthesis rewrites may reject depth to protect the formatter.
	// Flat OR, AND and addition must succeed.
	if err != nil {
		// Exactly 500k repetitions exceed the tokenizer's fixed 1m-token
		// ceiling. Exercise the full pipeline just below it at 490k as well.
		if terms == 500000 && strings.Contains(err.Error(), "token count") && strings.Contains(err.Error(), "exceeds limit") {
			if out != "" {
				t.Fatal("parse error returned with output")
			}
			t.Log("bounded tokenizer rejection at 500k repetitions")
			return
		}
		if op == "OR" || op == "AND" || op == "+" || !strings.Contains(err.Error(), "expression nesting too deep") {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "" {
			t.Fatal("error returned with output")
		}
		t.Logf("bounded nesting rejection: %v", err)
		return
	}
	if out == "" {
		t.Fatal("empty output")
	}
	if op == "OR" && !strings.HasPrefix(out, "SELECT 1 OR 1") {
		t.Fatalf("unexpected output prefix: %.80s", out)
	}
	t.Logf("success: %d bytes in %v", len(out), time.Since(started))
}
