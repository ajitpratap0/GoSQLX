// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	sqlast "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestLowerKeywordTable checks every table entry against strings.ToLower, the
// behaviour the table replaces.
func TestLowerKeywordTable(t *testing.T) {
	if len(lowerKeywordTable) == 0 {
		t.Fatal("lowerKeywordTable is empty")
	}
	for upper, lower := range lowerKeywordTable {
		if want := strings.ToLower(upper); lower != want {
			t.Errorf("lowerKeywordTable[%q] = %q, want %q", upper, lower, want)
		}
	}
}

// TestLowerKeywordMatchesToLower is the equivalence test: for table hits,
// misses, mixed case, already-lower and non-ASCII input the result is
// byte-identical to strings.ToLower.
func TestLowerKeywordMatchesToLower(t *testing.T) {
	inputs := []string{
		"", "a", "SELECT", "select", "Select", "sElEcT", "ORDER BY", "order by",
		"NOT MATCHED BY SOURCE", " WHERE ", " where ", "UNKNOWN_KW", "X-Y",
		"CAFÉ", "İSTANBUL", "ÀB", "straße", "ΣΑΣ", "WITH\tTIES", "MiXeD CaSe 123",
	}
	for u := range lowerKeywordTable {
		inputs = append(inputs, u, strings.ToLower(u), capitalized(u))
	}
	for _, in := range inputs {
		if got, want := lowerKeyword(in), strings.ToLower(in); got != want {
			t.Errorf("lowerKeyword(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestKwLowerDoesNotAllocateForKnownKeywords pins the point of the table.
func TestKwLowerDoesNotAllocateForKnownKeywords(t *testing.T) {
	opts := sqlast.ReadableStyle()
	opts.KeywordCase = sqlast.KeywordLower
	f := &nodeFormatter{opts: opts}
	var sink string
	for _, k := range []string{"SELECT", "FROM", "WHERE", "ORDER BY", "WITH TIES", "LEFT JOIN", "UNION ALL"} {
		if got := f.kw(k); got != strings.ToLower(k) {
			t.Fatalf("kw(%q) = %q", k, got)
		}
		if n := testing.AllocsPerRun(100, func() { sink = f.kw(k) }); n != 0 {
			t.Errorf("kw(%q) allocates %v times per call, want 0", k, n)
		}
	}
	_ = sink
}

// TestKwLiteralsAreInLowerKeywordTable parses this package's sources and
// requires every kw("LITERAL") call to be in the table, so a new keyword
// cannot silently fall back to the allocating path.
func TestKwLiteralsAreInLowerKeywordTable(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "kw" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			seen++
			if _, ok := lowerKeywordTable[s]; !ok && s != strings.ToLower(s) {
				t.Errorf("%s: kw(%q) is not in lowerKeywordTable", fset.Position(lit.Pos()), s)
			}
			return true
		})
	}
	if seen < 50 {
		t.Fatalf("found only %d kw literal call sites; scanner is broken", seen)
	}
}

// capitalized upper-cases the first byte and lower-cases the rest, giving a
// mixed-case probe for ASCII keywords.
func capitalized(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
