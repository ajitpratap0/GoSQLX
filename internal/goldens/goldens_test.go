// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package goldens

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// sample records two rows of two statements in two columns; mutate changes
// the output of one statement.
func sample(keep bool, mutate func(row, col string, idx int, out string) string) *Golden {
	g := New("sample", "unit test", "a", "b")
	g.keep = keep
	for _, row := range []string{"dir/two.sql", "dir/one.sql"} {
		for _, col := range []string{"a", "b"} {
			for idx := 0; idx < 2; idx++ {
				out := "line1\nline2 " + row + "\nline3"
				if col == "b" && row == "dir/one.sql" {
					out = "different " + out
				}
				if mutate != nil {
					out = mutate(row, col, idx, out)
				}
				g.Add(row, col, idx, "SELECT "+row, out)
			}
		}
	}
	return g
}

func TestRenderIsSortedCompactAndOrderIndependent(t *testing.T) {
	got := sample(false, nil).Render()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	var rows []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			rows = append(rows, l)
		}
	}
	if len(rows) != 3 || rows[0] != "columns a b" {
		t.Fatalf("unexpected layout:\n%s", got)
	}
	if !strings.HasPrefix(rows[1], "dir/one.sql 2 ") || !strings.HasPrefix(rows[2], "dir/two.sql 2 ") {
		t.Fatalf("rows not sorted:\n%s", got)
	}
	if f := strings.Fields(rows[2]); len(f) != 4 || f[3] != sameAsLeft || len(f[2]) != hashLen {
		t.Fatalf("equal neighbour cells must render as %q: %q", sameAsLeft, rows[2])
	}
	if f := strings.Fields(rows[1]); f[3] == sameAsLeft {
		t.Fatalf("differing cells rendered as equal: %q", rows[1])
	}

	// Adding in a different order, concurrently, renders the same file.
	g := New("sample", "unit test", "a", "b")
	type add struct {
		row, col string
		idx      int
		out      string
	}
	var adds []add
	for _, row := range []string{"dir/one.sql", "dir/two.sql"} {
		for idx := 1; idx >= 0; idx-- {
			for _, col := range []string{"b", "a"} {
				out := "line1\nline2 " + row + "\nline3"
				if col == "b" && row == "dir/one.sql" {
					out = "different " + out
				}
				adds = append(adds, add{row, col, idx, out})
			}
		}
	}
	Parallel(len(adds), func(i int) {
		a := adds[i]
		g.Add(a.row, a.col, a.idx, "", a.out)
	})
	if g.Render() != got {
		t.Fatalf("render depends on Add order:\n%s\nvs\n%s", g.Render(), got)
	}
}

func TestCompareFindsExactlyTheMutatedCell(t *testing.T) {
	want := sample(false, nil).Render()
	if ms, notes := Compare(want, want); len(ms) != 0 || len(notes) != 0 {
		t.Fatalf("identical goldens differ: %v %v", ms, notes)
	}
	// A one-byte change in one statement of one cell, in a column that was
	// rendered as "=" before, must be reported for that cell only.
	got := sample(false, func(row, col string, idx int, out string) string {
		if row == "dir/two.sql" && col == "b" && idx == 1 {
			return out + "!"
		}
		return out
	}).Render()
	ms, notes := Compare(want, got)
	if len(notes) != 0 || len(ms) != 1 || ms[0].Row != "dir/two.sql" || ms[0].Col != "b" {
		t.Fatalf("want one mismatch at dir/two.sql [b], got %+v %v", ms, notes)
	}
	// Changing the left cell to equal the right one keeps the right cell's
	// resolved hash, so only the left cell is reported.
	got = sample(false, func(row, col string, idx int, out string) string {
		if row == "dir/one.sql" && col == "a" {
			return "different " + out
		}
		return out
	}).Render()
	ms, _ = Compare(want, got)
	if len(ms) != 1 || ms[0].Row != "dir/one.sql" || ms[0].Col != "a" {
		t.Fatalf("want one mismatch at dir/one.sql [a], got %+v", ms)
	}
}

func TestCompareReportsRowAndColumnChanges(t *testing.T) {
	want := sample(false, nil).Render()
	g := New("sample", "unit test", "a", "c")
	g.Add("dir/one.sql", "a", 0, "", "x")
	g.Add("dir/new.sql", "c", 0, "", "y")
	ms, notes := Compare(want, g.Render())
	joined := strings.Join(notes, "\n")
	for _, w := range []string{"columns changed", "row not in committed golden: dir/new.sql", "row only in committed golden: dir/two.sql", "statement count 2 -> 1"} {
		if !strings.Contains(joined, w) {
			t.Errorf("notes lack %q:\n%s", w, joined)
		}
	}
	if len(ms) == 0 {
		t.Error("no cell mismatches reported")
	}
}

func TestReportWithBaseDumpShowsFirstDifferingStatements(t *testing.T) {
	dir := t.TempDir()
	base := sample(true, nil)
	if err := base.Dump(dir); err != nil {
		t.Fatal(err)
	}
	cur := sample(true, func(row, col string, idx int, out string) string {
		if row == "dir/two.sql" && col == "a" && idx == 1 {
			return strings.Replace(out, "line2", "LINE2", 1)
		}
		return out
	})
	rep := cur.Report(base.Render(), dir)
	for _, w := range []string{
		`golden "sample" changed: 1 cell(s) differ`,
		"dir/two.sql [a]",
		"--- statement #1",
		"input: SELECT dir/two.sql",
		"    line1",
		"  - line2 dir/two.sql",
		"  + LINE2 dir/two.sql",
	} {
		if !strings.Contains(rep, w) {
			t.Errorf("report lacks %q:\n%s", w, rep)
		}
	}
	if strings.Contains(rep, "statement #0") {
		t.Errorf("report shows an unchanged statement:\n%s", rep)
	}

	noBase := cur.Report(base.Render(), "")
	if !strings.Contains(noBase, "task goldens:diff") || strings.Contains(noBase, "--- statement") {
		t.Errorf("report without base must point at task goldens:diff only:\n%s", noBase)
	}
}

func TestDumpRoundTripsArbitraryOutput(t *testing.T) {
	dir := t.TempDir()
	g := New("rt", "unit test", "c")
	g.keep = true
	outs := []string{"", "### 1 99\nfake header\n", "trailing newline\n", "ünïcödé\r\n\x00"}
	for i, o := range outs {
		g.Add("x/y.sql", "c", i, "", o)
	}
	if err := g.Dump(dir); err != nil {
		t.Fatal(err)
	}
	got, err := readDumpCell(dir, "rt", "c", "x/y.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range outs {
		if got[i] != o {
			t.Errorf("item %d: got %q, want %q", i, got[i], o)
		}
	}
	if _, err := readDumpCell(dir, "rt", "c", "missing.sql"); err == nil {
		t.Error("missing cell read without error")
	}
}

func TestLineDiff(t *testing.T) {
	old := "a\nb\nc\nd\ne"
	cur := "a\nb\nc\nX\ne"
	got := LineDiff(old, cur, 2, 10)
	want := "\n    b\n    c\n  - d\n  + X"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	long := LineDiff("x", strings.Repeat("y\n", 30)+"x", 0, 5)
	if !strings.Contains(long, "+ ... 25 more lines") {
		t.Fatalf("long diff not capped: %q", long)
	}
}

func TestTokensRendersEveryField(t *testing.T) {
	l := func(line, col int) models.Location { return models.Location{Line: line, Column: col} }
	toks := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT", Word: &models.Word{Value: "SELECT", Keyword: &models.Keyword{Word: "SELECT", Reserved: true}}}, Start: l(1, 1), End: l(1, 7)},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "a b", Quote: '`', Word: &models.Word{Value: "a b", QuoteStyle: '`'}}, Start: l(1, 8), End: l(1, 13)},
		{Token: models.Token{Type: models.TokenTypeNumber, Value: "9999999999", Long: true}, Start: l(2, 1), End: l(2, 11)},
	}
	got := Tokens(toks)
	want := "1:1-1:7 SELECT \"SELECT\" w=\"SELECT\"|'\\x00'|SELECT|true\n" +
		"1:8-1:13 IDENTIFIER \"a b\" q='`' w=\"a b\"|'`'|-\n" +
		"2:1-2:11 NUMBER \"9999999999\" long\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	// The real tokenizer output carries spans for every token, EOF included.
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	live, err := tkz.Tokenize([]byte("SELECT x\nFROM t"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Tokens(live); !strings.Contains(got, "2:6-2:7 IDENTIFIER \"t\"") || !strings.Contains(got, "EOF") {
		t.Fatalf("tokenizer dump:\n%s", got)
	}
}

func TestPositionsCoversNodePositionsAndStatementBounds(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("-- c\nSELECT a\nFROM t JOIN u ON t.id = u.id;\nSELECT 1", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	got := Positions(tree)
	for _, w := range []string{
		"Statements[0](SelectStatement)\n",
		"  Columns[0](Identifier)\n    Pos 2:8\n",
		"StatementStarts[0] 2:1\n",
		"StatementStarts[1] 4:1\n",
		"StatementEnds[0] 3:30\n",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("positions lack %q:\n%s", w, got)
		}
	}
	if Positions(tree) != got {
		t.Error("Positions is not deterministic")
	}
	if Positions(nil) != "" {
		t.Error("Positions(nil) not empty")
	}
}

func TestErrorIncludesCodeLocationAndMessage(t *testing.T) {
	_, err := gosqlx.ParseWithDialect("SELECT FROM", keywords.DialectGeneric)
	got := Error(err)
	if !strings.HasPrefix(got, "error code=E") || !strings.Contains(got, " at=1:") || !strings.Contains(got, err.Error()) {
		t.Fatalf("unexpected error rendering: %q", got)
	}
	if Error(nil) != "ok" {
		t.Fatal(`Error(nil) != "ok"`)
	}
	if got := Error(errors.New("plain")); got != "error code=\nplain" {
		t.Fatalf("plain error: %q", got)
	}
}

func TestSafeAndParallel(t *testing.T) {
	if got := Safe(func() string { panic("boom") }); got != "PANIC: boom" {
		t.Fatalf("Safe: %q", got)
	}
	var seen [1000]atomic.Int32
	Parallel(len(seen), func(i int) { seen[i].Add(1) })
	for i := range seen {
		if seen[i].Load() != 1 {
			t.Fatalf("index %d ran %d times", i, seen[i].Load())
		}
	}
	Parallel(0, func(int) { t.Error("ran with n=0") })
}

func TestCheckPassesOnCommittedGoldenShape(t *testing.T) {
	// The committed goldens are produced by the per-package tests; here we
	// only make sure every committed file parses into rows and columns.
	for _, name := range []string{"tokens", "parse", "format", "fingerprint", "lint", "security", "transpile", "lsp"} {
		g := New(name, "", "x")
		root := mustRoot(t)
		data, err := readFile(g.Path(root))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p := parseGolden(data)
		if len(p.cols) == 0 || len(p.rows) == 0 {
			t.Fatalf("%s: no columns or rows", name)
		}
		for _, r := range p.rows {
			for _, c := range p.cols {
				if h := p.cells[cellKey{r, c}]; len(h) != hashLen {
					t.Fatalf("%s: %s [%s]: bad hash %q", name, r, c, h)
				}
			}
		}
	}
}

func mustRoot(t *testing.T) string {
	t.Helper()
	root, err := benchcorpus.FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
