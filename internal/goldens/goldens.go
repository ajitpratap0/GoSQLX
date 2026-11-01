// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package goldens pins observable library behaviour over the benchmark corpus
// so performance work cannot change output silently.
//
// Each golden is one file, testdata/goldens/<name>.sha256. It holds one line
// per row (a corpus file, or an LSP document) with one short hash per column
// (a dialect, a render style, ...). A cell's hash covers the full output of
// every statement in the row, in statement order, so any byte of difference in
// any statement changes it, while the file stays a few kilobytes.
//
// Flags (pass after -args, or directly to a single-package go test):
//
//	-goldens.update     rewrite the golden files from the current tree
//	-goldens.dump=DIR   also write every output in readable form under DIR
//	-goldens.base=DIR   a -goldens.dump directory made from a base revision; on
//	                    mismatch, print the first differing statements against it
//
// scripts/goldens-diff.sh (task goldens:diff) makes the base dump from a git
// revision in a temporary worktree and runs the goldens against it, which is
// the readable diff mode: it prints, per mismatching cell, the first statements
// whose output changed, with the input SQL and a line diff.
package goldens

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
)

var (
	update  = flag.Bool("goldens.update", false, "rewrite testdata/goldens/*.sha256 from the current tree")
	dumpDir = flag.String("goldens.dump", "", "write every golden output in readable form under this directory")
	baseDir = flag.String("goldens.base", "", "a -goldens.dump directory from a base revision; on mismatch print the first differing statements against it")
)

// Dir is the golden directory relative to the repository root.
const Dir = "testdata/goldens"

// hashLen is the number of hex digits kept per cell (64 bits).
const hashLen = 16

// sameAsLeft stands for a cell whose hash equals the cell to its left, which
// keeps dialect columns that agree compact and makes the ones that differ
// stand out.
const sameAsLeft = "="

const (
	// maxCellsReported caps the mismatching cells listed in a failure.
	maxCellsReported = 25
	// maxCellsDiffed caps the cells for which statement diffs are printed.
	maxCellsDiffed = 6
	// maxStmtsPerCell caps the differing statements printed per cell.
	maxStmtsPerCell = 2
)

// Golden accumulates the outputs of one golden. Add is safe for concurrent use.
type Golden struct {
	name, desc string
	cols       []string
	colIdx     map[string]int
	keep       bool // keep full outputs (dump or base diff requested)

	mu   sync.Mutex
	rows map[string]*row
}

type row struct {
	cells []map[int]item
}

type item struct {
	sum    [sha256.Size]byte
	input  string
	output string // only when Golden.keep
}

// New starts a golden named name (the file stem) with the given columns, in
// the order they appear in the file. desc is written to the file header.
func New(name, desc string, columns ...string) *Golden {
	g := &Golden{name: name, desc: desc, cols: columns, colIdx: map[string]int{}, rows: map[string]*row{}, keep: *dumpDir != "" || *baseDir != ""}
	for i, c := range columns {
		if strings.ContainsAny(c, " \t\n") {
			panic("goldens: column name with whitespace: " + c)
		}
		g.colIdx[c] = i
	}
	return g
}

// Add records the output of statement idx of row in column col. input is the
// statement text, shown by the diff mode. Each (row, col, idx) must be added
// once.
func (g *Golden) Add(rowName, col string, idx int, input, output string) {
	ci, ok := g.colIdx[col]
	if !ok {
		panic(fmt.Sprintf("goldens: %s: unknown column %q", g.name, col))
	}
	if strings.ContainsAny(rowName, " \t\n") {
		panic("goldens: row name with whitespace: " + rowName)
	}
	it := item{sum: sha256.Sum256([]byte(output)), input: input}
	if g.keep {
		it.output = output
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.rows[rowName]
	if r == nil {
		r = &row{cells: make([]map[int]item, len(g.cols))}
		g.rows[rowName] = r
	}
	if r.cells[ci] == nil {
		r.cells[ci] = map[int]item{}
	}
	if _, dup := r.cells[ci][idx]; dup {
		panic(fmt.Sprintf("goldens: %s: duplicate %s/%s#%d", g.name, rowName, col, idx))
	}
	r.cells[ci][idx] = it
}

func (g *Golden) rowNames() []string {
	names := make([]string, 0, len(g.rows))
	for n := range g.rows {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func sortedIdx(m map[int]item) []int {
	idx := make([]int, 0, len(m))
	for i := range m {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	return idx
}

// cellHash hashes "<idx>\x00<sha256(output)>" for every statement in order.
func cellHash(m map[int]item) string {
	if m == nil {
		return "-"
	}
	h := sha256.New()
	for _, i := range sortedIdx(m) {
		it := m[i]
		h.Write(strconv.AppendInt(nil, int64(i), 10))
		h.Write([]byte{0})
		h.Write(it.sum[:])
	}
	return hex.EncodeToString(h.Sum(nil))[:hashLen]
}

func rowCount(r *row) int {
	n := 0
	for _, c := range r.cells {
		if len(c) > n {
			n = len(c)
		}
	}
	return n
}

// Render returns the golden file content for the recorded outputs.
func (g *Golden) Render() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "# GoSQLX behaviour golden %q: %s\n", g.name, g.desc)
	b.WriteString("# Generated; do not edit. Regenerate with -goldens.update (task goldens:update) and list every changed cell in the PR.\n")
	b.WriteString("# Line: <row> <statements> <one 64-bit hash per column, \"=\" = same as left>. Readable diff: task goldens:diff.\n")
	fmt.Fprintf(&b, "columns %s\n", strings.Join(g.cols, " "))
	for _, name := range g.rowNames() {
		r := g.rows[name]
		fmt.Fprintf(&b, "%s %d", name, rowCount(r))
		prev := ""
		for _, c := range r.cells {
			h := cellHash(c)
			b.WriteByte(' ')
			if h == prev {
				b.WriteString(sameAsLeft)
			} else {
				b.WriteString(h)
			}
			prev = h
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Path returns the golden file path under root.
func (g *Golden) Path(root string) string {
	return filepath.Join(root, filepath.FromSlash(Dir), g.name+".sha256")
}

// Check compares the recorded outputs with the committed golden file, or
// rewrites it under -goldens.update. It also writes the -goldens.dump tree.
func (g *Golden) Check(t testing.TB) {
	t.Helper()
	root, err := benchcorpus.FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	if *dumpDir != "" {
		if err := g.Dump(*dumpDir); err != nil {
			t.Fatalf("goldens: dump: %v", err)
		}
	}
	got := g.Render()
	path := g.Path(root)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("goldens: wrote %s (%d rows)", path, len(g.rows))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("goldens: %v\nGenerate it with: go test -run %s ./<pkg> -args -goldens.update (or task goldens:update)", err, t.Name())
	}
	if string(want) == got {
		return
	}
	t.Error(g.Report(string(want), *baseDir))
}

// cellKey names one cell.
type cellKey struct{ row, col string }

// parsed is a golden file reduced to its cells.
type parsed struct {
	cols  []string
	cells map[cellKey]string
	count map[string]string
	rows  []string
}

func parseGolden(s string) parsed {
	p := parsed{cells: map[cellKey]string{}, count: map[string]string{}}
	for _, line := range strings.Split(s, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if f[0] == "columns" {
			p.cols = f[1:]
			continue
		}
		if len(f) < 2 {
			continue
		}
		p.rows = append(p.rows, f[0])
		p.count[f[0]] = f[1]
		prev := ""
		for i, h := range f[2:] {
			if h == sameAsLeft {
				h = prev
			}
			prev = h
			col := strconv.Itoa(i)
			if i < len(p.cols) {
				col = p.cols[i]
			}
			p.cells[cellKey{f[0], col}] = h
		}
	}
	return p
}

// Mismatch is one differing cell between the committed and current golden.
type Mismatch struct {
	Row, Col  string
	Want, Got string // hashes, "" when the row or column is absent
}

// Compare lists the differing cells of two rendered goldens, in row then
// column order of the current golden (rows only in want come last).
func Compare(want, got string) (ms []Mismatch, notes []string) {
	w, g := parseGolden(want), parseGolden(got)
	if strings.Join(w.cols, " ") != strings.Join(g.cols, " ") {
		notes = append(notes, fmt.Sprintf("columns changed: committed %v, current %v", w.cols, g.cols))
	}
	seen := map[string]bool{}
	for _, r := range g.rows {
		seen[r] = true
		if _, ok := w.count[r]; !ok {
			notes = append(notes, "row not in committed golden: "+r)
		} else if w.count[r] != g.count[r] {
			notes = append(notes, fmt.Sprintf("row %s: statement count %s -> %s", r, w.count[r], g.count[r]))
		}
		for _, c := range g.cols {
			k := cellKey{r, c}
			if w.cells[k] != g.cells[k] {
				ms = append(ms, Mismatch{Row: r, Col: c, Want: w.cells[k], Got: g.cells[k]})
			}
		}
	}
	for _, r := range w.rows {
		if !seen[r] {
			notes = append(notes, "row only in committed golden: "+r)
		}
	}
	return ms, notes
}

// Report describes how the current outputs differ from want. With a base
// dump directory it also prints the first differing statements per cell.
func (g *Golden) Report(want, base string) string {
	got := g.Render()
	ms, notes := Compare(want, got)
	var b strings.Builder
	fmt.Fprintf(&b, "golden %q changed: %d cell(s) differ", g.name, len(ms))
	if len(ms) == 0 && len(notes) == 0 {
		b.WriteString("\n  only the header comment differs; regenerate with task goldens:update")
	}
	for _, n := range notes {
		b.WriteString("\n  ")
		b.WriteString(n)
	}
	for i, m := range ms {
		if i == maxCellsReported {
			fmt.Fprintf(&b, "\n  ... and %d more", len(ms)-i)
			break
		}
		fmt.Fprintf(&b, "\n  %s [%s]: %s -> %s", m.Row, m.Col, orDash(m.Want), orDash(m.Got))
	}
	if base == "" {
		fmt.Fprintf(&b, "\nStatement-level diff against a base revision: task goldens:diff BASE=origin/main"+
			"\n(or scripts/goldens-diff.sh origin/main). If the change is intended, regenerate with"+
			" task goldens:update and list every changed cell and its reason in the PR.")
		return b.String()
	}
	if !g.keep {
		b.WriteString("\n(-goldens.base given but outputs were not kept; this is a bug)")
		return b.String()
	}
	for i, m := range ms {
		if i == maxCellsDiffed {
			fmt.Fprintf(&b, "\n... statement diffs shown for the first %d cells only", maxCellsDiffed)
			break
		}
		b.WriteString(g.cellDiff(base, m.Row, m.Col))
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

// cellDiff prints the first differing statements of one cell against the
// base dump.
func (g *Golden) cellDiff(base, rowName, col string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== %s [%s]", rowName, col)
	old, err := readDumpCell(base, g.name, col, rowName)
	if err != nil {
		fmt.Fprintf(&b, "\n  no base output: %v", err)
		return b.String()
	}
	g.mu.Lock()
	r := g.rows[rowName]
	var cur map[int]item
	if r != nil {
		cur = r.cells[g.colIdx[col]]
	}
	g.mu.Unlock()
	all := map[int]bool{}
	for i := range old {
		all[i] = true
	}
	for i := range cur {
		all[i] = true
	}
	idx := make([]int, 0, len(all))
	for i := range all {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	shown := 0
	for _, i := range idx {
		o, inOld := old[i]
		c, inCur := cur[i]
		if inOld && inCur && o == c.output {
			continue
		}
		if shown == maxStmtsPerCell {
			b.WriteString("\n  ... more statements differ")
			break
		}
		shown++
		fmt.Fprintf(&b, "\n--- statement #%d", i)
		if inCur {
			fmt.Fprintf(&b, "\n  input: %s", clip(oneLine(c.input), 300))
		}
		switch {
		case !inOld:
			b.WriteString("\n  (not in base)")
		case !inCur:
			b.WriteString("\n  (not in current run)")
		default:
			b.WriteString(LineDiff(o, c.output, 4, 20))
		}
	}
	if shown == 0 {
		b.WriteString("\n  outputs equal the base dump; the base dump is from a different golden revision")
	}
	return b.String()
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// LineDiff renders old and new as the differing middle part between their
// common leading and trailing lines, with ctx lines of leading context and at
// most max lines per side.
func LineDiff(old, cur string, ctx, maxLines int) string {
	a, c := strings.Split(old, "\n"), strings.Split(cur, "\n")
	p := 0
	for p < len(a) && p < len(c) && a[p] == c[p] {
		p++
	}
	s := 0
	for s < len(a)-p && s < len(c)-p && a[len(a)-1-s] == c[len(c)-1-s] {
		s++
	}
	var b strings.Builder
	for i := max(0, p-ctx); i < p; i++ {
		fmt.Fprintf(&b, "\n    %s", a[i])
	}
	side := func(lines []string, mark string) {
		for i, l := range lines {
			if i == maxLines {
				fmt.Fprintf(&b, "\n  %s ... %d more lines", mark, len(lines)-i)
				return
			}
			fmt.Fprintf(&b, "\n  %s %s", mark, l)
		}
	}
	side(a[p:len(a)-s], "-")
	side(c[p:len(c)-s], "+")
	return b.String()
}

// Dump writes every kept output under dir/<golden>/<column>/<row>.txt.
func (g *Golden) Dump(dir string) error {
	if !g.keep {
		return errors.New("outputs not kept")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for name, r := range g.rows {
		for ci, cell := range r.cells {
			if cell == nil {
				continue
			}
			path := dumpPath(dir, g.name, g.cols[ci], name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			var b strings.Builder
			for _, i := range sortedIdx(cell) {
				out := cell[i].output
				fmt.Fprintf(&b, "### %d %d\n%s\n", i, len(out), out)
			}
			if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

func dumpPath(dir, golden, col, rowName string) string {
	return filepath.Join(dir, golden, col, filepath.FromSlash(rowName)+".txt")
}

// readDumpCell reads one cell written by Dump.
func readDumpCell(dir, golden, col, rowName string) (map[int]string, error) {
	data, err := os.ReadFile(dumpPath(dir, golden, col, rowName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s/%s/%s not in base dump", golden, col, rowName)
	}
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	rd := bufio.NewReader(strings.NewReader(string(data)))
	for {
		hdr, err := rd.ReadString('\n')
		if errors.Is(err, io.EOF) && hdr == "" {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("corrupt dump header %q: %w", hdr, err)
		}
		var idx, n int
		if _, err := fmt.Sscanf(hdr, "### %d %d\n", &idx, &n); err != nil {
			return nil, fmt.Errorf("corrupt dump header %q: %w", hdr, err)
		}
		buf := make([]byte, n+1)
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, fmt.Errorf("corrupt dump body #%d: %w", idx, err)
		}
		out[idx] = string(buf[:n])
	}
}
