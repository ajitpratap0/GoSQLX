// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errors

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestContextFormatting_ShortInputsUnchanged locks the exact rendering of the
// SQL context block for inputs whose lines are all within the verbatim limit.
// The expected strings were captured from the implementation that predates the
// bounded context window (#615), so any drift here is a behaviour change.
func TestContextFormatting_ShortInputsUnchanged(t *testing.T) {
	long120 := strings.Repeat("a", 119) + "b"
	cases := []struct {
		name          string
		sql           string
		line, col, hl int
		ctx           string // (*Error).formatContext
		multi         string // FormatMultiLineContext
		window        string // FormatContextWindow(..., 2, 2)
	}{
		{name: "single_line", sql: "SELECT * FORM users", line: 1, col: 10, hl: 4,
			ctx:    "\n   1 | SELECT * FORM users\n                ^^^^\n",
			multi:  "\n   1 | SELECT * FORM users\n                ^^^^\n",
			window: "\n   1 | SELECT * FORM users\n                ^^^^\n"},
		{name: "middle_line", sql: "SELECT a\nFROM t\nWHERE x", line: 2, col: 6, hl: 1,
			ctx:    "\n   1 | SELECT a\n   2 | FROM t\n            ^\n   3 | WHERE x",
			multi:  "\n   1 | SELECT a\n   2 | FROM t\n            ^\n   3 | WHERE x\n",
			window: "\n   1 | SELECT a\n   2 | FROM t\n            ^\n   3 | WHERE x\n"},
		{name: "last_line", sql: "SELECT a\nFROM t\nWHERE x", line: 3, col: 7, hl: 3,
			ctx:    "\n   2 | FROM t\n   3 | WHERE x\n             ^^^\n",
			multi:  "\n   2 | FROM t\n   3 | WHERE x\n             ^^^\n",
			window: "\n   1 | SELECT a\n   2 | FROM t\n   3 | WHERE x\n             ^^^\n"},
		{name: "column_zero", sql: "SELECT a\nFROM t\nWHERE x", line: 2, col: 0, hl: 1,
			ctx:    "\n   1 | SELECT a\n   2 | FROM t\n   3 | WHERE x",
			multi:  "\n   1 | SELECT a\n   2 | FROM t\n   3 | WHERE x\n",
			window: "\n   1 | SELECT a\n   2 | FROM t\n   3 | WHERE x\n"},
		{name: "caret_past_end", sql: "SELECT a FROM", line: 1, col: 14, hl: 1,
			ctx:    "\n   1 | SELECT a FROM\n                    ^\n",
			multi:  "\n   1 | SELECT a FROM\n                    ^\n",
			window: "\n   1 | SELECT a FROM\n                    ^\n"},
		{name: "boundary_120", sql: "SELECT 1\n" + long120 + "\nFROM t", line: 2, col: 118, hl: 3,
			ctx:    "\n   1 | SELECT 1\n   2 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\n                                                                                                                            ^^^\n   3 | FROM t",
			multi:  "\n   1 | SELECT 1\n   2 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\n                                                                                                                            ^^^\n   3 | FROM t\n",
			window: "\n   1 | SELECT 1\n   2 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\n                                                                                                                            ^^^\n   3 | FROM t\n"},
		{name: "crlf", sql: "SELECT a\r\nFROM t\r\nWHERE x", line: 2, col: 3, hl: 2,
			ctx:    "\n   1 | SELECT a\r\n   2 | FROM t\r\n         ^^\n   3 | WHERE x",
			multi:  "\n   1 | SELECT a\r\n   2 | FROM t\r\n         ^^\n   3 | WHERE x\n",
			window: "\n   1 | SELECT a\r\n   2 | FROM t\r\n         ^^\n   3 | WHERE x\n"},
		{name: "trailing_newline", sql: "SELECT 1\n", line: 2, col: 1, hl: 1,
			ctx:    "\n   1 | SELECT 1\n   2 | \n       ^\n",
			multi:  "\n   1 | SELECT 1\n   2 | \n       ^\n",
			window: "\n   1 | SELECT 1\n   2 | \n       ^\n"},
		{name: "trailing_newline_first", sql: "SELECT 1\n", line: 1, col: 8, hl: 1,
			ctx:    "\n   1 | SELECT 1\n              ^\n   2 | ",
			multi:  "\n   1 | SELECT 1\n              ^\n   2 | \n",
			window: "\n   1 | SELECT 1\n              ^\n   2 | \n"},
		{name: "many_lines", sql: "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nSELECT x\nl10\nl11\nl12", line: 9, col: 8, hl: 1,
			ctx:    "\n   8 | l8\n   9 | SELECT x\n              ^\n  10 | l10",
			multi:  "\n   8 | l8\n   9 | SELECT x\n              ^\n  10 | l10\n",
			window: "\n   7 | l7\n   8 | l8\n   9 | SELECT x\n              ^\n  10 | l10\n  11 | l11\n"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loc := models.Location{Line: c.line, Column: c.col}
			e := NewError(ErrCodeExpectedToken, "msg", loc).WithContext(c.sql, c.hl)
			if got := e.formatContext(); got != c.ctx {
				t.Errorf("formatContext mismatch:\n got: %q\nwant: %q", got, c.ctx)
			}
			wantErr := fmt.Sprintf("Error %s at line %d, column %d: msg\n", ErrCodeExpectedToken, c.line, c.col) + c.ctx
			if got := e.Error(); !strings.HasPrefix(got, wantErr) {
				t.Errorf("Error() mismatch:\n got: %q\nwant prefix: %q", got, wantErr)
			}
			if got := FormatMultiLineContext(c.sql, loc, c.hl); got != c.multi {
				t.Errorf("FormatMultiLineContext mismatch:\n got: %q\nwant: %q", got, c.multi)
			}
			if got := FormatContextWindow(c.sql, loc, c.hl, 2, 2); got != c.window {
				t.Errorf("FormatContextWindow mismatch:\n got: %q\nwant: %q", got, c.window)
			}
		})
	}
}

// longLineQuery mirrors the report in #615: one huge select list followed by
// an unterminated string literal on the same (only) line.
func longLineQuery(size int) (sql string, quoteCol int) {
	prefix := "SELECT " + strings.Repeat("c, ", size/3) + "x FROM t WHERE a = "
	return prefix + "'unterminated", len(prefix) + 1
}

type boundedCase struct {
	name string
	sql  string
	loc  models.Location
	hl   int
}

func boundedCases() []boundedCase {
	const kb100 = 100 * 1024
	sql100, col100 := longLineQuery(kb100)
	cases := []boundedCase{
		{"long single line, error at end (100KB)", sql100, models.Location{Line: 1, Column: col100}, 1},
		{"#616 shape: short context, huge column", "WHERE clause requires a boolean expression", models.Location{Line: 1, Column: 102422}, 6},
		{"huge neighbour lines",
			strings.Repeat("x, ", kb100/3) + "\nSELECT 1\n" + strings.Repeat("y, ", kb100/3),
			models.Location{Line: 2, Column: 8}, 1},
		{"huge highlight on short line", "SELECT * FORM users", models.Location{Line: 1, Column: 10}, 1 << 20},
	}
	if !testing.Short() {
		sql1m, col1m := longLineQuery(1 << 20)
		cases = append(cases, boundedCase{"long single line, error at end (1MiB)", sql1m, models.Location{Line: 1, Column: col1m}, 1})
	}
	return cases
}

func TestErrorString_BoundedForLongLines(t *testing.T) {
	const limit = 1024
	for _, c := range boundedCases() {
		t.Run(c.name, func(t *testing.T) {
			e := NewError(ErrCodeUnterminatedString, "unterminated string literal", c.loc).WithContext(c.sql, c.hl)
			if got := e.Error(); len(got) >= limit {
				t.Errorf("Error() is %d bytes, want < %d", len(got), limit)
			}
			if got := FormatMultiLineContext(c.sql, c.loc, c.hl); len(got) >= limit {
				t.Errorf("FormatMultiLineContext is %d bytes, want < %d", len(got), limit)
			}
			if got := FormatContextWindow(c.sql, c.loc, c.hl, 2, 2); len(got) >= limit {
				t.Errorf("FormatContextWindow is %d bytes, want < %d", len(got), limit)
			}
		})
	}
}

func BenchmarkErrorString_LongLine(b *testing.B) {
	sql, col := longLineQuery(100 * 1024)
	e := NewError(ErrCodeUnterminatedString, "unterminated string literal", models.Location{Line: 1, Column: col}).WithContext(sql, 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Error()
	}
}

func BenchmarkErrorString_Short(b *testing.B) {
	e := NewError(ErrCodeExpectedToken, "expected FROM, got FORM", models.Location{Line: 1, Column: 10}).WithContext("SELECT * FORM users", 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Error()
	}
}

func TestLineRange(t *testing.T) {
	inputs := []string{"", "a", "a\n", "\n\n", "a\nb\nc", "a\r\nb"}
	for _, in := range inputs {
		all := strings.Split(in, "\n")
		for first := 1; first <= 5; first++ {
			for last := 1; last <= 5; last++ {
				var want []string
				if first <= len(all) && last >= first {
					hi := last
					if hi > len(all) {
						hi = len(all)
					}
					want = all[first-1 : hi]
				}
				got := lineRange(in, first, last)
				if len(got) != len(want) {
					t.Errorf("lineRange(%q, %d, %d) = %q, want %q", in, first, last, got, want)
					continue
				}
				for i := range got {
					if got[i] != want[i] {
						t.Errorf("lineRange(%q, %d, %d) = %q, want %q", in, first, last, got, want)
						break
					}
				}
			}
		}
	}
	// A huge upper bound must not allocate proportionally.
	if got := lineRange("a\nb", 1, 1<<40); len(got) != 2 {
		t.Errorf("lineRange with huge last = %q, want 2 lines", got)
	}
}

func TestClipLine(t *testing.T) {
	t.Run("verbatim at limit", func(t *testing.T) {
		line := strings.Repeat("a", contextMaxLine)
		got, start, prefix := clipLine(line, contextMaxLine-1)
		if got != line || start != 0 || prefix != 0 {
			t.Errorf("120-byte line should be verbatim, got len=%d start=%d prefix=%d", len(got), start, prefix)
		}
	})
	t.Run("windowed one over the limit", func(t *testing.T) {
		line := strings.Repeat("a", contextMaxLine+1)
		got, _, _ := clipLine(line, contextMaxLine)
		if got == line || !strings.Contains(got, contextEllipsis) {
			t.Errorf("121-byte line should be clipped, got %q", got)
		}
	})
	long := strings.Repeat("a", 300)
	t.Run("error at start has no left marker", func(t *testing.T) {
		got, start, prefix := clipLine(long, 0)
		if strings.HasPrefix(got, contextEllipsis) || !strings.HasSuffix(got, contextEllipsis) || start != 0 || prefix != 0 {
			t.Errorf("unexpected clip %q start=%d prefix=%d", got, start, prefix)
		}
	})
	t.Run("error at end has no right marker", func(t *testing.T) {
		got, start, prefix := clipLine(long, len(long)-1)
		if !strings.HasPrefix(got, contextEllipsis) || strings.HasSuffix(got, contextEllipsis) || prefix != len(contextEllipsis) || start == 0 {
			t.Errorf("unexpected clip %q start=%d prefix=%d", got, start, prefix)
		}
	})
	t.Run("offset beyond end", func(t *testing.T) {
		got, _, _ := clipLine(long, 1<<30)
		if len(got) > contextMaxLine+2*len(contextEllipsis) {
			t.Errorf("clipped line too long: %d", len(got))
		}
	})
	t.Run("multi-byte runes stay valid", func(t *testing.T) {
		line := strings.Repeat("é", 200) // 400 bytes
		for off := 1; off < len(line); off += 7 {
			got, _, _ := clipLine(line, off)
			if !utf8.ValidString(got) {
				t.Fatalf("off=%d: clipped line is not valid UTF-8: %q", off, got)
			}
			if !strings.Contains(got, contextEllipsis) {
				t.Fatalf("off=%d: expected an ellipsis in %q", off, got)
			}
		}
	})
}

// TestContext_InvalidUTF8LongLine guards against clipLine scanning past the
// window on a long run of UTF-8 continuation bytes (start > end panicked).
func TestContext_InvalidUTF8LongLine(t *testing.T) {
	line := strings.Repeat("\x80", 300)
	maxLen := contextMaxLine + 2*len(contextEllipsis)
	for off := 0; off <= len(line); off += 13 {
		got, start, prefix := clipLine(line, off)
		if len(got) > maxLen || start < 0 || start > len(line) || (prefix != 0 && prefix != len(contextEllipsis)) {
			t.Fatalf("off=%d: unbounded clip len=%d start=%d prefix=%d", off, len(got), start, prefix)
		}
	}

	loc := models.Location{Line: 1, Column: 100}
	// Generous bound: gutter, clipped line, caret line and newlines.
	const bound = 4 * (contextMaxLine + 2*len(contextEllipsis) + 16)
	if got := FormatMultiLineContext(line, loc, 1); got == "" || len(got) > bound {
		t.Errorf("FormatMultiLineContext: len=%d, want 1..%d", len(got), bound)
	}
	if got := FormatContextWindow(line, loc, 1, 1, 1); got == "" || len(got) > bound {
		t.Errorf("FormatContextWindow: len=%d, want 1..%d", len(got), bound)
	}
	msg := NewError(ErrCodeUnexpectedToken, "unexpected", loc).WithContext(line, 1).Error()
	if len(msg) > bound+512 {
		t.Errorf("Error(): len=%d, want <= %d", len(msg), bound+512)
	}
}

func TestContext_CaretAlignedUnderErrorByte(t *testing.T) {
	sql, col := longLineQuery(100 * 1024)
	loc := models.Location{Line: 1, Column: col}
	out := FormatMultiLineContext(sql, loc, 1)

	rows := strings.Split(strings.TrimSuffix(strings.TrimPrefix(out, "\n"), "\n"), "\n")
	if len(rows) != 2 {
		t.Fatalf("expected source row and caret row, got %d rows: %q", len(rows), rows)
	}
	idx := strings.IndexByte(rows[1], '^')
	if idx < 0 || idx >= len(rows[0]) {
		t.Fatalf("caret column %d outside source row %q", idx, rows[0])
	}
	if rows[0][idx] != '\'' {
		t.Errorf("caret points at %q, want the opening quote", rows[0][idx])
	}
}

func TestContext_NeighbourLinesClipped(t *testing.T) {
	sql := strings.Repeat("x", 500) + "\nSELECT 1\n" + strings.Repeat("y", 500)
	out := FormatMultiLineContext(sql, models.Location{Line: 2, Column: 8}, 1)
	rows := strings.Split(strings.TrimSuffix(strings.TrimPrefix(out, "\n"), "\n"), "\n")
	if len(rows) != 4 {
		t.Fatalf("expected 4 rows, got %d: %q", len(rows), rows)
	}
	for _, i := range []int{0, 3} {
		if !strings.HasSuffix(rows[i], contextEllipsis) {
			t.Errorf("neighbour row %d not clipped: %q", i, rows[i])
		}
		if len(rows[i]) > 6+contextMaxLine+2*len(contextEllipsis) {
			t.Errorf("neighbour row %d too long: %d", i, len(rows[i]))
		}
	}
	if !strings.HasSuffix(rows[1], "SELECT 1") {
		t.Errorf("short error line should be verbatim: %q", rows[1])
	}
}

func TestContext_HighlightAndPaddingCapped(t *testing.T) {
	out := FormatMultiLineContext("SELECT 1", models.Location{Line: 1, Column: 5000}, 1<<20)
	if got := strings.Count(out, "^"); got != contextMaxLine {
		t.Errorf("highlight carets = %d, want %d", got, contextMaxLine)
	}
	if len(out) > 1024 {
		t.Errorf("output is %d bytes, want bounded", len(out))
	}
}

func TestContext_InvalidLocations(t *testing.T) {
	for _, loc := range []models.Location{{Line: 0, Column: 1}, {Line: -1, Column: 1}, {Line: 3, Column: 1}, {Line: 1 << 62, Column: 1}} {
		if got := FormatMultiLineContext("a\nb", loc, 1); got != "" {
			t.Errorf("FormatMultiLineContext(%+v) = %q, want empty", loc, got)
		}
		if got := FormatContextWindow("a\nb", loc, 1, 1<<62, 1<<62); got != "" {
			t.Errorf("FormatContextWindow(%+v) = %q, want empty", loc, got)
		}
	}
	// Huge before/after counts and negative counts must neither panic nor over-allocate.
	if got := FormatContextWindow("a\nb\nc", models.Location{Line: 2, Column: 1}, 1, 1<<62, 1<<62); !strings.Contains(got, " 3 | c") || !strings.Contains(got, " 1 | a") {
		t.Errorf("unexpected window for huge counts: %q", got)
	}
	if got := FormatContextWindow("a\nb\nc", models.Location{Line: 2, Column: 1}, 1, -1, -1); !strings.Contains(got, " 2 | b") || strings.Contains(got, " 1 | a") || strings.Contains(got, " 3 | c") {
		t.Errorf("unexpected window for negative counts: %q", got)
	}
}

// splitRows returns the rendered context block as rows without the leading and
// trailing newline.
func splitRows(out string) []string {
	return strings.Split(strings.TrimSuffix(strings.TrimPrefix(out, "\n"), "\n"), "\n")
}

// TestContext_TabIsOneColumnLongLine checks that the column reported by the
// tokenizer, where a '\t' counts as one column like any other byte, is used as
// a byte offset when clipping: with many tabs before the error the window must
// still show the offending text.
func TestContext_TabIsOneColumnLongLine(t *testing.T) {
	const tabs = 25
	prefix := strings.Repeat("\t", tabs) + strings.Repeat("a ", 60)
	line := prefix + "ZZTOP" + strings.Repeat(" b", 60)
	if len(line) <= contextMaxLine {
		t.Fatalf("test line must be longer than %d bytes", contextMaxLine)
	}
	// Column as computed by tokenizer.toSQLPosition: 1 + 1 per byte, tabs included.
	col := 1 + len(prefix)
	out := FormatMultiLineContext(line, models.Location{Line: 1, Column: col}, 5)
	rows := splitRows(out)
	if len(rows) != 2 {
		t.Fatalf("expected source row and caret row, got %d rows: %q", len(rows), rows)
	}
	if !strings.Contains(rows[0], "ZZTOP") {
		t.Fatalf("clipped window misses the error site: %q", rows[0])
	}
	idx := strings.IndexByte(rows[1], '^')
	if idx < 0 || idx >= len(rows[0]) || !strings.HasPrefix(rows[0][idx:], "ZZTOP") {
		t.Errorf("caret at %d does not point at ZZTOP in %q", idx, rows[0])
	}
	if got, want := rows[1][:idx], mirrorOf(rows[0][:idx]); got != want {
		t.Errorf("caret padding %q does not mirror the source text %q", got, want)
	}

	// Tabs interleaved inside the window: the error text must still be shown.
	line2 := strings.Repeat("\ta", 40) + "ZZTOP" + strings.Repeat("b", 100)
	col2 := 1 + 40*2
	rows2 := splitRows(FormatMultiLineContext(line2, models.Location{Line: 1, Column: col2}, 5))
	if len(rows2) != 2 || !strings.Contains(rows2[0], "ZZTOP") {
		t.Errorf("interleaved tabs: window misses the error site: %q", rows2)
	}
}

// mirrorOf returns s with every byte but a tab replaced by a space: the padding
// that puts a caret under the byte that follows s whatever width a tab has.
func mirrorOf(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		return ' '
	}, s)
}

// With a tab as one column, the caret line repeats the tabs of the source line
// so the caret stays under the error byte for any tab width.
func TestContext_CaretKeepsTabs(t *testing.T) {
	tests := []struct {
		name string
		line string
		col  int
		want string // whitespace between the gutter and the caret
	}{
		{"no tab", "SELECT 1 FROM t", 8, "       "},
		{"leading tab", "\tWHERE ) AND x", 8, "\t      "},
		{"tab before error", "SELECT 1 FROM t\tWHERE x = = 1", 27, strings.Repeat(" ", 15) + "\t" + strings.Repeat(" ", 10)},
		{"column past the end", "a\tb", 6, " \t   "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := splitRows(FormatMultiLineContext(tc.line, models.Location{Line: 1, Column: tc.col}, 1))
			if len(rows) != 2 {
				t.Fatalf("expected source and caret rows, got %q", rows)
			}
			const gutter = "   1 | "
			if !strings.HasPrefix(rows[1], strings.Repeat(" ", len(gutter))) {
				t.Fatalf("caret row %q does not start with the gutter", rows[1])
			}
			pad := strings.TrimSuffix(rows[1][len(gutter):], "^")
			if pad != tc.want {
				t.Errorf("padding = %q, want %q", pad, tc.want)
			}
		})
	}
}

// TestContext_ClipNeverHidesErrorByte guards against the rune-boundary snap
// moving the window start past the error byte when the line starts with an
// invalid UTF-8 byte (the byte was cut and the caret pointed into the ellipsis).
func TestContext_ClipNeverHidesErrorByte(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"continuation_then_digits", "\xbf" + strings.Repeat("0", 121)},
		{"invalid_lead_sql", "\x80SELECT a FROM t WHERE " + strings.Repeat("b = 1 AND ", 20) + "c = 2"},
		{"continuation_run", strings.Repeat("\x80", 3) + strings.Repeat("x", 200)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := splitRows(FormatMultiLineContext(tc.line, models.Location{Line: 1, Column: 1}, 1))
			if len(rows) != 2 {
				t.Fatalf("expected 2 rows, got %q", rows)
			}
			const gutter = "   1 | "
			if !strings.HasPrefix(rows[0], gutter) {
				t.Fatalf("unexpected gutter in %q", rows[0])
			}
			if strings.HasPrefix(rows[0][len(gutter):], contextEllipsis) {
				t.Errorf("line starting at the error byte must not be prefixed with %q: %q", contextEllipsis, rows[0])
			}
			idx := strings.IndexByte(rows[1], '^')
			if idx != len(gutter) || rows[0][idx] != tc.line[0] {
				t.Errorf("caret at %d, want %d under byte %q; row %q", idx, len(gutter), tc.line[0], rows[0])
			}
		})
	}
}

// FuzzClipLine checks that the clipped window always contains the byte the
// column maps to, stays bounded, and that for tab-free lines the caret sits
// directly under that byte. Without -fuzz it only runs the seed corpus.
func FuzzClipLine(f *testing.F) {
	f.Add("\xbf"+strings.Repeat("0", 121), 1)
	f.Add("\x80SELECT a FROM t WHERE "+strings.Repeat("b = 1 AND ", 20)+"c = 2", 1)
	f.Add(strings.Repeat("\t", 25)+strings.Repeat("a ", 60)+"ZZTOP", 221)
	f.Add(strings.Repeat("é", 200), 150)
	f.Add(strings.Repeat("\x80", 300), 100)
	f.Add("SELECT 1", 3)
	f.Fuzz(func(t *testing.T, line string, col int) {
		if strings.IndexByte(line, '\n') >= 0 || col < 1 {
			return
		}
		b := columnToByte(line, col-1)
		if b < 0 || b > len(line) {
			t.Fatalf("columnToByte(%d) = %d out of [0,%d]", col-1, b, len(line))
		}
		display, start, prefixLen := clipLine(line, b)
		if len(display) > contextMaxLine+2*len(contextEllipsis) {
			t.Fatalf("display too long: %d", len(display))
		}
		if len(line) > contextMaxLine && b < len(line) {
			if start > b {
				t.Fatalf("window start %d past error byte %d", start, b)
			}
			if i := prefixLen + b - start; i >= len(display) || display[i] != line[b] {
				t.Fatalf("error byte %d not shown at %d in %q", b, i, display)
			}
		}
		out := FormatMultiLineContext(line, models.Location{Line: 1, Column: col}, 1)
		if len(out) > 4*(contextMaxLine+2*len(contextEllipsis)+16)+4*contextMaxLine {
			t.Fatalf("output too long: %d", len(out))
		}
		if len(line) > contextMaxLine && b < len(line) && strings.IndexByte(line, '\t') < 0 {
			rows := splitRows(out)
			idx := strings.IndexByte(rows[1], '^')
			if idx < 0 || idx >= len(rows[0]) || rows[0][idx] != line[b] {
				t.Fatalf("caret at %d not under error byte %d in %q", idx, b, rows[0])
			}
		}
	})
}
