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

package highlight

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func TestANSI(t *testing.T) {
	sql := "SELECT 'a'"
	spans := Spans(sql)

	got := ANSI(sql, spans, ANSIOptions{Theme: MonoTheme(), Mode: NoColor})
	if want := "\x1b[1mSELECT\x1b[0m 'a'"; got != want {
		t.Errorf("mono: got %q, want %q", got, want)
	}

	got = ANSI(sql, spans, ANSIOptions{Mode: TrueColor})
	if !strings.Contains(got, "\x1b[1;38;2;86;156;214mSELECT\x1b[0m") {
		t.Errorf("truecolor keyword sequence missing: %q", got)
	}

	got = ANSI(sql, spans, ANSIOptions{})
	if !strings.Contains(got, "38;5;") {
		t.Errorf("256-color sequence missing: %q", got)
	}
	if stripANSI(got) != sql {
		t.Errorf("stripped output %q != source", stripANSI(got))
	}
}

func TestANSI_ResetsAtNewlines(t *testing.T) {
	sql := "/* a\nb */ SELECT 1"
	got := ANSI(sql, Spans(sql), ANSIOptions{Mode: TrueColor})
	for i, line := range strings.Split(got, "\n") {
		if strings.Count(line, "\x1b[") > 0 && !strings.HasSuffix(strings.TrimRight(line, " "), ansiReset) {
			t.Errorf("line %d does not end with a reset: %q", i, line)
		}
	}
	if stripANSI(got) != sql {
		t.Errorf("stripped output %q != source", stripANSI(got))
	}
}

func TestHTML(t *testing.T) {
	sql := "SELECT '<b>&\"' FROM t -- <script>"
	spans := Spans(sql)

	got := HTML(sql, spans, HTMLOptions{})
	want := `<span class="gsx-keyword">SELECT</span> <span class="gsx-string">&#39;&lt;b&gt;&amp;&#34;&#39;</span> ` +
		`<span class="gsx-keyword">FROM</span> <span class="gsx-identifier">t</span> <span class="gsx-comment">-- &lt;script&gt;</span>`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(got, "<script>") || strings.Contains(got, "<b>") {
		t.Error("unescaped markup in output")
	}

	wrapped := HTML(sql, spans, HTMLOptions{Wrap: true, ClassPrefix: "sql-"})
	if !strings.HasPrefix(wrapped, `<pre class="sql-highlight"><code><span class="sql-keyword">`) ||
		!strings.HasSuffix(wrapped, "</code></pre>") {
		t.Errorf("wrap/prefix wrong: %s", wrapped)
	}

	inline := HTML("SELECT 1", Spans("SELECT 1"), HTMLOptions{InlineStyles: true, Theme: LightTheme()})
	if want := `<span style="color:#0000FF;font-weight:bold">SELECT</span> <span style="color:#098658">1</span>`; inline != want {
		t.Errorf("inline: got %s\nwant %s", inline, want)
	}
}

func TestHTML_RejectsUnsafeThemeAndPrefix(t *testing.T) {
	evil := Theme{Styles: map[Category]Style{Keyword: {Color: `red;background:url("x")`}}}
	got := HTML("SELECT 1", Spans("SELECT 1"), HTMLOptions{InlineStyles: true, Theme: evil})
	if strings.Contains(got, "url") || strings.Contains(got, "red") {
		t.Errorf("unsafe color leaked: %s", got)
	}
	got = HTML("SELECT 1", Spans("SELECT 1"), HTMLOptions{ClassPrefix: `x" onclick="alert(1)`})
	if strings.Contains(got, "onclick") || !strings.Contains(got, `class="gsx-keyword"`) {
		t.Errorf("unsafe prefix not replaced: %s", got)
	}
	if css := CSS(evil, ""); css != "" {
		t.Errorf("unsafe CSS emitted: %q", css)
	}
}

func TestCSS(t *testing.T) {
	css := CSS(DarkTheme(), "")
	for _, want := range []string{
		".gsx-keyword{color:#569CD6;font-weight:bold}",
		".gsx-comment{color:#6A9955;font-style:italic}",
		".gsx-error{color:#F44747;text-decoration:underline}",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("missing rule %q in:\n%s", want, css)
		}
	}
	if CSS(Theme{}, "") != css {
		t.Error("zero Theme should mean DarkTheme")
	}
	if !strings.Contains(CSS(LightTheme(), "p_"), ".p_string{color:#A31515}") {
		t.Error("custom prefix not applied")
	}
}

func TestRenderers_IgnoreBadSpans(t *testing.T) {
	src := "SELECT 1"
	bad := []Span{
		{Start: 0, End: 6, Category: Keyword},
		{Start: 3, End: 5, Category: Number},   // overlaps
		{Start: 7, End: 99, Category: Number},  // out of range
		{Start: 7, End: 7, Category: Number},   // empty
		{Start: -1, End: 2, Category: Keyword}, // negative
		{Start: 7, End: 8, Category: Category(250)},
	}
	if got := stripANSI(ANSI(src, bad, ANSIOptions{})); got != src {
		t.Errorf("ANSI with bad spans: %q", got)
	}
	got := HTML(src, bad, HTMLOptions{})
	if want := `<span class="gsx-keyword">SELECT</span> 1`; got != want {
		t.Errorf("HTML with bad spans: got %s, want %s", got, want)
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("boom")
	}
	f.n--
	return len(p), nil
}

func TestWriters_PropagateErrors(t *testing.T) {
	sql := "SELECT a FROM t"
	spans := Spans(sql)
	for n := 0; n < 3; n++ {
		if err := WriteANSI(&failWriter{n: n}, sql, spans, ANSIOptions{}); err == nil {
			t.Errorf("WriteANSI n=%d: expected error", n)
		}
		if err := WriteHTML(&failWriter{n: n}, sql, spans, HTMLOptions{Wrap: true}); err == nil {
			t.Errorf("WriteHTML n=%d: expected error", n)
		}
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sql, spans, HTMLOptions{}); err != nil || buf.Len() == 0 {
		t.Errorf("WriteHTML to buffer: %v", err)
	}
}

func TestThemes(t *testing.T) {
	for _, name := range ThemeNames() {
		th, ok := ThemeByName(strings.ToUpper(name))
		if !ok || th.Name != name {
			t.Errorf("ThemeByName(%q) = %v, %v", name, th.Name, ok)
		}
	}
	if _, ok := ThemeByName("nope"); ok {
		t.Error("unknown theme accepted")
	}
	a := DarkTheme()
	a.Styles[Keyword] = Style{Color: "#000000"}
	if DarkTheme().Style(Keyword).Color != "#569CD6" {
		t.Error("DarkTheme returned shared, mutable state")
	}
}

func TestParseHex(t *testing.T) {
	tests := []struct {
		in      string
		r, g, b uint8
		ok      bool
	}{
		{"#FFFFFF", 255, 255, 255, true},
		{"#0a0B0c", 10, 11, 12, true},
		{"#fff", 255, 255, 255, true},
		{"fff", 0, 0, 0, false},
		{"#ggg", 0, 0, 0, false},
		{"#12345", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	}
	for _, tt := range tests {
		r, g, b, ok := parseHex(tt.in)
		if ok != tt.ok || r != tt.r || g != tt.g || b != tt.b {
			t.Errorf("parseHex(%q) = %d,%d,%d,%v", tt.in, r, g, b, ok)
		}
	}
}

func TestXterm256(t *testing.T) {
	tests := []struct {
		r, g, b uint8
		want    int
	}{
		{0, 0, 0, 16},
		{255, 255, 255, 231},
		{255, 0, 0, 196},
		{128, 128, 128, 244},
	}
	for _, tt := range tests {
		if got := xterm256(tt.r, tt.g, tt.b); got != tt.want {
			t.Errorf("xterm256(%d,%d,%d) = %d, want %d", tt.r, tt.g, tt.b, got, tt.want)
		}
	}
}

// sgrOnlyRE matches output whose only escape sequences are SGR codes.
var sgrOnlyRE = regexp.MustCompile(`^(?s:\x1b\[[0-9;]*m|[^\x1b])*$`)

func TestANSI_NeutralizesTerminalControls(t *testing.T) {
	sql := "SELECT '\x1b[31mred\x1b]0;pwn\x07' AS a,\t'x\x7f' -- \x1b[2J clear\r\n" +
		"/* \x1b[31m */ FROM t\x00 WHERE b = '\u009b31m' AND c = 'ok\xff';\n"
	spans := Spans(sql)
	for _, mode := range []ColorMode{Color256, TrueColor, NoColor} {
		for _, theme := range []Theme{DarkTheme(), MonoTheme()} {
			got := ANSI(sql, spans, ANSIOptions{Theme: theme, Mode: mode})
			text := stripANSI(got)
			if strings.ContainsAny(text, "\x1b\x07\x00\x7f\u009b") {
				t.Fatalf("mode %d: control character leaked into output: %q", mode, got)
			}
			if !sgrOnlyRE.MatchString(got) {
				t.Fatalf("mode %d: output contains a non-SGR escape: %q", mode, got)
			}
			want := "SELECT '␛[31mred␛]0;pwn␇' AS a,\t'x␡' -- ␛[2J clear\r\n" +
				"/* ␛[31m */ FROM t␀ WHERE b = '\ufffd31m' AND c = 'ok\ufffd';\n"
			if text != want {
				t.Fatalf("mode %d: got text\n%q\nwant\n%q", mode, text, want)
			}
		}
	}
}

func TestANSI_LiteralAndCommentEscapesAreInert(t *testing.T) {
	for _, sql := range []string{
		"SELECT '\x1b[31m' FROM t",
		"SELECT 1 -- \x1b[31m\nFROM t",
		"SELECT 1 /* \x1b[31m */",
	} {
		got := ANSI(sql, Spans(sql), ANSIOptions{})
		if strings.Contains(got, "\x1b[31m") {
			t.Errorf("%q: raw source escape survived: %q", sql, got)
		}
		if !strings.Contains(got, "␛[31m") {
			t.Errorf("%q: expected visible ␛ in output: %q", sql, got)
		}
	}
}

func TestANSI_PreservesWhitespaceAndUnicode(t *testing.T) {
	sql := "SELECT\t'naïve é世界 😀'\r\n  FROM t\n"
	got := stripANSI(ANSI(sql, Spans(sql), ANSIOptions{}))
	if got != sql {
		t.Fatalf("got %q, want %q", got, sql)
	}
}

func TestTerminalSafe_CleanInputDoesNotAllocate(t *testing.T) {
	s := "SELECT 'café'\t\r\n FROM t"
	if n := testing.AllocsPerRun(100, func() { _ = terminalSafe(s) }); n != 0 {
		t.Fatalf("terminalSafe allocated %v times on clean input", n)
	}
}
