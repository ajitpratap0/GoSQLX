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

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
)

// resetHighlightFlags restores the highlight command's flag variables (and the
// shared output flag) to their defaults, now and after the test.
func resetHighlightFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		highlightOutputFormat = highlightFormatANSI
		highlightTheme = "dark"
		highlightDialect = ""
		highlightColor = highlightColorAuto
		highlightStandalone = false
		outputFile = ""
	}
	reset()
	t.Cleanup(reset)
}

// runHighlight executes `gosqlx <args...>` with fresh highlight flags and
// returns stdout, stderr and the command error.
func runHighlight(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	resetHighlightFlags(t)
	var out, errBuf bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errBuf)
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})
	err := rootCmd.Execute()
	return out.String(), errBuf.String(), err
}

// withStdin replaces os.Stdin with a pipe holding content for the test.
func withStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatalf("write stdin pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin pipe: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		_ = r.Close()
	})
}

func TestHighlightCmd_Formats(t *testing.T) {
	const sql = "SELECT id FROM users WHERE name = 'a<b'"
	tests := []struct {
		name        string
		args        []string
		contains    []string
		notContains []string
		exact       string
	}{
		{
			name:  "ansi auto on non-terminal prints raw SQL",
			args:  []string{"highlight", sql},
			exact: sql + "\n",
		},
		{
			name:  "alias hl",
			args:  []string{"hl", sql},
			exact: sql + "\n",
		},
		{
			name:  "ansi color never prints raw SQL",
			args:  []string{"highlight", "--color", "never", sql},
			exact: sql + "\n",
		},
		{
			name:     "ansi color always",
			args:     []string{"highlight", "--color", "always", sql},
			contains: []string{"\x1b[", "SELECT", "\x1b[0m"},
		},
		{
			name: "html fragment",
			args: []string{"highlight", "-f", "html", sql},
			contains: []string{
				`<pre class="gsx-highlight"><code>`,
				`<span class="gsx-keyword">SELECT</span>`,
				`<span class="gsx-string">&#39;a&lt;b&#39;</span>`,
				"</code></pre>\n",
			},
			notContains: []string{"<!DOCTYPE", "<style>", "\x1b["},
		},
		{
			name: "html standalone",
			args: []string{"highlight", "--format", "html", "--standalone", "--theme", "light", sql},
			contains: []string{
				"<!DOCTYPE html>",
				`<meta charset="utf-8">`,
				"<style>",
				"background:#FFFFFF",
				".gsx-keyword{color:#0000FF;font-weight:bold}",
				`<span class="gsx-keyword">SELECT</span>`,
				"</html>\n",
			},
		},
		{
			name:     "css",
			args:     []string{"highlight", "-f", "css", "--theme", "dark"},
			contains: []string{".gsx-keyword{color:#569CD6;font-weight:bold}", ".gsx-comment{"},
		},
		{
			name:     "css mono",
			args:     []string{"highlight", "-f", "css", "--theme", "mono"},
			contains: []string{".gsx-keyword{font-weight:bold}"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", "")
			t.Setenv("COLORTERM", "")
			out, _, err := runHighlight(t, tt.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.exact != "" && out != tt.exact {
				t.Fatalf("output = %q, want %q", out, tt.exact)
			}
			for _, s := range tt.contains {
				if !strings.Contains(out, s) {
					t.Errorf("output missing %q:\n%s", s, out)
				}
			}
			for _, s := range tt.notContains {
				if strings.Contains(out, s) {
					t.Errorf("output unexpectedly contains %q:\n%s", s, out)
				}
			}
			if !strings.HasSuffix(out, "\n") {
				t.Errorf("output does not end with a newline: %q", out)
			}
		})
	}
}

func TestHighlightCmd_JSON(t *testing.T) {
	sql := "SELECT a\nFROM t -- c"
	out, _, err := runHighlight(t, "highlight", "-f", "json", sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(out, "]\n") || !strings.Contains(out, "\n  {") {
		t.Errorf("expected pretty-printed JSON array with trailing newline, got %q", out)
	}

	var spans []highlightJSONSpan
	if err := json.Unmarshal([]byte(out), &spans); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	want := []highlightJSONSpan{
		{Start: 0, End: 6, Category: highlight.Keyword, Text: "SELECT", Line: 1, Column: 1},
		{Start: 7, End: 8, Category: highlight.Identifier, Text: "a", Line: 1, Column: 8},
		{Start: 9, End: 13, Category: highlight.Keyword, Text: "FROM", Line: 2, Column: 1},
		{Start: 14, End: 15, Category: highlight.Identifier, Text: "t", Line: 2, Column: 6},
		{Start: 16, End: 20, Category: highlight.Comment, Text: "-- c", Line: 2, Column: 8},
	}
	if len(spans) != len(want) {
		t.Fatalf("got %d spans, want %d: %+v", len(spans), len(want), spans)
	}
	for i := range want {
		if spans[i] != want[i] {
			t.Errorf("span %d = %+v, want %+v", i, spans[i], want[i])
		}
	}
	if !strings.Contains(out, `"category": "keyword"`) {
		t.Errorf("expected category names in JSON, got:\n%s", out)
	}
}

func TestHighlightCmd_JSONInvalidSQL(t *testing.T) {
	out, _, err := runHighlight(t, "highlight", "-f", "json", "SELECT 'unterminated")
	if err != nil {
		t.Fatalf("invalid SQL must still highlight, got error: %v", err)
	}
	var spans []highlightJSONSpan
	if err := json.Unmarshal([]byte(out), &spans); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(spans) == 0 || spans[len(spans)-1].Category != highlight.Error {
		t.Fatalf("expected trailing error span, got %+v", spans)
	}
}

func TestHighlightCmd_InvalidFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"invalid theme", []string{"highlight", "--theme", "neon", "SELECT 1"}, "valid themes: dark, light, mono"},
		{"invalid dialect", []string{"highlight", "--dialect", "bogus", "SELECT 1"}, "unknown SQL dialect"},
		{"invalid format", []string{"highlight", "-f", "yaml", "SELECT 1"}, "valid formats: ansi, html, json, css"},
		{"invalid color", []string{"highlight", "--color", "sometimes", "SELECT 1"}, "valid modes: auto, always, never"},
		{"standalone without html", []string{"highlight", "--standalone", "SELECT 1"}, "--standalone requires --format html"},
		{"missing file", []string{"highlight", filepath.Join(t.TempDir(), "missing.sql")}, "invalid file path"},
		{"too many args", []string{"highlight", "SELECT 1", "SELECT 2"}, "accepts at most 1 arg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := runHighlight(t, tt.args...)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestHighlightCmd_ValidDialect(t *testing.T) {
	out, _, err := runHighlight(t, "highlight", "-f", "html", "--dialect", "mysql", "SELECT `a` FROM t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `<span class="gsx-quoted-identifier">`+"`a`</span>") {
		t.Fatalf("expected quoted identifier under mysql dialect, got:\n%s", out)
	}
}

func TestHighlightCmd_Stdin(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"auto-detected pipe", []string{"highlight", "-f", "html"}},
		{"explicit dash", []string{"highlight", "-f", "html", "-"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withStdin(t, "SELECT 1\n")
			out, _, err := runHighlight(t, tt.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := `<pre class="gsx-highlight"><code><span class="gsx-keyword">SELECT</span> <span class="gsx-number">1</span>` + "\n</code></pre>\n"
			if out != want {
				t.Fatalf("output = %q, want %q", out, want)
			}
		})
	}
}

func TestHighlightCmd_StdinRawPreservesNewline(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	withStdin(t, "SELECT 1\n")
	out, _, err := runHighlight(t, "highlight", "--color", "never")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "SELECT 1\n" {
		t.Fatalf("output = %q, want %q (no extra newline)", out, "SELECT 1\n")
	}
}

func TestHighlightCmd_StdinEmpty(t *testing.T) {
	withStdin(t, "")
	if _, _, err := runHighlight(t, "highlight"); err == nil {
		t.Fatal("expected error for empty stdin")
	}
}

func TestHighlightCmd_FileInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "query.sql")
	if err := os.WriteFile(path, []byte("/* hi */\nSELECT 1"), 0600); err != nil {
		t.Fatal(err)
	}

	out, _, err := runHighlight(t, "highlight", "-f", "html", "--standalone", path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range []string{
		"<title>query.sql</title>",
		`<span class="gsx-comment">/* hi */</span>`,
		`<span class="gsx-keyword">SELECT</span>`,
	} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q:\n%s", s, out)
		}
	}
}

func TestHighlightCmd_OutputFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.json")
	out, _, err := runHighlight(t, "highlight", "-f", "json", "-o", dst, "SELECT 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "" {
		t.Errorf("expected no stdout when -o is set, got %q", out)
	}
	data, err := os.ReadFile(dst) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	var spans []highlightJSONSpan
	if err := json.Unmarshal(data, &spans); err != nil {
		t.Fatalf("invalid JSON in output file: %v", err)
	}
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2: %+v", len(spans), spans)
	}
}

func TestHighlightCmd_ColorEnv(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		noColor   string
		colorTerm string
		wantColor bool
		wantTrue  bool
	}{
		{"always ignores NO_COLOR", []string{"--color", "always"}, "1", "", true, false},
		{"always truecolor", []string{"--color", "always"}, "", "truecolor", true, true},
		{"always 24bit", []string{"--color", "always"}, "", "24bit", true, true},
		{"never with truecolor", []string{"--color", "never"}, "", "truecolor", false, false},
		{"auto non-terminal", []string{"--color", "auto"}, "", "truecolor", false, false},
		{"mono theme always", []string{"--color", "always", "--theme", "mono"}, "", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tt.noColor)
			t.Setenv("COLORTERM", tt.colorTerm)
			args := append([]string{"highlight"}, tt.args...)
			out, _, err := runHighlight(t, append(args, "SELECT 1")...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := strings.Contains(out, "\x1b["); got != tt.wantColor {
				t.Fatalf("colored = %v, want %v: %q", got, tt.wantColor, out)
			}
			if got := strings.Contains(out, "38;2;"); got != tt.wantTrue {
				t.Fatalf("truecolor = %v, want %v: %q", got, tt.wantTrue, out)
			}
		})
	}
}

func TestResolveANSIColor(t *testing.T) {
	env := func(vals map[string]string) func(string) string {
		return func(k string) string { return vals[k] }
	}
	tests := []struct {
		name     string
		color    string
		tty      bool
		env      map[string]string
		wantOn   bool
		wantMode highlight.ColorMode
	}{
		{"auto tty", highlightColorAuto, true, nil, true, highlight.Color256},
		{"auto tty truecolor", highlightColorAuto, true, map[string]string{"COLORTERM": "truecolor"}, true, highlight.TrueColor},
		{"auto tty 24bit uppercase", highlightColorAuto, true, map[string]string{"COLORTERM": "24BIT"}, true, highlight.TrueColor},
		{"auto tty NO_COLOR", highlightColorAuto, true, map[string]string{"NO_COLOR": "1"}, false, highlight.NoColor},
		{"auto tty empty NO_COLOR", highlightColorAuto, true, map[string]string{"NO_COLOR": ""}, true, highlight.Color256},
		{"auto pipe", highlightColorAuto, false, nil, false, highlight.NoColor},
		{"always pipe NO_COLOR", highlightColorAlways, false, map[string]string{"NO_COLOR": "1"}, true, highlight.Color256},
		{"never tty", highlightColorNever, true, map[string]string{"COLORTERM": "truecolor"}, false, highlight.NoColor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			on, mode := resolveANSIColor(tt.color, tt.tty, env(tt.env))
			if on != tt.wantOn || mode != tt.wantMode {
				t.Fatalf("resolveANSIColor(%q, %v) = (%v, %v), want (%v, %v)", tt.color, tt.tty, on, mode, tt.wantOn, tt.wantMode)
			}
		})
	}
}

func TestWriteHighlightJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHighlightJSON(&buf, "", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "[]\n" {
		t.Fatalf("output = %q, want %q", buf.String(), "[]\n")
	}
}
