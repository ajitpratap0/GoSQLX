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

package gosqlx

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestHighlight_MatchesSpans(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		opts []highlight.Option
	}{
		{"simple select", "SELECT id, name FROM users WHERE active = TRUE", nil},
		{"function and comment", "SELECT COUNT(*) FROM t -- total", nil},
		{"mysql backticks", "SELECT `a` FROM t", []highlight.Option{highlight.WithDialect(keywords.DialectMySQL)}},
		{"invalid sql", "SELECT 'unterminated", nil},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Highlight(tt.sql, tt.opts...)
			want := highlight.Spans(tt.sql, tt.opts...)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Highlight(%q) = %v, want %v", tt.sql, got, want)
			}
		})
	}
}

func TestHighlight_Categories(t *testing.T) {
	sql := "SELECT name, COUNT(*) FROM users WHERE id = 42 AND note = 'x' -- c"
	want := map[string]highlight.Category{
		"SELECT": highlight.Keyword,
		"name":   highlight.Identifier,
		"COUNT":  highlight.Function,
		"42":     highlight.Number,
		"'x'":    highlight.String,
		"-- c":   highlight.Comment,
	}
	got := map[string]highlight.Category{}
	for _, s := range Highlight(sql) {
		got[s.Text(sql)] = s.Category
	}
	for text, cat := range want {
		if got[text] != cat {
			t.Errorf("category of %q = %v, want %v", text, got[text], cat)
		}
	}
}

func TestHighlight_InvalidSQLMarksError(t *testing.T) {
	sql := "SELECT 'unterminated"
	spans := Highlight(sql)
	if len(spans) == 0 {
		t.Fatal("expected spans for invalid SQL")
	}
	last := spans[len(spans)-1]
	if last.Category != highlight.Error || last.End != len(sql) {
		t.Fatalf("last span = %+v, want Error span ending at %d", last, len(sql))
	}
	if spans[0].Category != highlight.Keyword {
		t.Errorf("first span = %+v, want keyword", spans[0])
	}
}

func TestHighlightANSI(t *testing.T) {
	sql := "SELECT id FROM users"
	got := HighlightANSI(sql)
	want := highlight.ANSI(sql, highlight.Spans(sql), highlight.ANSIOptions{
		Theme: highlight.DarkTheme(),
		Mode:  highlight.Color256,
	})
	if got != want {
		t.Fatalf("HighlightANSI = %q, want %q", got, want)
	}
	if !strings.Contains(got, "\x1b[") || !strings.Contains(got, "\x1b[0m") {
		t.Errorf("expected ANSI escape sequences, got %q", got)
	}
	if strings.Contains(got, "38;2;") {
		t.Errorf("expected 256-color sequences, got true color: %q", got)
	}
	if stripANSI(got) != sql {
		t.Errorf("stripped output = %q, want %q", stripANSI(got), sql)
	}
}

func TestHighlightANSI_Empty(t *testing.T) {
	if got := HighlightANSI(""); got != "" {
		t.Fatalf("HighlightANSI(\"\") = %q, want empty", got)
	}
}

func TestHighlightHTML(t *testing.T) {
	sql := "SELECT a FROM t WHERE b < 'x&y'"
	got := HighlightHTML(sql)
	if !strings.HasPrefix(got, `<pre class="gsx-highlight"><code>`) || !strings.HasSuffix(got, "</code></pre>") {
		t.Fatalf("expected <pre><code> wrapper, got %q", got)
	}
	for _, sub := range []string{
		`<span class="gsx-keyword">SELECT</span>`,
		`<span class="gsx-operator">&lt;</span>`,
		`<span class="gsx-string">&#39;x&amp;y&#39;</span>`,
	} {
		if !strings.Contains(got, sub) {
			t.Errorf("HighlightHTML output missing %q:\n%s", sub, got)
		}
	}
	if strings.Contains(got, "style=") {
		t.Errorf("expected class-based output, got inline styles: %q", got)
	}
}

func TestHighlightHTML_WithDialect(t *testing.T) {
	sql := "SELECT `a` FROM t"
	got := HighlightHTML(sql, highlight.WithDialect(keywords.DialectMySQL))
	if !strings.Contains(got, `<span class="gsx-quoted-identifier">`+"`a`</span>") {
		t.Fatalf("expected quoted identifier span under mysql, got %q", got)
	}
}

func TestHighlight_Concurrent(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = $1"
	want := HighlightHTML(sql)
	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := HighlightHTML(sql); got != want {
				errs <- got
			}
			_ = HighlightANSI(sql)
		}()
	}
	wg.Wait()
	close(errs)
	for got := range errs {
		t.Errorf("concurrent HighlightHTML = %q, want %q", got, want)
	}
}

// stripANSI removes SGR escape sequences ("\x1b[...m") from s.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
