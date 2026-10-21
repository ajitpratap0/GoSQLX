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
	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
)

// Highlight classifies sql for syntax highlighting and returns the spans.
//
// This is a convenience wrapper around highlight.Spans. Each span is a 0-based
// byte range [Start, End) of sql tagged with a category such as keyword,
// function, string or comment; spans are sorted, never overlap, and any byte
// not covered by a span (typically whitespace) is plain text.
//
// Highlight never fails: invalid SQL is highlighted up to the first lexical
// error and the remainder is covered by a single Error span, so it is safe to
// call on incomplete editor input. Use highlight.WithDialect to apply
// dialect-specific keywords and quoting; unknown dialects fall back to the
// default.
//
// Thread Safety: safe for concurrent use.
//
// Example:
//
//	sql := "SELECT id FROM users"
//	for _, s := range gosqlx.Highlight(sql, highlight.WithDialect(keywords.DialectMySQL)) {
//	    fmt.Printf("%-10s %q\n", s.Category, s.Text(sql))
//	}
func Highlight(sql string, opts ...highlight.Option) []highlight.Span {
	return highlight.Spans(sql, opts...)
}

// HighlightANSI returns sql colored with ANSI escape sequences for terminal
// display, using the dark theme and the xterm 256-color palette.
//
// Styles are reset before each newline, so the output stays correct when
// piped through tools such as head or less -R. For another theme or true
// color output, call highlight.ANSI with Highlight's spans directly.
//
// Thread Safety: safe for concurrent use.
//
// Example:
//
//	fmt.Println(gosqlx.HighlightANSI("SELECT * FROM users WHERE id = 1"))
func HighlightANSI(sql string, opts ...highlight.Option) string {
	return highlight.ANSI(sql, Highlight(sql, opts...), highlight.ANSIOptions{
		Theme: highlight.DarkTheme(),
		Mode:  highlight.Color256,
	})
}

// HighlightHTML returns sql as escaped HTML wrapped in
// <pre class="gsx-highlight"><code>...</code></pre>, with every token in a
// <span class="gsx-<category>"> element (for example gsx-keyword or
// gsx-string).
//
// All source text is HTML-escaped. Pair the output with a stylesheet from
// highlight.CSS, or call highlight.HTML directly for inline styles or a
// custom class prefix.
//
// Thread Safety: safe for concurrent use.
//
// Example:
//
//	html := gosqlx.HighlightHTML("SELECT 1")
//	css := highlight.CSS(highlight.DarkTheme(), "")
//	page := "<style>" + css + "</style>" + html
func HighlightHTML(sql string, opts ...highlight.Option) string {
	return highlight.HTML(sql, Highlight(sql, opts...), highlight.HTMLOptions{
		Wrap: true,
	})
}
