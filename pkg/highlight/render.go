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
	"fmt"
	"io"
	"strconv"
	"strings"
)

// walk calls fn for every run of src in order: gaps between spans as Plain,
// spans with their category. Spans that are out of range, empty, or overlap
// an earlier span are skipped, so renderers never panic on bad input and
// always reproduce src exactly.
func walk(src string, spans []Span, fn func(text string, c Category) error) error {
	cursor := 0
	for _, s := range spans {
		if s.Start < cursor || s.End > len(src) || s.Start >= s.End {
			continue
		}
		if s.Start > cursor {
			if err := fn(src[cursor:s.Start], Plain); err != nil {
				return err
			}
		}
		if err := fn(src[s.Start:s.End], s.Category); err != nil {
			return err
		}
		cursor = s.End
	}
	if cursor < len(src) {
		return fn(src[cursor:], Plain)
	}
	return nil
}

// ColorMode selects how ANSI output encodes colors.
type ColorMode int

const (
	// Color256 maps theme colors to the xterm 256-color palette. It is the
	// default and works in virtually every modern terminal.
	Color256 ColorMode = iota
	// TrueColor emits 24-bit colors. Use it when COLORTERM is "truecolor"
	// or "24bit".
	TrueColor
	// NoColor emits only bold, italic and underline attributes.
	NoColor
)

// ANSIOptions configures ANSI terminal rendering.
type ANSIOptions struct {
	// Theme supplies the styles. The zero Theme means DarkTheme.
	Theme Theme
	// Mode selects the color encoding. The zero value is Color256.
	Mode ColorMode
}

const ansiReset = "\x1b[0m"

// ANSI renders src with ANSI escape sequences for terminal display.
//
// Styles are reset before every newline and re-applied after it, so output
// stays correct when piped through head, grep or a pager.
func ANSI(src string, spans []Span, opts ANSIOptions) string {
	var b strings.Builder
	b.Grow(len(src) + len(spans)*12)
	_ = WriteANSI(&b, src, spans, opts)
	return b.String()
}

// WriteANSI is like ANSI but writes to w.
func WriteANSI(w io.Writer, src string, spans []Span, opts ANSIOptions) error {
	theme := opts.Theme
	if theme.Styles == nil {
		theme = DarkTheme()
	}
	var sgr [numCategories]string
	for c := Keyword; c < numCategories; c++ {
		sgr[c] = sgrFor(theme.Style(c), opts.Mode)
	}
	sw := stringWriter(w)
	return walk(src, spans, func(text string, c Category) error {
		seq := ""
		if c < numCategories {
			seq = sgr[c]
		}
		if seq == "" {
			_, err := sw.WriteString(text)
			return err
		}
		for {
			line, rest, more := strings.Cut(text, "\n")
			if line != "" {
				if _, err := sw.WriteString(seq + line + ansiReset); err != nil {
					return err
				}
			}
			if !more {
				return nil
			}
			if _, err := sw.WriteString("\n"); err != nil {
				return err
			}
			text = rest
		}
	})
}

// sgrFor builds the "\x1b[...m" sequence for a style, or "" for no styling.
func sgrFor(s Style, mode ColorMode) string {
	var params []string
	if s.Bold {
		params = append(params, "1")
	}
	if s.Italic {
		params = append(params, "3")
	}
	if s.Underline {
		params = append(params, "4")
	}
	if r, g, b, ok := parseHex(s.Color); ok && mode != NoColor {
		if mode == TrueColor {
			params = append(params, fmt.Sprintf("38;2;%d;%d;%d", r, g, b))
		} else {
			params = append(params, "38;5;"+strconv.Itoa(xterm256(r, g, b)))
		}
	}
	if len(params) == 0 {
		return ""
	}
	return "\x1b[" + strings.Join(params, ";") + "m"
}

// xterm256 returns the closest xterm 256-color index (6x6x6 cube or
// grayscale ramp) for an RGB color.
func xterm256(r, g, b uint8) int {
	levels := [6]int{0, 95, 135, 175, 215, 255}
	nearest := func(v uint8) int {
		best, bestD := 0, 1<<30
		for i, l := range levels {
			if d := abs(int(v) - l); d < bestD {
				best, bestD = i, d
			}
		}
		return best
	}
	ri, gi, bi := nearest(r), nearest(g), nearest(b)
	cube := 16 + 36*ri + 6*gi + bi
	cubeD := sq(int(r)-levels[ri]) + sq(int(g)-levels[gi]) + sq(int(b)-levels[bi])

	avg := (int(r) + int(g) + int(b)) / 3
	gi2 := (avg - 8) / 10
	if gi2 < 0 {
		gi2 = 0
	} else if gi2 > 23 {
		gi2 = 23
	}
	gray := 8 + gi2*10
	grayD := sq(int(r)-gray) + sq(int(g)-gray) + sq(int(b)-gray)
	if grayD < cubeD {
		return 232 + gi2
	}
	return cube
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func sq(v int) int { return v * v }

// DefaultClassPrefix is the CSS class prefix used by HTML and CSS when no
// prefix is given: spans render as <span class="gsx-keyword">.
const DefaultClassPrefix = "gsx-"

// HTMLOptions configures HTML rendering.
type HTMLOptions struct {
	// ClassPrefix prefixes category class names. Empty means
	// DefaultClassPrefix. Prefixes containing characters other than ASCII
	// letters, digits, '-' and '_' are replaced by DefaultClassPrefix.
	ClassPrefix string
	// InlineStyles emits style="..." attributes from Theme instead of class
	// names, for contexts without a stylesheet (e-mail, Markdown exports).
	InlineStyles bool
	// Theme supplies styles when InlineStyles is set. The zero Theme means
	// DarkTheme.
	Theme Theme
	// Wrap encloses the output in <pre class="{prefix}highlight"><code>.
	Wrap bool
}

var htmlEscaper = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;",
)

// HTML renders src as HTML. All source text is escaped; only <span>
// elements (and the optional <pre><code> wrapper) are emitted.
func HTML(src string, spans []Span, opts HTMLOptions) string {
	var b strings.Builder
	b.Grow(len(src) + len(spans)*32)
	_ = WriteHTML(&b, src, spans, opts)
	return b.String()
}

// WriteHTML is like HTML but writes to w.
func WriteHTML(w io.Writer, src string, spans []Span, opts HTMLOptions) error {
	prefix := sanitizePrefix(opts.ClassPrefix)
	theme := opts.Theme
	if theme.Styles == nil {
		theme = DarkTheme()
	}
	var open [numCategories]string
	for c := Keyword; c < numCategories; c++ {
		if opts.InlineStyles {
			if css := cssDecl(theme.Style(c)); css != "" {
				open[c] = `<span style="` + css + `">`
			}
		} else {
			open[c] = `<span class="` + prefix + c.String() + `">`
		}
	}

	sw := stringWriter(w)
	if opts.Wrap {
		if _, err := sw.WriteString(`<pre class="` + prefix + `highlight"><code>`); err != nil {
			return err
		}
	}
	err := walk(src, spans, func(text string, c Category) error {
		tag := ""
		if c < numCategories {
			tag = open[c]
		}
		if tag != "" {
			if _, err := sw.WriteString(tag); err != nil {
				return err
			}
		}
		if _, err := htmlEscaper.WriteString(w, text); err != nil {
			return err
		}
		if tag != "" {
			_, err := sw.WriteString("</span>")
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if opts.Wrap {
		_, err = sw.WriteString("</code></pre>")
	}
	return err
}

// CSS returns a stylesheet with one rule per category for the class names
// emitted by HTML, e.g. ".gsx-keyword{color:#569CD6;font-weight:bold}".
//
// The zero Theme means DarkTheme, as for HTML and ANSI.
func CSS(theme Theme, classPrefix string) string {
	if theme.Styles == nil {
		theme = DarkTheme()
	}
	prefix := sanitizePrefix(classPrefix)
	var b strings.Builder
	for c := Keyword; c < numCategories; c++ {
		if decl := cssDecl(theme.Style(c)); decl != "" {
			b.WriteString("." + prefix + c.String() + "{" + decl + "}\n")
		}
	}
	return b.String()
}

func cssDecl(s Style) string {
	var parts []string
	if r, g, b, ok := parseHex(s.Color); ok {
		parts = append(parts, fmt.Sprintf("color:#%02X%02X%02X", r, g, b))
	}
	if s.Bold {
		parts = append(parts, "font-weight:bold")
	}
	if s.Italic {
		parts = append(parts, "font-style:italic")
	}
	if s.Underline {
		parts = append(parts, "text-decoration:underline")
	}
	return strings.Join(parts, ";")
}

func sanitizePrefix(p string) string {
	if p == "" {
		return DefaultClassPrefix
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return DefaultClassPrefix
		}
	}
	return p
}

func stringWriter(w io.Writer) io.StringWriter {
	if sw, ok := w.(io.StringWriter); ok {
		return sw
	}
	return stringWriterAdapter{w}
}

type stringWriterAdapter struct{ w io.Writer }

func (a stringWriterAdapter) WriteString(s string) (int, error) {
	return a.w.Write([]byte(s))
}
