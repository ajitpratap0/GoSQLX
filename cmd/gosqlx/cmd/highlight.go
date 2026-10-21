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
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Output formats accepted by the highlight command.
const (
	highlightFormatANSI = "ansi"
	highlightFormatHTML = "html"
	highlightFormatJSON = "json"
	highlightFormatCSS  = "css"
)

// Color modes accepted by the highlight command's --color flag.
const (
	highlightColorAuto   = "auto"
	highlightColorAlways = "always"
	highlightColorNever  = "never"
)

var (
	highlightFormats    = []string{highlightFormatANSI, highlightFormatHTML, highlightFormatJSON, highlightFormatCSS}
	highlightColorModes = []string{highlightColorAuto, highlightColorAlways, highlightColorNever}
)

var (
	highlightOutputFormat string
	highlightTheme        string
	highlightDialect      string
	highlightColor        string
	highlightStandalone   bool
)

// highlightCmd represents the highlight command
var highlightCmd = &cobra.Command{
	Use:     "highlight [file|query]",
	Aliases: []string{"hl"},
	Short:   "Syntax-highlight SQL for terminals, HTML or editors",
	Long: `Syntax-highlight SQL as ANSI terminal colors, HTML, or JSON spans.

Highlighting is lexical and never fails: invalid SQL is highlighted up to the
first lexical error and the rest is marked as an error.

Examples:
  gosqlx highlight query.sql                         # Colored output in the terminal
  gosqlx hl "SELECT * FROM users WHERE id = 1"       # Highlight a query directly
  gosqlx highlight --theme light query.sql           # Theme for light terminals
  gosqlx highlight --color always query.sql | less -R
  gosqlx highlight -f html query.sql                 # HTML fragment (class-based)
  gosqlx highlight -f html --standalone -o out.html query.sql
  gosqlx highlight -f json query.sql                 # Spans for editors/tools
  gosqlx highlight -f css --theme dark               # Stylesheet for -f html output
  gosqlx highlight --dialect mysql query.sql         # Dialect-specific keywords

Pipeline/Stdin Examples:
  echo "SELECT 1" | gosqlx highlight                 # Highlight stdin (auto-detect)
  gosqlx highlight -                                 # Explicit stdin marker
  gosqlx highlight < query.sql                       # Input redirection

Formats:
  ansi  ANSI escape sequences (default). --color controls coloring: auto colors
        only when stdout is a terminal and NO_COLOR is unset; never prints the
        SQL unchanged. 24-bit color is used when COLORTERM is truecolor or 24bit.
  html  <pre class="gsx-highlight"><code> with <span class="gsx-<category>">
        elements. --standalone emits a complete HTML document with an inline
        stylesheet for --theme.
  json  Array of {start, end, category, text, line, column}. start/end are
        0-based byte offsets (end exclusive); line and column are 1-based, with
        column counted in bytes.
  css   Stylesheet for --theme matching the html class names (no input read).

Themes: dark (default), light, mono`,
	Args: cobra.MaximumNArgs(1),
	RunE: highlightRun,
}

// highlightConfig is the validated configuration of one highlight run.
type highlightConfig struct {
	format     string
	theme      highlight.Theme
	dialect    string
	color      string
	standalone bool
}

func highlightRun(cmd *cobra.Command, args []string) error {
	cfg, err := newHighlightConfig(highlightOutputFormat, highlightTheme, highlightDialect, highlightColor, highlightStandalone)
	if err != nil {
		return err
	}

	// The stylesheet does not depend on the input.
	if cfg.format == highlightFormatCSS {
		return WriteOutput([]byte(highlight.CSS(cfg.theme, "")), outputFile, cmd.OutOrStdout())
	}

	input, err := readHighlightInput(args)
	if err != nil {
		return err
	}

	tty := outputFile == "" && isTerminalWriter(cmd.OutOrStdout())
	out, err := renderHighlight(string(input.Content), input, cfg, tty, os.Getenv)
	if err != nil {
		return err
	}
	return WriteOutput(out, outputFile, cmd.OutOrStdout())
}

// newHighlightConfig validates the highlight flags.
func newHighlightConfig(format, theme, dialect, color string, standalone bool) (highlightConfig, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if !containsString(highlightFormats, format) {
		return highlightConfig{}, fmt.Errorf("invalid format %q; valid formats: %s", format, strings.Join(highlightFormats, ", "))
	}
	th, ok := highlight.ThemeByName(strings.TrimSpace(theme))
	if !ok {
		return highlightConfig{}, fmt.Errorf("unknown theme %q; valid themes: %s", theme, strings.Join(highlight.ThemeNames(), ", "))
	}
	if err := validateDialectName(dialect); err != nil {
		return highlightConfig{}, err
	}
	color = strings.ToLower(strings.TrimSpace(color))
	if !containsString(highlightColorModes, color) {
		return highlightConfig{}, fmt.Errorf("invalid color mode %q; valid modes: %s", color, strings.Join(highlightColorModes, ", "))
	}
	if standalone && format != highlightFormatHTML {
		return highlightConfig{}, fmt.Errorf("--standalone requires --format html")
	}
	return highlightConfig{format: format, theme: th, dialect: dialect, color: color, standalone: standalone}, nil
}

// readHighlightInput reads the SQL to highlight from stdin ("-" or piped with
// no argument), a file, or an inline query, applying the shared size, path
// and binary-content checks.
func readHighlightInput(args []string) (*InputResult, error) {
	if len(args) == 0 || args[0] == "-" {
		if !ShouldReadFromStdin(args) {
			return nil, fmt.Errorf("no input provided: specify file path, SQL query, or pipe via stdin")
		}
		content, err := ReadFromStdin()
		if err != nil {
			return nil, fmt.Errorf("failed to read from stdin: %w", err)
		}
		if err := ValidateStdinInput(content); err != nil {
			return nil, fmt.Errorf("stdin validation failed: %w", err)
		}
		return &InputResult{Type: InputTypeSQL, Content: content, Source: "stdin"}, nil
	}

	input, err := GetInputSource(args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}
	return input, nil
}

// renderHighlight highlights sql and renders it in cfg.format. tty reports
// whether the output is an interactive terminal; getenv supplies NO_COLOR and
// COLORTERM. The result always ends with a newline.
func renderHighlight(sql string, input *InputResult, cfg highlightConfig, tty bool, getenv func(string) string) ([]byte, error) {
	var opts []highlight.Option
	if cfg.dialect != "" {
		opts = append(opts, highlight.WithDialect(keywords.SQLDialect(cfg.dialect)))
	}
	spans := highlight.Spans(sql, opts...)

	var buf bytes.Buffer
	switch cfg.format {
	case highlightFormatANSI:
		enabled, mode := resolveANSIColor(cfg.color, tty, getenv)
		if !enabled {
			buf.WriteString(sql)
			break
		}
		if err := highlight.WriteANSI(&buf, sql, spans, highlight.ANSIOptions{Theme: cfg.theme, Mode: mode}); err != nil {
			return nil, fmt.Errorf("failed to render ANSI output: %w", err)
		}
	case highlightFormatHTML:
		if err := writeHighlightHTML(&buf, sql, spans, input, cfg); err != nil {
			return nil, fmt.Errorf("failed to render HTML output: %w", err)
		}
	case highlightFormatJSON:
		if err := writeHighlightJSON(&buf, sql, spans); err != nil {
			return nil, fmt.Errorf("failed to render JSON output: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid format %q", cfg.format)
	}

	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// resolveANSIColor decides whether ANSI output is colored and with which
// color encoding. "auto" colors only when tty is true and NO_COLOR is unset or
// empty (https://no-color.org); "always" ignores both. 24-bit color is used
// when COLORTERM is "truecolor" or "24bit".
func resolveANSIColor(color string, tty bool, getenv func(string) string) (bool, highlight.ColorMode) {
	switch color {
	case highlightColorNever:
		return false, highlight.NoColor
	case highlightColorAuto:
		if !tty || getenv("NO_COLOR") != "" {
			return false, highlight.NoColor
		}
	}
	switch strings.ToLower(getenv("COLORTERM")) {
	case "truecolor", "24bit":
		return true, highlight.TrueColor
	}
	return true, highlight.Color256
}

// standalonePalette is the page background and default foreground used by
// --standalone for each built-in theme.
var standalonePalette = map[string][2]string{
	"dark":  {"#1E1E1E", "#D4D4D4"},
	"light": {"#FFFFFF", "#000000"},
	"mono":  {"#FFFFFF", "#000000"},
}

// writeHighlightHTML writes the class-based HTML fragment, or a complete
// document with an inline stylesheet when cfg.standalone is set.
func writeHighlightHTML(w *bytes.Buffer, sql string, spans []highlight.Span, input *InputResult, cfg highlightConfig) error {
	htmlOpts := highlight.HTMLOptions{Wrap: true}
	if !cfg.standalone {
		return highlight.WriteHTML(w, sql, spans, htmlOpts)
	}

	colors, ok := standalonePalette[cfg.theme.Name]
	if !ok {
		colors = standalonePalette["dark"]
	}
	title := "SQL"
	if input != nil && input.Type == InputTypeFile {
		title = filepath.Base(input.Source)
	}

	w.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	w.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	w.WriteString("<title>" + html.EscapeString(title) + "</title>\n<style>\n")
	fmt.Fprintf(w, "body{margin:0;background:%s;color:%s}\n", colors[0], colors[1])
	fmt.Fprintf(w, ".%shighlight{margin:0;padding:1em;background:%s;color:%s;"+
		"font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"+
		"font-size:14px;line-height:1.5;overflow:auto}\n", highlight.DefaultClassPrefix, colors[0], colors[1])
	w.WriteString(highlight.CSS(cfg.theme, ""))
	w.WriteString("</style>\n</head>\n<body>\n")
	if err := highlight.WriteHTML(w, sql, spans, htmlOpts); err != nil {
		return err
	}
	w.WriteString("\n</body>\n</html>\n")
	return nil
}

// highlightJSONSpan is one span in --format json output. Line and Column are
// 1-based; Column counts bytes from the start of the line.
type highlightJSONSpan struct {
	Start    int                `json:"start"`
	End      int                `json:"end"`
	Category highlight.Category `json:"category"`
	Text     string             `json:"text"`
	Line     int                `json:"line"`
	Column   int                `json:"column"`
}

// writeHighlightJSON writes spans as a pretty-printed JSON array.
func writeHighlightJSON(w io.Writer, sql string, spans []highlight.Span) error {
	starts := []int{0}
	for i := 0; i < len(sql); i++ {
		if sql[i] == '\n' {
			starts = append(starts, i+1)
		}
	}

	out := make([]highlightJSONSpan, 0, len(spans))
	for _, s := range spans {
		// Index of the last line starting at or before s.Start.
		line := sort.Search(len(starts), func(i int) bool { return starts[i] > s.Start }) - 1
		if line < 0 {
			line = 0
		}
		out = append(out, highlightJSONSpan{
			Start:    s.Start,
			End:      s.End,
			Category: s.Category,
			Text:     s.Text(sql),
			Line:     line + 1,
			Column:   s.Start - starts[line] + 1,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("failed to encode spans: %w", err)
	}
	return nil
}

// isTerminalWriter reports whether w is a file attached to a terminal.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd())) // #nosec G115
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func init() {
	rootCmd.AddCommand(highlightCmd)

	highlightCmd.Flags().StringVarP(&highlightOutputFormat, "format", "f", highlightFormatANSI, "output format: ansi, html, json, css")
	highlightCmd.Flags().StringVar(&highlightTheme, "theme", "dark", "color theme: "+strings.Join(highlight.ThemeNames(), ", "))
	highlightCmd.Flags().StringVar(&highlightDialect, "dialect", "", "SQL dialect: generic, postgresql, mysql, mariadb, sqlserver, oracle, sqlite, snowflake, bigquery, redshift, clickhouse (default: generic keyword set)")
	highlightCmd.Flags().StringVar(&highlightColor, "color", highlightColorAuto, "ANSI coloring: auto, always, never (ansi format only)")
	highlightCmd.Flags().BoolVar(&highlightStandalone, "standalone", false, "emit a complete HTML document with an inline stylesheet (html format only)")
}
