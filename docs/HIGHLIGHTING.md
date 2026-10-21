# SQL Syntax Highlighting

GoSQLX highlights SQL for terminals, web pages and editors. The same classifier
drives the `pkg/highlight` Go package, the `gosqlx highlight` CLI command, the
LSP server's semantic tokens and the WASM build behind the
[gosqlx.dev playground](https://gosqlx.dev/playground/).

## Table of Contents

- [Overview](#overview)
- [Categories](#categories)
- [Go Usage](#go-usage)
- [Error Tolerance](#error-tolerance)
- [Dialects](#dialects)
- [CLI](#cli)
- [Language Server](#language-server)
- [WASM and JavaScript](#wasm-and-javascript)
- [Performance](#performance)
- [Limitations](#limitations)

## Overview

`highlight.Spans` runs the GoSQLX tokenizer over the input and tags each token
with a `Category`. The result is a slice of `Span` values:

```go
type Span struct {
    Start    int      `json:"start"`    // byte offset, inclusive
    End      int      `json:"end"`      // byte offset, exclusive
    Category Category `json:"category"`
}
```

Spans are sorted by `Start`, never overlap and never carry `Plain`. Bytes not
covered by a span, usually whitespace, are plain text. Offsets are 0-based byte
offsets into the source string, and `Span.Text(src)` returns the covered text.
Block comments and multi-line strings produce a single span that crosses line
breaks. Tabs are fully supported: each tab is one byte, and offsets never depend
on tab width.

Renderers turn spans into output:

| Renderer | Output |
|----------|--------|
| `ANSI` / `WriteANSI` | Terminal escape sequences: 256-color, 24-bit color, or attributes only |
| `HTML` / `WriteHTML` | Escaped HTML with `class="gsx-<category>"` spans, or inline styles |
| `CSS` | A stylesheet matching the HTML class names for a theme |

Spans also marshal to JSON as `{"start":0,"end":6,"category":"keyword"}`.

## Categories

Category names are stable. They are used as JSON values, HTML class suffixes
and theme keys, and will not change. New categories may be added later.

| Name | Go constant | Examples |
|------|-------------|----------|
| `keyword` | `Keyword` | `SELECT`, `FROM`, `RETURNING`, `LATERAL` |
| `function` | `Function` | `COUNT` in `COUNT(*)`, `now` in `now()` |
| `type` | `DataType` | `VARCHAR` in a column definition, `int` in `x::int`, `DATE` in `CAST(x AS DATE)` |
| `identifier` | `Identifier` | `users`, `id`, aliases (each part of `u.id`) |
| `quoted-identifier` | `QuotedIdentifier` | `"Order"`, `` `order` ``, `[order]` |
| `string` | `String` | `'abc'`, `N'abc'`, `E'\n'`, `X'1F'`, `$$body$$` |
| `number` | `Number` | `42`, `3.14`, `1e10`, `0x1F` |
| `constant` | `Constant` | `TRUE`, `FALSE`, `NULL` |
| `operator` | `Operator` | `=`, `<>`, `\|\|`, `->>`, `::`, `*` |
| `punctuation` | `Punctuation` | `,` `.` `;` `(` `)` `[` `]` |
| `comment` | `Comment` | `-- note`, `/* block */` |
| `placeholder` | `Placeholder` | `$1`, `?`, `:name`, `@var`, `@@var` |
| `error` | `Error` | the rest of the input after a lexical error |

`highlight.Categories()` lists them in this order, and
`highlight.ParseCategory(name)` maps a name back to its constant.

## Go Usage

### Spans

```go
import (
    "fmt"

    "github.com/ajitpratap0/GoSQLX/pkg/highlight"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

sql := "SELECT name FROM users WHERE id = $1 -- by id"
for _, s := range highlight.Spans(sql, highlight.WithDialect(keywords.DialectPostgreSQL)) {
    fmt.Printf("%-11s %s\n", s.Category, s.Text(sql))
}
// keyword     SELECT
// identifier  name
// keyword     FROM
// identifier  users
// keyword     WHERE
// identifier  id
// operator    =
// placeholder $1
// comment     -- by id
```

`Spans` is safe for concurrent use and needs no cleanup: it takes and returns
its pooled tokenizer internally.

The high-level `gosqlx` package wraps the common cases:

```go
spans := gosqlx.Highlight(sql)     // []highlight.Span
term  := gosqlx.HighlightANSI(sql) // dark theme, 256 colors
html  := gosqlx.HighlightHTML(sql) // <pre class="gsx-highlight"><code>...</code></pre>
```

All three accept `highlight.Option` values such as
`highlight.WithDialect(keywords.DialectMySQL)`. For other themes, color modes
or inline styles, pass the spans to the renderers below.

### Terminal output

```go
spans := highlight.Spans(sql)

// 256-color, dark theme (the zero ANSIOptions).
fmt.Println(highlight.ANSI(sql, spans, highlight.ANSIOptions{}))

// 24-bit color with the light theme, written straight to stdout.
err := highlight.WriteANSI(os.Stdout, sql, spans, highlight.ANSIOptions{
    Theme: highlight.LightTheme(),
    Mode:  highlight.TrueColor,
})
if err != nil {
    return fmt.Errorf("write highlighted SQL: %w", err)
}
```

`ColorMode` is `Color256` (default), `TrueColor` or `NoColor`. `NoColor` keeps
bold, italic and underline only. Styles are reset before each newline and
re-applied after it, so output stays correct through `head`, `grep` or a pager.

**Untrusted input.** `ANSI` and `WriteANSI` never copy terminal control
characters from the source, so a string literal or comment cannot inject
escape sequences. C0 controls other than tab, newline and carriage return are
shown as Unicode control pictures (ESC becomes U+241B), DEL as U+2421, and C1
controls and invalid UTF-8 as U+FFFD. The rendered text therefore differs from
the input only where it contained such characters. HTML output is escaped.

### HTML and CSS

```go
sql := "SELECT 'a' AS x"
fmt.Println(highlight.HTML(sql, highlight.Spans(sql), highlight.HTMLOptions{}))
// <span class="gsx-keyword">SELECT</span> <span class="gsx-string">&#39;a&#39;</span> <span class="gsx-keyword">AS</span> <span class="gsx-identifier">x</span>
```

All source text is HTML-escaped; only `<span>` elements are emitted.
`HTMLOptions` fields:

| Field | Effect |
|-------|--------|
| `ClassPrefix` | Class name prefix. Empty means `highlight.DefaultClassPrefix` (`"gsx-"`). Prefixes with characters other than ASCII letters, digits, `-` and `_` fall back to the default. |
| `InlineStyles` | Emit `style="..."` from `Theme` instead of classes, for e-mail or Markdown exports. |
| `Theme` | Styles for `InlineStyles`. The zero `Theme` means `DarkTheme()`. |
| `Wrap` | Enclose the output in `<pre class="{prefix}highlight"><code>...</code></pre>`, where `{prefix}` is the effective class prefix: `gsx-` by default, so `<pre class="gsx-highlight">`, or your `ClassPrefix` when set. |

With class names, generate the matching stylesheet once and serve it with the
page:

```go
css := highlight.CSS(highlight.DarkTheme(), "") // "" uses the gsx- prefix
// .gsx-keyword{color:#569CD6;font-weight:bold}
// .gsx-function{color:#DCDCAA}
// ...
```

`CSS` styles the token classes only; set the background and font on
`.gsx-highlight` yourself.

### Themes

| Name | Constructor | Use |
|------|-------------|-----|
| `dark` | `highlight.DarkTheme()` | Default; dark backgrounds |
| `light` | `highlight.LightTheme()` | Light backgrounds |
| `mono` | `highlight.MonoTheme()` | No color: bold keywords and functions, italic comments, underlined errors |

`highlight.ThemeByName(name)` looks a theme up case-insensitively and returns
`(Theme, bool)`; `highlight.ThemeNames()` returns `["dark", "light", "mono"]`.
Each constructor returns a fresh copy, so you can change it.

### Custom theme

A `Theme` maps categories to a `Style{Color, Bold, Italic, Underline}`. Colors
are `"#RRGGBB"` or `"#RGB"`; anything else is ignored, so a theme can never
inject CSS or escape sequences. Categories without an entry use the default
foreground.

```go
theme := highlight.DarkTheme()
theme.Name = "brand"
theme.Styles[highlight.Keyword] = highlight.Style{Color: "#FF7A00", Bold: true}
theme.Styles[highlight.Comment] = highlight.Style{Color: "#808080", Italic: true}

term := highlight.ANSI(sql, spans, highlight.ANSIOptions{Theme: theme})
css := highlight.CSS(theme, "sql-") // .sql-keyword{color:#FF7A00;font-weight:bold} ...
html := highlight.HTML(sql, spans, highlight.HTMLOptions{ClassPrefix: "sql-", Wrap: true})
```

## Error Tolerance

`Spans` never returns an error, because editor input is incomplete most of the
time. Lexical errors are handled the same way for every kind of unterminated
literal or comment: everything before the offending position is still
classified, and the rest of the input becomes one `error` span that runs to the
end of the input:

- unterminated string literals, such as `'abc`
- unterminated quoted identifiers, such as `"name` or `` `name ``
- unterminated dollar-quoted strings, such as `$$body`
- unterminated block comments, such as `/* note`

```go
sql := "SELECT 'unterminated FROM t"
for _, s := range highlight.Spans(sql) {
    fmt.Printf("%-8s %q\n", s.Category, s.Text(sql))
}
// keyword  "SELECT"
// error    "'unterminated FROM t"
```

Inputs the tokenizer refuses outright yield no spans, so they render as plain
text. This covers input over the tokenizer's 10 MB size limit (`MaxInputSize`)
and input with more than 1,000,000 tokens, where comments count toward the
token limit (`MaxTokens`). The CLI rejects files over 10 MB before it
highlights them. Renderers skip out-of-range or overlapping spans, so they
always reproduce the source exactly.

## Dialects

`highlight.WithDialect` selects the dialect used for tokenization and keyword
recognition. With no dialect, highlighting uses the generic keyword set. An
unknown or empty dialect falls back to the same generic set.

```go
spans := highlight.Spans(sql, highlight.WithDialect(keywords.DialectMySQL))
```

Accepted dialect names, as listed by `keywords.AllDialects()`, are `generic`,
`postgresql`, `mysql`, `mariadb`, `sqlserver`, `oracle`, `sqlite`, `snowflake`,
`bigquery`, `redshift` and `clickhouse`. The CLI `--dialect` flag and the LSP
`initializationOptions.dialect` setting take the same names.

The dialect changes classification where the languages differ, for example:

- MySQL and MariaDB: `"text"` is a string; `` `name` `` is a quoted identifier.
- SQL Server: `[name]` is a quoted identifier. In other dialects `[` and `]`
  are punctuation.
- Keywords come from the selected dialect's keyword table.

## CLI

```bash
gosqlx highlight "SELECT id FROM users WHERE active = TRUE"
gosqlx highlight query.sql
cat query.sql | gosqlx hl                            # stdin; hl is an alias

gosqlx highlight --theme light query.sql
gosqlx highlight --dialect mysql query.sql
gosqlx highlight -f html --standalone query.sql > query.html
gosqlx highlight -f css --theme dark > gosqlx.css  # reads no input
gosqlx highlight -f json "SELECT 1"
```

| Flag | Values | Default |
|------|--------|---------|
| `--format`, `-f` | `ansi`, `html`, `json`, `css` | `ansi` |
| `--theme` | `dark`, `light`, `mono` | `dark` |
| `--dialect` | `generic`, `postgresql`, `mysql`, `mariadb`, `sqlserver`, `oracle`, `sqlite`, `snowflake`, `bigquery`, `redshift`, `clickhouse` | generic keyword set |
| `--color` | `auto`, `always`, `never` (ANSI only) | `auto` |
| `--standalone` | full HTML page with inline CSS (with `-f html`) | off |

`--color auto` colors output only when stdout is a terminal and `NO_COLOR` is
unset. `COLORTERM=truecolor` or `COLORTERM=24bit` selects 24-bit color;
otherwise the 256-color palette is used.

`-f json` prints one object per span, adding the span text and the 1-based
line and column of its start (column counted in bytes). `gosqlx highlight -f
json "SELECT 1"` prints:

```json
[
  {
    "start": 0,
    "end": 6,
    "category": "keyword",
    "text": "SELECT",
    "line": 1,
    "column": 1
  },
  {
    "start": 7,
    "end": 8,
    "category": "number",
    "text": "1",
    "line": 1,
    "column": 8
  }
]
```

Input with no spans, such as input over the tokenizer limits, prints `[]`.

## Language Server

`gosqlx lsp` answers `textDocument/semanticTokens/full` from `pkg/highlight`,
so editors get the same classification as the CLI, including every dialect
keyword and all comments. It uses the standard LSP token types:

| LSP token type | Categories |
|----------------|------------|
| `keyword` | `keyword`; `constant` with the `readonly` modifier |
| `function` | `function` |
| `type` | `type` |
| `variable` | `identifier`, `quoted-identifier` |
| `string` | `string` |
| `number` | `number` |
| `operator` | `operator` |
| `comment` | `comment` |
| `parameter` | `placeholder` |

Punctuation is not reported, and lexical errors appear as diagnostics instead
of tokens. Positions are UTF-16, as LSP requires, and multi-line tokens are
split into one token per line. See the [LSP Guide](LSP_GUIDE.md#semantic-tokens).

## WASM and JavaScript

The WASM build exports `gosqlxHighlight(sql[, dialect])`. It returns a JSON
string whose offsets are UTF-16 code units, so they index JavaScript strings
directly:

```js
const { spans } = JSON.parse(gosqlxHighlight(sql, "postgresql"));
const escape = (s) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
let html = "", pos = 0;
for (const { start, end, category } of spans) {
  html += escape(sql.slice(pos, start));
  html += `<span class="gsx-${category}">${escape(sql.slice(start, end))}</span>`;
  pos = end;
}
html += escape(sql.slice(pos));
```

The result has the shape `{"spans":[{"start":0,"end":6,"category":"keyword"}]}`.
The [gosqlx.dev playground](https://gosqlx.dev/playground/) uses it for editor
highlighting.

## Performance

Highlighting is one tokenizer pass plus classification. `BenchmarkSpans` (about
2 KB of SQL) takes about 45 µs per call on an Apple M4 (45 MB/s, 282 allocations).
Measure on your own hardware with:

```bash
go test -run '^$' -bench 'BenchmarkSpans|BenchmarkHTML' -benchmem ./pkg/highlight/
```

## Limitations

- Classification is lexical with light context, not a full parse. Function
  names are found in call position, type names in type position (column
  definitions, `x::int`, `CAST(x AS DATE)`), and keywords used as names may
  still show as keywords.
- Highlighting does not validate SQL. Syntactically invalid but lexically valid
  SQL is highlighted normally; use `gosqlx validate` or the LSP diagnostics for
  errors.
- After the first lexical error, the rest of the input is a single `error`
  span.
