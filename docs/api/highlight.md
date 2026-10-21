# highlight package

Dialect-aware SQL syntax highlighting: classify SQL into byte-offset spans, then render them for terminals, HTML pages or editors.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/highlight` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/highlight))

Part of the [GoSQLX API reference](../API_REFERENCE.md). The guide with examples, CLI usage and the WASM build is [Syntax Highlighting](../HIGHLIGHTING.md).

The same classifier drives `gosqlx.Highlight*`, the `gosqlx highlight` command and the LSP server's semantic tokens.

## Quick Example

```go
import (
    "fmt"

    "github.com/ajitpratap0/GoSQLX/pkg/highlight"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

sql := "SELECT id, name FROM users WHERE active = TRUE"
spans := highlight.Spans(sql, highlight.WithDialect(keywords.DialectPostgreSQL))

for _, s := range spans {
    fmt.Printf("%-12s %q\n", s.Category, s.Text(sql))
}

fmt.Print(highlight.ANSI(sql, spans, highlight.ANSIOptions{}))

html := highlight.HTML(sql, spans, highlight.HTMLOptions{Wrap: true})
css := highlight.CSS(highlight.DarkTheme(), "")
```

## Classifying SQL

### `Spans(sql string, opts ...Option) []Span`

Classifies `sql` for syntax highlighting.

- Spans are sorted by `Start`, never overlap and never carry `Plain`. Any byte not covered by a span (typically whitespace) is plain text.
- `Spans` never returns an error. When the tokenizer rejects the input, everything before the offending position is still classified and the rest of the input is one `Error` span, so it is safe to call on incomplete editor input.
- Input the tokenizer refuses outright (beyond its size or token limits) yields no spans. An empty string yields `nil`.
- `Spans` is safe for concurrent use.

### `WithDialect(d keywords.SQLDialect) Option`

Selects the dialect used for tokenization and keyword recognition. It accepts the 11 values of `keywords.AllDialects()`: `generic`, `postgresql`, `mysql`, `mariadb`, `sqlserver`, `oracle`, `sqlite`, `snowflake`, `bigquery`, `redshift` and `clickhouse`. An empty or unknown dialect uses the generic keyword set.

```go
type Option func(*config)
```

### `Span`

```go
type Span struct {
    Start    int      `json:"start"`    // 0-based byte offset, inclusive
    End      int      `json:"end"`      // 0-based byte offset, exclusive
    Category Category `json:"category"`
}
```

`src[s.Start:s.End]` is the span's text. Offsets always fall on UTF-8 boundaries. Spans marshal to JSON as `{"start":0,"end":6,"category":"keyword"}`.

### `(s Span) Text(src string) string`

Returns the source text covered by the span, or `""` when the span does not fit within `src`.

## Categories

### `Category`

```go
type Category uint8

const (
    Plain Category = iota // never on a Span; implicit category of gaps
    Keyword               // SELECT, FROM, RETURNING, LATERAL
    Function              // a function name in call position: COUNT, now
    DataType              // a type name in type position: VARCHAR, x::int
    Identifier            // unquoted table, column, alias or schema name
    QuotedIdentifier      // "name", `name` or [name]
    String                // string literals, including N'', E'', X'' and dollar-quoted
    Number                // numeric literals
    Constant              // TRUE, FALSE, NULL
    Operator              // =, <>, ||, ->>, ::
    Punctuation           // comma, period, semicolon, parentheses, brackets, braces
    Comment               // -- line and /* block */ comments
    Placeholder           // $1, ?, :name, @var, @@var
    Error                 // input the tokenizer rejected; always runs to the end of the input
)
```

Each category has a stable lowercase name, used as the JSON value, the HTML class suffix and the theme key. The names will not change; new categories may be appended in later releases.

| Category | Name |
|---|---|
| `Plain` | `plain` |
| `Keyword` | `keyword` |
| `Function` | `function` |
| `DataType` | `type` |
| `Identifier` | `identifier` |
| `QuotedIdentifier` | `quoted-identifier` |
| `String` | `string` |
| `Number` | `number` |
| `Constant` | `constant` |
| `Operator` | `operator` |
| `Punctuation` | `punctuation` |
| `Comment` | `comment` |
| `Placeholder` | `placeholder` |
| `Error` | `error` |

### `(c Category) String() string`

Returns the stable name, for example `"keyword"` or `"quoted-identifier"`.

### `(c Category) MarshalText() ([]byte, error)` and `(c *Category) UnmarshalText(text []byte) error`

Encode and decode the stable name, so `Category` round-trips through JSON. Unknown names and out-of-range values return an error.

### `ParseCategory(name string) (Category, bool)`

Returns the category with the given stable name.

### `Categories() []Category`

Returns every category that can appear on a `Span`, in declaration order, excluding `Plain`. The result is a fresh slice.

## Terminal Output

### `ANSI(src string, spans []Span, opts ANSIOptions) string`

Renders `src` with ANSI escape sequences.

### `WriteANSI(w io.Writer, src string, spans []Span, opts ANSIOptions) error`

Like `ANSI`, but writes to `w`.

```go
type ANSIOptions struct {
    Theme Theme     // the zero Theme means DarkTheme
    Mode  ColorMode // the zero value is Color256
}

type ColorMode int

const (
    Color256  ColorMode = iota // xterm 256-color palette (default)
    TrueColor                  // 24-bit color; use when COLORTERM is "truecolor" or "24bit"
    NoColor                    // bold, italic and underline only
)
```

Styles are reset before every newline and re-applied after it, so output stays correct when piped through `head`, `grep` or a pager.

Source text cannot inject terminal escape sequences. C0 control characters other than tab, newline and carriage return are shown as Unicode control pictures (ESC becomes U+241B), DEL as U+2421, and C1 controls and invalid UTF-8 bytes as U+FFFD. Only the renderer's own SGR sequences reach the terminal.

## HTML and CSS

### `HTML(src string, spans []Span, opts HTMLOptions) string`

Renders `src` as HTML. All source text is escaped; only `<span>` elements and the optional `<pre><code>` wrapper are emitted.

### `WriteHTML(w io.Writer, src string, spans []Span, opts HTMLOptions) error`

Like `HTML`, but writes to `w`.

```go
type HTMLOptions struct {
    ClassPrefix  string // empty means DefaultClassPrefix
    InlineStyles bool   // emit style="..." from Theme instead of class names
    Theme        Theme  // used with InlineStyles; the zero Theme means DarkTheme
    Wrap         bool   // wrap the output in <pre class="{prefix}highlight"><code>
}

const DefaultClassPrefix = "gsx-"
```

Spans render as `<span class="gsx-keyword">` and so on. A `ClassPrefix` containing characters other than ASCII letters, digits, `-` and `_` is replaced by `DefaultClassPrefix`. `InlineStyles` suits contexts without a stylesheet, such as e-mail.

### `CSS(theme Theme, classPrefix string) string`

Returns a stylesheet with one rule per category for the class names `HTML` emits, for example `.gsx-keyword{color:#569CD6;font-weight:bold}`. The zero `Theme` means `DarkTheme`. It styles the token classes only, not the `<pre>` wrapper.

## Themes

```go
type Theme struct {
    Name   string
    Styles map[Category]Style
}

type Style struct {
    Color     string // "#RRGGBB" or "#RGB"; empty or malformed means the default foreground
    Bold      bool
    Italic    bool
    Underline bool
}
```

Categories without an entry in `Styles` render with the default style. Colors are validated before use, so a theme cannot inject CSS or escape sequences.

### `(t Theme) Style(c Category) Style`

Returns the style for `c`, or the zero `Style` when the theme has none.

### `DarkTheme() Theme`, `LightTheme() Theme`, `MonoTheme() Theme`

The built-in themes: `DarkTheme` is the default and suits dark backgrounds, `LightTheme` suits light backgrounds, and `MonoTheme` uses only bold, italic and underline. Each call returns a fresh copy that the caller may modify.

### `ThemeByName(name string) (Theme, bool)`

Returns a fresh copy of the built-in theme with the given case-insensitive name. An empty name returns `DarkTheme`.

### `ThemeNames() []string`

Lists the built-in theme names: `dark`, `light` and `mono`.

## High-Level Helpers

The `gosqlx` package wraps the common cases:

```go
func Highlight(sql string, opts ...highlight.Option) []highlight.Span // same as highlight.Spans
func HighlightANSI(sql string, opts ...highlight.Option) string       // DarkTheme, Color256
func HighlightHTML(sql string, opts ...highlight.Option) string       // class-based, wrapped in <pre class="gsx-highlight"><code>
```

For another theme, true color, inline styles or a custom class prefix, call `highlight.ANSI` or `highlight.HTML` with the spans directly.
