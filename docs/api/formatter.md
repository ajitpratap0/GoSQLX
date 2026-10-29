# formatter package

Format SQL text or render an existing AST, with dialect-aware conversions and comment placement.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/formatter` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/formatter))

Part of the [GoSQLX API reference](../API_REFERENCE.md). For the convenience API, see [gosqlx](gosqlx.md#formatting-functions).

## Formatting SQL Text

```go
type Options struct {
    IndentSize int    // spaces per level; New defaults non-positive values to 2
    Uppercase  bool   // uppercase SQL keywords
    Compact    bool   // single-line layout
    Dialect    string // input and target dialect; empty = generic
}

func New(opts Options) *Formatter
func (f *Formatter) Format(sql string) (string, error)
func FormatString(sql string) (string, error)
```

`Format` tokenizes, parses and renders SQL, returning tokenization, parsing, conversion or comment-placement errors. It keeps comments and optimizer hints. Whitespace-only input returns `"", nil`. A recognized dialect selects lexical and parser rules as well as rendering; an unknown dialect is ignored for tokenization and parsing. `FormatString` uses `Options{}`.

```go
f := formatter.New(formatter.Options{Uppercase: true, Compact: true})
out, err := f.Format("select id from users")
if err != nil {
    return err
}
fmt.Println(out)
```

## Rendering an AST

```go
func FormatAST(a *ast.AST, opts ast.FormatOptions) string
func FormatStatement(s ast.Statement, opts ast.FormatOptions) string
func FormatExpression(e ast.Expression, opts ast.FormatOptions) string

func FormatASTChecked(a *ast.AST, opts ast.FormatOptions) (string, error)
func FormatStatementChecked(s ast.Statement, opts ast.FormatOptions) (string, error)
func FormatExpressionChecked(e ast.Expression, opts ast.FormatOptions) (string, error)
```

Start with `ast.ReadableStyle()` or `ast.CompactStyle()` and adjust `ast.FormatOptions`. These functions render existing nodes without parsing SQL again. The checked variants return errors for unsupported target-dialect semantic conversions, including operators nested inside expressions, and do not mutate the caller's nodes. Nil inputs return an empty string without an error. The string-only variants discard errors and return an empty string when rendering fails; prefer checked calls when selecting a target dialect.

Since v1.17.0, checked rendering lets callers handle these conversion failures explicitly. `FormatASTChecked` can also report comment-placement errors when the tree carries comments and statement spans.

## Joining Comments and Statements

```go
type CommentLayout struct {
    Dialect    string
    Terminator string
    Gap        string
    Batches    []models.Location
    Starts     []models.Location
}

func JoinWithComments(stmts []string, tokens []models.TokenWithSpan, comments []models.Comment, layout CommentLayout) (string, error)
func JoinASTWithComments(tree *ast.AST, stmts []string, tokens []models.TokenWithSpan, comments []models.Comment, layout CommentLayout) (string, error)

var ErrUnplaceableComment = errors.New("formatter: cannot preserve comment")
```

Pass rendered statements in source order and tokens and comments from the original input. `Terminator` is inserted between statements: use `";"` if the parts have no terminators, or `""` if they already do. `Gap` separates statements and their trailing comments, usually `"\n"`, `"\n\n"` or `" "`; line comments force a line break when needed.

`Starts` supplies one source start per rendered statement, including `GO` entries, to avoid splitting procedure bodies at internal semicolons. Without it, token semicolons determine statement boundaries. `Batches` supplies parser-recognized `GO` positions; nil enables token-based recognition. `Dialect` selects lexical rules and batch boundaries.

Ordinary comments inside a statement move above it. Between statements, comments lead the next statement unless they shared a line with the preceding statement; trailing comments remain trailing. Optimizer hints directly after a supported statement keyword stay there when the rendered occurrence can be identified. If a meaningful hint or MySQL executable comment cannot be restored faithfully, the join returns an error wrapping `ErrUnplaceableComment`. Use `errors.Is` to check it and retain the original SQL on failure. When source and rendered statements cannot be matched, ordinary comments move before the first statement; hints retain the same error checks.

`JoinASTWithComments` uses parser statement spans and Oracle execute-line metadata. Supply one rendered part per `AST.Statements` entry, without execute lines; the helper inserts those lines without changing statement counts. Tokens, when available, allow hints inside statements to be placed.

### Source positions

```go
func BatchPositions(tree *ast.AST) []models.Location
func StatementPositions(tree *ast.AST) []models.Location
```

`BatchPositions` collects `BatchSeparator.Pos` for `CommentLayout.Batches`. It returns a non-nil slice even for nil trees or scripts without `GO`, telling the joiner to follow the parser's boundaries. `StatementPositions` returns `AST.StatementStarts` for `CommentLayout.Starts`, or nil when the tree is nil or the slice length does not match the statement count.

## Script Rendering Helpers

```go
func EnsureStatementTerminator(stmt ast.Statement, part string, addSemicolon bool) string
func ExecuteSlashStatement(stmt ast.Statement, part string) string
func RestoreUnicodeIdentifiers(tree *ast.AST, statement int, sql, dialect string) string
```

`EnsureStatementTerminator` appends `;` when requested, unless the rendered part is empty, already ends in `;`, or represents a `BatchSeparator`.

`ExecuteSlashStatement` appends `"\n/"` for an Oracle SQL*Plus execute command without adding a SQL terminator to an ordinary statement. It retains the required ending semicolon for recognized PL/SQL utility blocks.

`RestoreUnicodeIdentifiers` restores PostgreSQL `U&` source spellings for one statement index using `AST.UnicodeIdentifiers`; semantic names on the AST stay decoded. It restores spellings only for unset, generic or PostgreSQL target dialects. Other targets keep decoded identifiers. A nil tree or absent metadata leaves the rendered SQL unchanged.
