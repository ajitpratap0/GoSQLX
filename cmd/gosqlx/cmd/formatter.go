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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/internal/batch"
	pkgformatter "github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// CLIFormatterOptions contains configuration for the SQL formatter CLI
type CLIFormatterOptions struct {
	InPlace    bool
	IndentSize int
	Uppercase  bool
	Compact    bool
	Check      bool
	MaxLine    int
	Verbose    bool
	Output     string // Output file path
	Dialect    string
}

// Formatter provides SQL formatting functionality with injectable output
type Formatter struct {
	Out  io.Writer
	Err  io.Writer
	Opts CLIFormatterOptions
}

// FormatterResult contains the results of a formatting run
type FormatterResult struct {
	TotalFiles       int
	FormattedFiles   int
	AlreadyFormatted int
	FailedFiles      int
	NeedsFormatting  []string
	Duration         time.Duration
}

// FileFormatterResult contains the result for a single file
type FileFormatterResult struct {
	Path      string
	Formatted string
	Changed   bool
	Error     error
}

// NewFormatter creates a new Formatter with the given options
func NewFormatter(out, err io.Writer, opts CLIFormatterOptions) *Formatter {
	return &Formatter{
		Out:  out,
		Err:  err,
		Opts: opts,
	}
}

// Format formats the given SQL files or patterns
func (f *Formatter) Format(args []string) (*FormatterResult, error) {
	startTime := time.Now()

	// Expand file arguments
	files, err := expandFileArgs(args)
	if err != nil {
		return nil, fmt.Errorf("failed to expand file arguments: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no SQL files found matching the specified patterns")
	}

	result := &FormatterResult{
		NeedsFormatting: make([]string, 0),
	}

	// Format each file
	for _, file := range files {
		fileResult := f.formatFile(file)
		result.TotalFiles++

		if fileResult.Error != nil {
			fmt.Fprintf(f.Err, "❌ %s: %v\n", file, fileResult.Error)
			result.FailedFiles++
			continue
		}

		if f.Opts.Check {
			if fileResult.Changed {
				result.NeedsFormatting = append(result.NeedsFormatting, file)
			}
			continue
		}

		if f.Opts.InPlace {
			if fileResult.Changed {
				// G306: Use 0600 for better security (owner read/write only)
				err = os.WriteFile(file, []byte(fileResult.Formatted), 0600)
				if err != nil {
					fmt.Fprintf(f.Err, "❌ Failed to write %s: %v\n", file, err)
					result.FailedFiles++
					continue
				}
				if f.Opts.Verbose {
					fmt.Fprintf(f.Out, "✅ Formatted: %s\n", file)
				}
				result.FormattedFiles++
			} else {
				if f.Opts.Verbose {
					fmt.Fprintf(f.Out, "✓ Already formatted: %s\n", file)
				}
				result.AlreadyFormatted++
			}
		} else if f.Opts.Output != "" {
			// G306: Use 0600 for better security (owner read/write only)
			err = os.WriteFile(f.Opts.Output, []byte(fileResult.Formatted), 0600)
			if err != nil {
				fmt.Fprintf(f.Err, "❌ Failed to write output file: %v\n", err)
				result.FailedFiles++
				continue
			}
			result.FormattedFiles++
		} else {
			output := fileResult.Formatted
			if !strings.HasSuffix(output, "\n") {
				output += "\n"
			}
			fmt.Fprint(f.Out, output)
			result.FormattedFiles++
		}
	}

	result.Duration = time.Since(startTime)

	// Handle check mode results
	if f.Opts.Check {
		if len(result.NeedsFormatting) > 0 {
			fmt.Fprintf(f.Err, "The following files need formatting:\n")
			for _, file := range result.NeedsFormatting {
				fmt.Fprintf(f.Err, "  %s\n", file)
			}
			return result, fmt.Errorf("%d files need formatting", len(result.NeedsFormatting))
		}
		// Failed files were already reported on stderr and fail the run; do
		// not also claim they are properly formatted.
		if result.FailedFiles == 0 {
			fmt.Fprintf(f.Out, "All %d files are properly formatted (%v)\n", result.TotalFiles, result.Duration)
		}
	}

	return result, nil
}

// formatFile formats a single SQL file
func (f *Formatter) formatFile(filename string) FileFormatterResult {
	result := FileFormatterResult{
		Path: filename,
	}

	// Use security validation first
	if err := ValidateFileAccess(filename); err != nil {
		result.Error = fmt.Errorf("file access validation failed: %w", err)
		return result
	}

	// G304: Path is validated by ValidateFileAccess above
	data, err := os.ReadFile(filename) // #nosec G304
	if err != nil {
		result.Error = fmt.Errorf("failed to read file: %w", err)
		return result
	}

	original := string(data)
	if len(data) == 0 {
		result.Formatted = original
		result.Changed = false
		return result
	}

	formatted, err := f.formatSQL(original)
	if err != nil {
		result.Error = err
		return result
	}

	result.Formatted = formatted
	result.Changed = (original != formatted)
	return result
}

// utf8BOM is the byte order mark some editors put at the start of a file.
const utf8BOM = "\uFEFF"

// formatSQL formats a SQL string. A leading UTF-8 byte order mark is not SQL:
// it is set aside and written back in front of the result, so formatting a
// file in place does not strip it.
func (f *Formatter) formatSQL(sql string) (string, error) {
	if strings.HasPrefix(sql, utf8BOM) {
		out, err := f.formatSQLText(strings.TrimPrefix(sql, utf8BOM))
		if err != nil {
			return "", err
		}
		return utf8BOM + out, nil
	}
	return f.formatSQLText(sql)
}

// formatSQLText formats SQL text without a byte order mark.
func (f *Formatter) formatSQLText(sql string) (string, error) {
	// Acquire a tokenizer for the configured dialect (pooled for the default)
	tkz, releaseTkz, err := tokenizerForDialect(f.Opts.Dialect)
	if err != nil {
		return "", fmt.Errorf("tokenizer setup failed: %w", err)
	}
	defer releaseTkz()

	// Tokenize the SQL
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return "", fmt.Errorf("tokenization failed: %w", err)
	}

	if len(tokens) == 0 {
		return "", nil
	}
	if !hasStatementTokens(tokens) {
		// Whitespace or comments only: there is nothing to format, and the
		// text is returned untouched rather than reported as a syntax error.
		return sql, nil
	}
	comments := tkz.Comments

	// Parse to AST with proper error handling for memory management
	p := parserForDialect(f.Opts.Dialect)
	parsedAST, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		// Parser failed, no AST to release
		return "", fmt.Errorf("parsing failed: %w", err)
	}

	// CRITICAL: Always release AST, even on formatting errors
	defer func() {
		ast.ReleaseAST(parsedAST)
	}()

	if err := checkFormattable(parsedAST, tokens, f.Opts.Dialect); err != nil {
		return "", err
	}

	// Configure formatter options
	indentStr := strings.Repeat(" ", f.Opts.IndentSize)
	formatterOpts := FormatterOptions{
		Indent:       indentStr,
		Compact:      f.Opts.Compact,
		UppercaseKw:  f.Opts.Uppercase,
		AlignColumns: !f.Opts.Compact, // Align columns unless in compact mode
		Dialect:      f.Opts.Dialect,
	}

	// Create formatter and format the AST. Comments are put back around the
	// statements they belonged to; one that cannot be put back (an optimizer
	// hint away from its statement's first keyword) refuses the whole file.
	formatter := NewSQLFormatter(formatterOpts)
	var formatted string
	if len(comments) == 0 {
		formatted, err = formatter.Format(parsedAST)
	} else {
		formatted, err = formatter.FormatWithComments(parsedAST, tokens, comments)
	}
	if err != nil {
		return "", fmt.Errorf("render: %w (input left unchanged)", err)
	}

	// Refuse output that fails verifyFormattedSQL, so format, format -i and
	// format -o do not emit or write SQL the renderer got wrong (#599). The
	// check cannot see what the parser itself drops; see verifyFormattedSQL.
	// Keyword case is semantically irrelevant, and the parser does not accept
	// every lowercase keyword sequence, so lowercase output is verified via an
	// uppercase-keyword rendering of the same tree.
	verifyText := formatted
	if !formatterOpts.UppercaseKw {
		upperOpts := formatterOpts
		upperOpts.UppercaseKw = true
		verifyText, err = NewSQLFormatter(upperOpts).Format(parsedAST)
		if err != nil {
			return "", fmt.Errorf("render for verification: %w", err)
		}
	}
	// verifyFormattedSQL errors are self-describing; callers add the
	// "formatting failed" prefix.
	if err := verifyFormattedSQL(parsedAST, tokens, verifyText, f.Opts.Dialect); err != nil {
		return "", err
	}
	// Comments are not part of the AST, so verify them on the real output.
	if err := verifyComments(comments, formatted, f.Opts.Dialect); err != nil {
		return "", err
	}

	return formatted, nil
}

// verifyComments requires the formatted output to contain exactly the
// comments of the input, so format -i can never delete or invent one.
func verifyComments(input []models.Comment, formatted, dialect string) error {
	tkz, release, err := tokenizerForDialect(dialect)
	if err != nil {
		return fmt.Errorf("tokenizer setup failed: %w", err)
	}
	defer release()
	if _, err := tkz.TokenizeString(formatted); err != nil {
		return fmt.Errorf("formatted output does not re-tokenize (formatter bug; input left unchanged): %w", err)
	}
	pool := make(map[string]int, len(input))
	for _, c := range tkz.Comments {
		pool[c.Text]++
	}
	for _, c := range input {
		if pool[c.Text] == 0 {
			return fmt.Errorf("formatted output loses the comment %q (formatter bug; input left unchanged)", c.Text)
		}
		pool[c.Text]--
	}
	for text, n := range pool {
		if n > 0 {
			return fmt.Errorf("formatted output adds the comment %q (formatter bug; input left unchanged)", text)
		}
	}
	return nil
}

// verifyFormattedSQL re-parses formatted with the same dialect and checks
// that it yields the same number of statements, the same AST.SQL(), the same
// canonical pkg/formatter rendering of each statement, and the same string
// literal values and quoted identifiers as the input tokens.
//
// SQL() is compared case-insensitively because some nodes (e.g. set operation
// operators) keep the source keyword case. The per-statement rendering covers
// statements without a SQL() method (e.g. ALTER), which AST.SQL() skips. The
// token comparison covers what neither can see: identifiers carry no quoting
// in the AST, and string literals are re-escaped by the renderer.
//
// This is a consistency check between the input's parse and the output's
// parse. Anything the parser itself drops (comments, clauses it skips) is
// absent from both and is not detected.
func verifyFormattedSQL(original *ast.AST, inputTokens []models.TokenWithSpan, formatted, dialect string) error {
	tkz, release, err := tokenizerForDialect(dialect)
	if err != nil {
		return fmt.Errorf("tokenizer setup failed: %w", err)
	}
	defer release()

	tokens, err := tkz.TokenizeString(formatted)
	if err != nil {
		return fmt.Errorf("formatted output does not re-tokenize (formatter bug; input left unchanged): %w", err)
	}
	if err := checkQuotedTokens(inputTokens, tokens, dialect); err != nil {
		return err
	}
	if err := checkMySQLDoubleQuotes(inputTokens, tokens, dialect); err != nil {
		return err
	}
	reparsed, err := parserForDialect(dialect).ParseFromModelTokens(tokens)
	if err != nil {
		return fmt.Errorf("formatted output does not re-parse (formatter bug; input left unchanged): %w", err)
	}
	defer ast.ReleaseAST(reparsed)

	if got, want := len(reparsed.Statements), len(original.Statements); got != want {
		return fmt.Errorf("formatted output has %d statements, input has %d (formatter bug; input left unchanged)", got, want)
	}
	if !strings.EqualFold(original.SQL(), reparsed.SQL()) {
		return errors.New("formatted output changes the query (formatter bug; input left unchanged)")
	}
	canonical := NewSQLFormatter(FormatterOptions{Compact: true, UppercaseKw: true, Dialect: dialect}).style
	for i, stmt := range original.Statements {
		want := pkgformatter.FormatStatement(stmt, canonical)
		got := pkgformatter.FormatStatement(reparsed.Statements[i], canonical)
		if !strings.EqualFold(want, got) {
			return fmt.Errorf("formatted output changes statement %d (formatter bug; input left unchanged)", i+1)
		}
	}
	return nil
}

// checkQuotedTokens compares the quoted tokens of the input and of the
// formatted output. Every string literal value of the input must appear in
// the output, so a literal the renderer re-escapes for another dialect (e.g.
// doubled backslashes where a backslash is not an escape) is refused. Every
// quoted identifier of the input must either appear quoted in the output or
// mean the same identifier bare (see bareWords.safe); the AST does not record
// quoting, so the renderer writes most identifiers bare.
func checkQuotedTokens(input, output []models.TokenWithSpan, dialect string) error {
	bw, release, err := newBareWords(dialect)
	if err != nil {
		return fmt.Errorf("tokenizer setup failed: %w", err)
	}
	defer release()

	input = mergeAdjacentStrings(input, dialect)
	output = mergeAdjacentStrings(output, dialect)

	pool := make(map[string]int)
	for _, t := range output {
		if isStringLiteralToken(t.Token) || bw.isQuotedIdent(t.Token) {
			pool[t.Token.Value]++
		}
	}
	for i, t := range input {
		if !isStringLiteralToken(t.Token) || isStringAlias(input, i, dialect) {
			continue
		}
		if pool[t.Token.Value] == 0 {
			return fmt.Errorf("formatted output changes string literal %q (formatter bug; input left unchanged)", t.Token.Value)
		}
		pool[t.Token.Value]--
	}
	for i, t := range input {
		if !bw.isQuotedIdent(t.Token) && !isStringAlias(input, i, dialect) {
			continue
		}
		v := t.Token.Value
		if pool[v] > 0 {
			pool[v]--
			continue
		}
		if !bw.safe(v) {
			return fmt.Errorf("formatted output drops the quotes of identifier %q (formatter bug; input left unchanged)", v)
		}
	}
	return nil
}

// isStringAlias reports whether toks[i] is a string literal that names a
// column, as in "SELECT a AS 'x'" (MySQL, MariaDB, SQLite). The parser reads
// it as the alias x, the same as the delimited name, so the formatter writes
// it as a name rather than as a string.
func isStringAlias(toks []models.TokenWithSpan, i int, dialect string) bool {
	switch strings.ToLower(dialect) {
	case "mysql", "mariadb", "sqlite":
	default:
		return false
	}
	t := toks[i].Token
	if i == 0 || (t.Type != models.TokenTypeString && t.Type != models.TokenTypeSingleQuotedString) {
		return false
	}
	return toks[i-1].Token.Type == models.TokenTypeAs
}

// mergeAdjacentStrings returns toks with each run of adjacent single-quoted
// string tokens merged into one token, for the dialects whose parser reads
// 'a' 'b' as the literal 'ab' (MySQL, MariaDB, PostgreSQL). The formatter
// writes the merged literal, which means the same. Other dialects, and toks
// without such a run, are returned as they are.
func mergeAdjacentStrings(toks []models.TokenWithSpan, dialect string) []models.TokenWithSpan {
	switch strings.ToLower(dialect) {
	case "mysql", "mariadb", "postgresql", "postgres":
	default:
		return toks
	}
	plain := func(t models.Token) bool {
		return t.Type == models.TokenTypeString || t.Type == models.TokenTypeSingleQuotedString
	}
	var out []models.TokenWithSpan
	for i := 0; i < len(toks); i++ {
		if !plain(toks[i].Token) || i+1 >= len(toks) || !plain(toks[i+1].Token) {
			if out != nil {
				out = append(out, toks[i])
			}
			continue
		}
		if out == nil {
			out = append(make([]models.TokenWithSpan, 0, len(toks)), toks[:i]...)
		}
		merged := toks[i]
		var sb strings.Builder
		sb.WriteString(merged.Token.Value)
		for i+1 < len(toks) && plain(toks[i+1].Token) {
			i++
			sb.WriteString(toks[i].Token.Value)
		}
		merged.Token.Value = sb.String()
		out = append(out, merged)
	}
	if out == nil {
		return toks
	}
	return out
}

// checkMySQLDoubleQuotes requires MySQL/MariaDB output to keep exactly the
// input's double-quoted tokens. MySQL reads "..." as a string literal unless
// ANSI_QUOTES is set, while the parser treats it as an identifier, so the
// round-trip check alone misses two meaning changes: a string written bare
// (WHERE name = "bob" -> WHERE name = bob, a column reference) and an
// identifier newly written in ANSI quotes (`select` -> "select", a string).
// Input that uses a double-quoted name where a string cannot appear (a
// qualifier such as "users"."id", or a table after FROM/JOIN/INTO/UPDATE/
// TABLE) is ANSI_QUOTES-style SQL, where "..." is an identifier, so it is
// not checked.
func checkMySQLDoubleQuotes(input, output []models.TokenWithSpan, dialect string) error {
	if d := strings.ToLower(dialect); d != "mysql" && d != "mariadb" {
		return nil
	}
	if usesANSIQuotes(input) {
		return nil
	}
	pool := make(map[string]int)
	for _, t := range output {
		if t.Token.Quote == '"' {
			pool[t.Token.Value]++
		}
	}
	for _, t := range input {
		if t.Token.Quote != '"' {
			continue
		}
		if pool[t.Token.Value] == 0 {
			return fmt.Errorf("formatted output drops the double quotes of %q, which %s reads as a string (formatter limitation; input left unchanged)", t.Token.Value, dialect)
		}
		pool[t.Token.Value]--
	}
	for v, n := range pool {
		if n > 0 {
			return fmt.Errorf("formatted output writes %q in ANSI double quotes, which %s reads as a string unless ANSI_QUOTES is set (formatter limitation; input left unchanged)", v, dialect)
		}
	}
	return nil
}

// usesANSIQuotes reports whether toks use a double-quoted token as a name in
// a position where MySQL cannot accept a string: next to a '.', or right
// after FROM, JOIN, INTO, UPDATE or TABLE.
func usesANSIQuotes(toks []models.TokenWithSpan) bool {
	for i, t := range toks {
		if t.Token.Quote != '"' {
			continue
		}
		if i+1 < len(toks) && toks[i+1].Token.Value == "." {
			return true
		}
		if i > 0 {
			prev := toks[i-1].Token
			if prev.Value == "." {
				return true
			}
			switch strings.ToUpper(prev.Value) {
			case "FROM", "JOIN", "INTO", "UPDATE", "TABLE":
				return true
			}
		}
	}
	return false
}

// isStringLiteralToken reports whether tok is a string literal of any form.
// Double-quoted strings are treated as identifiers (see bareWords.isQuotedIdent).
func isStringLiteralToken(tok models.Token) bool {
	switch tok.Type {
	case models.TokenTypeString, models.TokenTypeSingleQuotedString,
		models.TokenTypeTripleSingleQuotedString, models.TokenTypeTripleDoubleQuotedString,
		models.TokenTypeDollarQuotedString, models.TokenTypeByteStringLiteral,
		models.TokenTypeNationalStringLiteral, models.TokenTypeEscapedStringLiteral,
		models.TokenTypeUnicodeStringLiteral, models.TokenTypeHexStringLiteral:
		return true
	}
	return tok.Quote == '\'' || tok.Quote == 'N'
}

// bareWords classifies identifiers for one dialect, memoizing the tokenizer
// round trip that tells keywords from plain identifiers.
type bareWords struct {
	dialect string
	tkz     *tokenizer.Tokenizer
	memo    map[string]bool
}

func newBareWords(dialect string) (*bareWords, func(), error) {
	tkz, release, err := tokenizerForDialect(dialect)
	if err != nil {
		return nil, nil, err
	}
	return &bareWords{dialect: dialect, tkz: tkz, memo: make(map[string]bool)}, release, nil
}

// isQuotedIdent reports whether tok is a quoted identifier: a double-quoted
// or bracketed token, or an identifier whose value cannot be a bare word. The
// tokenizer does not record backtick quoting, so a backtick identifier is
// recognized by the latter (e.g. `select`, `a b`); one that is a plain bare
// word (`users`) is indistinguishable and harmless to unquote.
func (b *bareWords) isQuotedIdent(tok models.Token) bool {
	if tok.Type == models.TokenTypeDoubleQuotedString {
		return true
	}
	switch tok.Quote {
	case '"', '`', '[':
		return true
	}
	if tok.Word != nil && tok.Word.QuoteStyle != 0 {
		return true
	}
	return tok.Type == models.TokenTypeIdentifier && !b.isBareWord(tok.Value)
}

// safe reports whether the quoted identifier v names the same identifier when
// written bare: it must be a bare word (see isBareWord) and survive the
// dialect's case folding (PostgreSQL and the default dialect fold bare
// identifiers to lowercase, Oracle and Snowflake to uppercase).
func (b *bareWords) safe(v string) bool {
	if !b.isBareWord(v) {
		return false
	}
	switch b.dialect {
	case "", "postgresql":
		return v == strings.ToLower(v)
	case "oracle", "snowflake":
		return v == strings.ToUpper(v)
	}
	return true
}

// isBareWord reports whether v is an ASCII word ([A-Za-z_][A-Za-z0-9_]*) that
// the dialect's tokenizer reads back as a plain identifier, i.e. not a
// keyword.
func (b *bareWords) isBareWord(v string) bool {
	if ok, seen := b.memo[v]; seen {
		return ok
	}
	ok := asciiWord(v) && b.tokenizesAsIdentifier(v)
	b.memo[v] = ok
	return ok
}

func asciiWord(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '_', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func (b *bareWords) tokenizesAsIdentifier(v string) bool {
	toks, err := b.tkz.TokenizeString(v)
	if err != nil {
		return false
	}
	n := 0
	for _, t := range toks {
		if t.Token.Type == models.TokenTypeEOF {
			continue
		}
		n++
		if n > 1 || t.Token.Type != models.TokenTypeIdentifier || t.Token.Value != v {
			return false
		}
	}
	return n == 1
}

// FormatterFlags represents CLI flags for formatter command
type FormatterFlags struct {
	InPlace    bool
	IndentSize int
	Uppercase  bool
	Compact    bool
	Check      bool
	MaxLine    int
	Verbose    bool
	Output     string
	Dialect    string
}

// FormatterOptionsFromConfig creates CLIFormatterOptions from config and CLI flags
func FormatterOptionsFromConfig(cfg *config.Config, flagsChanged map[string]bool, flags FormatterFlags) CLIFormatterOptions {
	opts := CLIFormatterOptions{
		IndentSize: cfg.Format.Indent,
		Uppercase:  cfg.Format.UppercaseKeywords,
		Compact:    cfg.Format.Compact,
		MaxLine:    cfg.Format.MaxLineLength,
		Verbose:    cfg.Output.Verbose,
	}

	// Override with CLI flags if explicitly set
	if flagsChanged["in-place"] {
		opts.InPlace = flags.InPlace
	}
	if flagsChanged["indent"] {
		opts.IndentSize = flags.IndentSize
	}
	if flagsChanged["uppercase"] || flagsChanged["no-uppercase"] {
		opts.Uppercase = flags.Uppercase
	}
	if flagsChanged["compact"] {
		opts.Compact = flags.Compact
	}
	if flagsChanged["check"] {
		opts.Check = flags.Check
	}
	if flagsChanged["max-line"] {
		opts.MaxLine = flags.MaxLine
	}
	if flagsChanged["verbose"] {
		opts.Verbose = flags.Verbose
	}
	if flagsChanged["output"] {
		opts.Output = flags.Output
	}
	if flagsChanged["dialect"] {
		opts.Dialect = flags.Dialect
	}

	return opts
}

// checkFormattable refuses parse results the CLI cannot rewrite faithfully, so
// format, format -i and format -o leave such input unchanged.
//
// DescribeStatement keeps only a name and drops DESCRIBE object kinds
// (EXPLAIN <stmt> is an ExplainStatement, which round-trips).
// UnsupportedStatement is rendered as a comment. Both are refused by type. As a general guard, a parse
// with more statements than semicolon-separated segments in the input means
// the parser split a statement, which re-parsing the output cannot detect.
func checkFormattable(tree *ast.AST, tokens []models.TokenWithSpan, dialect ...string) error {
	withBatches := false
	for _, stmt := range tree.Statements {
		switch stmt.(type) {
		case *ast.BatchSeparator:
			withBatches = true
		case *ast.DescribeStatement, *ast.UnsupportedStatement:
			return fmt.Errorf("unsupported statement type: %T (input left unchanged)", stmt)
		}
	}
	// T-SQL intentionally accepts statements without semicolons. Its parser
	// validates those boundaries; a semicolon count cannot bound its AST size.
	// The caller still verifies each rendered statement and the reparse count.
	if len(dialect) > 0 {
		switch strings.ToLower(dialect[0]) {
		case "sqlserver", "mssql", "tsql":
			return nil
		}
	}
	if got, segs := len(tree.Statements), statementSegments(tokens, withBatches); got > segs {
		return fmt.Errorf("input parses as %d statements but has %d semicolon-separated statements (input left unchanged)", got, segs)
	}
	return nil
}

// statementSegments counts the non-empty runs of tokens between semicolons,
// ignoring EOF, i.e. the most statements the input can legitimately hold.
func statementSegments(tokens []models.TokenWithSpan, withBatches ...bool) int {
	segs := 0
	inSeg := false
	for i := 0; i < len(tokens); i++ {
		if len(withBatches) > 0 && withBatches[0] {
			if next, ok := batch.End(tokens, i); ok {
				segs++ // a retained BatchSeparator is itself an AST statement
				inSeg = false
				i = next - 1
				continue
			}
		}
		tok := tokens[i]
		switch tok.Token.Type {
		case models.TokenTypeSemicolon:
			inSeg = false
		case models.TokenTypeEOF:
		default:
			if !inSeg {
				segs++
				inSeg = true
			}
		}
	}
	return segs
}
