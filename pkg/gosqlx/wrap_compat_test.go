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
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// These references call the lower-level APIs and construct the former
// fmt.Errorf errors. They never inspect the new wrapper's fields, so a changed
// sentinel, missing wrapper, or changed prefix cannot bless itself.
// legacyParseError returns the inner errors and the error the eager wrapping produced.
func legacyParseError(sql string, dialect keywords.SQLDialect, mode string) ([]error, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if dialect != "" {
		tkz.SetDialect(dialect)
	}
	tokens, err := tkz.TokenizeString(sql)
	if mode == "context" {
		tokens, err = tkz.TokenizeStringContext(context.Background(), sql)
	}
	if err != nil {
		return []error{err}, fmt.Errorf("%w: %w", ErrTokenize, err)
	}
	p := parser.GetParser()
	defer parser.PutParser(p)
	if dialect != "" {
		p.ApplyOptions(parser.WithDialect(string(dialect)))
	}
	if mode == "recovery" {
		stmts, errs := p.ParseWithRecoveryFromModelTokens(tokens)
		ast.ReleaseAST(&ast.AST{Statements: stmts})
		if len(errs) == 0 {
			return nil, nil
		}
		return errs, fmt.Errorf("%w: %w", ErrSyntax, errors.Join(errs...))
	}
	var a *ast.AST
	if mode == "context" {
		a, err = p.ParseContextFromModelTokens(context.Background(), tokens)
	} else {
		a, err = p.ParseFromModelTokens(tokens)
	}
	if a != nil {
		ast.ReleaseAST(a)
	}
	if err == nil {
		return nil, nil
	}
	return []error{err}, fmt.Errorf("%w: %w", ErrSyntax, err)
}

func legacyDialectError(sql string, dialect keywords.SQLDialect) error {
	a, err := parser.ParseWithDialect(sql, dialect)
	if a != nil {
		ast.ReleaseAST(a)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSyntax, err)
	}
	return nil
}

func legacyValidateError(sql string) error {
	if strings.TrimSpace(sql) == "" {
		return fmt.Errorf("%w: empty input", ErrSyntax)
	}
	if err := parser.Validate(sql); err != nil {
		return fmt.Errorf("%w: %w", ErrSyntax, err)
	}
	return nil
}

func legacyLintError(sql string, dialect keywords.SQLDialect) error {
	l := defaultLinter()
	if dialect != "" {
		l = linterForDialect(dialect)
	}
	r := l.LintString(sql, "<input>")
	if r.Error != nil {
		return r.Error
	}
	if r.TokenizeError != nil {
		return fmt.Errorf("%w: %w", ErrTokenize, r.TokenizeError)
	}
	if r.ParseError != nil {
		return fmt.Errorf("%w: %w", ErrSyntax, r.ParseError)
	}
	return nil
}

func legacyNormalizeError(sql string) error {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return fmt.Errorf("fingerprint: tokenization failed: %w", err)
	}
	p := parser.GetParser()
	defer parser.PutParser(p)
	a, err := p.ParseFromModelTokens(tokens)
	if a != nil {
		ast.ReleaseAST(a)
	}
	if err != nil {
		return fmt.Errorf("fingerprint: parsing failed: %w", err)
	}
	return nil
}

func assertLegacyError(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("error presence: got %v, want %v", got, want)
	}
	if want == nil {
		return
	}
	if got.Error() != want.Error() {
		t.Fatalf("error text:\ngot  %q\nwant %q", got.Error(), want.Error())
	}
	for _, sentinel := range []error{ErrTokenize, ErrSyntax, ErrTimeout, ErrUnsupportedDialect, ErrTooLarge, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(got, sentinel) != errors.Is(want, sentinel) {
			t.Errorf("errors.Is(%v): got %v, want %v", sentinel, errors.Is(got, sentinel), errors.Is(want, sentinel))
		}
	}
	var gotStructured, wantStructured *sqlerrors.Error
	gotAs, wantAs := errors.As(got, &gotStructured), errors.As(want, &wantStructured)
	if gotAs != wantAs {
		t.Fatalf("structured error presence: got %v, want %v", gotAs, wantAs)
	}
	if wantAs && (gotStructured.Code != wantStructured.Code || gotStructured.Location != wantStructured.Location) {
		t.Errorf("structured code/location: got %s/%+v, want %s/%+v", gotStructured.Code, gotStructured.Location, wantStructured.Code, wantStructured.Location)
	}
}

func TestWrapErrLegacyCompatibilityCorpus(t *testing.T) {
	invalid := []string{"", " \t\n"}
	templates := []string{
		"SELECT * FROM", "SELECT (", "SELECT 1 FROM t WHERE", "INSERT INTO t VALUES (",
		"UPDATE t SET", "DELETE FROM", "SELECT 'unterminated", "SELECT \x00", "SELECT * FROM t WHERE x =", "SELECT 1 +",
	}
	for i := 0; i < 24; i++ {
		for _, sql := range templates {
			invalid = append(invalid, strings.Repeat("\n", i/6)+strings.Repeat(" ", i%6)+sql)
		}
	}
	if len(invalid) < 200 {
		t.Fatal("compatibility corpus requires at least 200 invalid inputs")
	}
	seen := make(map[string]bool, len(invalid))
	for _, sql := range invalid {
		if seen[sql] {
			t.Fatalf("duplicate corpus input: %q", sql)
		}
		seen[sql] = true
	}
	ctx := context.Background()
	for i, sql := range invalid {
		t.Run(fmt.Sprintf("input_%03d", i), func(t *testing.T) {
			_, parseWant := legacyParseError(sql, "", "")
			_, contextWant := legacyParseError(sql, "", "context")
			if parseWant == nil {
				t.Fatalf("corpus input was valid: %q", sql)
			}
			type entrypoint struct {
				name string
				run  func() error
				want error
			}
			tests := []entrypoint{
				{"MustParse", func() (err error) {
					defer func() {
						recovered := recover()
						var ok bool
						err, ok = recovered.(error)
						if !ok {
							t.Fatalf("MustParse panic: got %v, want error", recovered)
						}
					}()
					MustParse(sql)
					return nil
				}, fmt.Errorf("gosqlx.MustParse: %w", parseWant)},
				{"Parse", func() error {
					a, e := Parse(sql)
					if a != nil {
						ast.ReleaseAST(a)
					}
					return e
				}, parseWant},
				{"ParseBytes", func() error {
					a, e := ParseBytes([]byte(sql))
					if a != nil {
						ast.ReleaseAST(a)
					}
					return e
				}, parseWant},
				{"ParseWithContext", func() error {
					a, e := ParseWithContext(ctx, sql)
					if a != nil {
						ast.ReleaseAST(a)
					}
					return e
				}, contextWant},
				{"ParseWithTimeout", func() error {
					a, e := ParseWithTimeout(sql, time.Hour)
					if a != nil {
						ast.ReleaseAST(a)
					}
					return e
				}, contextWant},
				{"ParseTree", func() error {
					tr, e := ParseTree(ctx, sql)
					if tr != nil {
						ast.ReleaseAST(tr.Raw())
					}
					return e
				}, contextWant},
				{"ParseReader", func() error {
					tr, e := ParseReader(ctx, strings.NewReader(sql))
					if tr != nil {
						ast.ReleaseAST(tr.Raw())
					}
					return e
				}, contextWant},
				{"Validate", func() error { return Validate(sql) }, legacyValidateError(sql)},
				{"Format", func() error { _, e := Format(sql, DefaultFormatOptions()); return e }, fmt.Errorf("cannot format invalid SQL: %w", parseWant)},
				{"Lint", func() error { _, e := Lint(sql); return e }, legacyLintError(sql, "")},
				{"Normalize", func() error { _, e := Normalize(sql); return e }, legacyNormalizeError(sql)},
				{"Fingerprint", func() error { _, e := Fingerprint(sql); return e }, legacyNormalizeError(sql)},
			}
			// Batch APIs retain their zero-based query index and extra context text.
			batchWant := fmt.Errorf("query %d: %w", 1, parseWant)
			tests = append(tests,
				entrypoint{"ParseMultiple", func() error { aa, e := ParseMultiple([]string{"SELECT 1", sql}); releaseASTs(aa); return e }, batchWant},
				entrypoint{"ValidateMultiple", func() error { return ValidateMultiple([]string{"SELECT 1", sql}) }, batchWant},
			)
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) { assertLegacyError(t, tc.run(), tc.want) })
			}

			recoveryInner, recoveryWant := legacyParseError(sql, "", "recovery")
			t.Run("ParseTreeRecovery", func(t *testing.T) { _, e := ParseTree(ctx, sql, WithRecovery()); assertLegacyError(t, e, recoveryWant) })
			t.Run("ParseReaderRecovery", func(t *testing.T) {
				_, e := ParseReader(ctx, strings.NewReader(sql), WithRecovery())
				assertLegacyError(t, e, recoveryWant)
			})
			t.Run("ParseWithRecovery", func(t *testing.T) {
				ss, got := ParseWithRecovery(sql)
				ast.ReleaseAST(&ast.AST{Statements: ss})
				if len(got) != len(recoveryInner) {
					t.Fatalf("diagnostic count: got %d, want %d", len(got), len(recoveryInner))
				}
				sentinel := ErrSyntax
				if errors.Is(recoveryWant, ErrTokenize) {
					sentinel = ErrTokenize
				}
				for j := range got {
					assertLegacyError(t, got[j], fmt.Errorf("%w: %w", sentinel, recoveryInner[j]))
				}
			})
			// The splitter skips blanks and trims source-position whitespace.
			t.Run("ParseReaderMultiple", func(t *testing.T) {
				var want error
				for j, segment := range SplitStatements("SELECT 1;"+sql, "") {
					segment = strings.TrimSpace(segment)
					if segment == "" || commentsOnly(segment) {
						continue
					}
					_, inner := legacyParseError(segment, "", "context")
					if inner != nil {
						want = fmt.Errorf("statement %d: %w", j, inner)
						break
					}
				}
				ts, got := ParseReaderMultiple(ctx, strings.NewReader("SELECT 1;"+sql))
				for _, tr := range ts {
					ast.ReleaseAST(tr.Raw())
				}
				assertLegacyError(t, got, want)
			})
			for _, dialect := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLServer} {
				t.Run(string(dialect), func(t *testing.T) {
					dialectWant := legacyDialectError(sql, dialect)
					_, formatWant := legacyParseError(sql, dialect, "")
					_, treeWant := legacyParseError(sql, dialect, "context")
					t.Run("ParseWithDialect", func(t *testing.T) {
						a, e := ParseWithDialect(sql, dialect)
						if a != nil {
							ast.ReleaseAST(a)
						}
						assertLegacyError(t, e, dialectWant)
					})
					t.Run("ParseTree", func(t *testing.T) {
						_, e := ParseTree(ctx, sql, WithDialect(string(dialect)))
						assertLegacyError(t, e, treeWant)
					})
					t.Run("FormatWithDialect", func(t *testing.T) {
						_, e := FormatWithDialect(sql, DefaultFormatOptions(), dialect)
						assertLegacyError(t, e, fmt.Errorf("cannot format invalid SQL: %w", formatWant))
					})
					t.Run("LintWithDialect", func(t *testing.T) {
						_, e := LintWithDialect(sql, dialect)
						assertLegacyError(t, e, legacyLintError(sql, dialect))
					})
					t.Run("Transpile", func(t *testing.T) {
						a, inner := parser.ParseWithDialect(sql, dialect)
						if a != nil {
							ast.ReleaseAST(a)
						}
						var want error
						if inner != nil {
							want = fmt.Errorf("parse: %w", inner)
						}
						_, got := Transpile(sql, dialect, keywords.DialectSQLite)
						assertLegacyError(t, got, want)
					})
				})
			}
		})
	}
}

func TestWrapErrLegacySentinelEdges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelDeadline()
	for _, expired := range []context.Context{ctx, deadline} {
		want := fmt.Errorf("%w: %w", ErrTimeout, expired.Err())
		_, got := ParseWithContext(expired, "SELECT 1")
		assertLegacyError(t, got, want)
		_, got = ParseTree(expired, "SELECT 1")
		assertLegacyError(t, got, want)
		_, got = ParseReader(expired, strings.NewReader("SELECT 1"))
		assertLegacyError(t, got, want)
		_, got = ParseReaderMultiple(expired, strings.NewReader("SELECT 1"))
		assertLegacyError(t, got, want)
	}
	_, got := ParseWithTimeout("SELECT 1", 0)
	assertLegacyError(t, got, fmt.Errorf("%w: %w", ErrTimeout, context.DeadlineExceeded))
	badDialect := keywords.SQLDialect("unsupported-test-dialect")
	want := fmt.Errorf("%w: %q", ErrUnsupportedDialect, badDialect)
	_, got = ParseWithDialect("SELECT 1", badDialect)
	assertLegacyError(t, got, want)
	_, got = FormatWithDialect("SELECT 1", DefaultFormatOptions(), badDialect)
	assertLegacyError(t, got, want)
	_, got = LintWithDialect("SELECT 1", badDialect)
	assertLegacyError(t, got, want)
	_, got = ParseTree(context.Background(), "SELECT 1", WithDialect(string(badDialect)))
	assertLegacyError(t, got, want)
	_, got = ParseReader(context.Background(), strings.NewReader("SELECT 1"), WithMaxBytes(3))
	assertLegacyError(t, got, fmt.Errorf("%w: read %d bytes, cap is %d", ErrTooLarge, 4, 3))
	_, got = ParseReader(context.Background(), nil)
	assertLegacyError(t, got, fmt.Errorf("%w: nil reader", ErrTokenize))
}

func TestWrapErrErrorsIsAllocs(t *testing.T) {
	inner := &sqlerrors.Error{Code: sqlerrors.ErrCodeUnexpectedToken, Message: "unexpected token"}
	wrapped := newWrap(ErrSyntax, inner)
	// Matching only the first sentinel would not exercise inner traversal or
	// the complete multi-error slice. Test hits on both branches and a miss.
	for _, target := range []error{ErrSyntax, inner, ErrTokenize} {
		if allocs := testing.AllocsPerRun(1000, func() { _ = errors.Is(wrapped, target) }); allocs != 0 {
			t.Errorf("errors.Is(%v) allocated %g times; want 0", target, allocs)
		}
	}
	var found *sqlerrors.Error
	if allocs := testing.AllocsPerRun(1000, func() { _ = errors.As(wrapped, &found) }); allocs != 0 {
		t.Errorf("errors.As allocated %g times; want 0", allocs)
	}
	if found != inner {
		t.Fatal("errors.As did not preserve the structured error pointer")
	}
}
