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

package parser_test

import (
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Issue #616: parser error builders were handed a human-readable sentence as
// their `sql` argument, which becomes Error.Context.SQL and is printed as the
// source line of the query. The sentence belongs in Error.Hint.

func TestIssue616_NoHintTextAsSourceSnippet(t *testing.T) {
	ch := keywords.DialectClickHouse
	tests := []struct {
		name    string
		sql     string
		dialect keywords.SQLDialect
		code    goerrors.ErrorCode
		msg     string
		col     int
		hint    string
	}{
		{"where", "SELECT a FROM t WHERE ) ", "", goerrors.ErrCodeExpectedToken, "expected expression after WHERE, got RPAREN", 23, "WHERE clause requires a boolean expression"},
		{"from eof", "SELECT a FROM", "", goerrors.ErrCodeExpectedToken, "expected table name, got EOF", 14, "FROM clause requires at least one table reference"},
		{"from semicolon", "SELECT a FROM;", "", goerrors.ErrCodeExpectedToken, "expected table name, got SEMICOLON", 14, "FROM clause requires at least one table reference"},
		{"select list", "SELECT FROM t", "", goerrors.ErrCodeExpectedToken, "expected column expression, got FROM", 8, "SELECT requires at least one column expression before FROM"},

		{"prewhere rparen", "SELECT a FROM t PREWHERE ) ", ch, goerrors.ErrCodeExpectedToken, "expected expression after PREWHERE", 26, "PREWHERE clause requires a boolean expression"},
		{"prewhere eof", "SELECT a FROM t PREWHERE", ch, goerrors.ErrCodeExpectedToken, "expected expression after PREWHERE", 25, "PREWHERE clause requires a boolean expression"},
		{"sample eof", "SELECT * FROM t FINAL SAMPLE", ch, goerrors.ErrCodeExpectedToken, "expected sampling size after SAMPLE", 29, "SAMPLE clause requires a numeric argument"},
		{"sample semicolon", "SELECT * FROM t FINAL SAMPLE;", ch, goerrors.ErrCodeExpectedToken, "expected sampling size after SAMPLE", 29, "SAMPLE clause requires a numeric argument"},
		{"sample non-numeric", "SELECT * FROM t FINAL SAMPLE x", ch, goerrors.ErrCodeExpectedToken, "expected numeric literal after SAMPLE", 30, "SAMPLE clause requires a numeric argument (ratio, row count, or N/D fraction)"},
		{"sample denominator", "SELECT * FROM t FINAL SAMPLE 1/", ch, goerrors.ErrCodeExpectedToken, "expected denominator after /", 32, "SAMPLE N/D fraction requires an integer denominator"},
		{"sample offset", "SELECT * FROM t SAMPLE 1/10 OFFSET", ch, goerrors.ErrCodeExpectedToken, "expected numeric literal after SAMPLE ... OFFSET", 35, "SAMPLE OFFSET requires a numeric argument"},
		{"sample offset denominator", "SELECT * FROM t SAMPLE 1/10 OFFSET 1/ ) ", ch, goerrors.ErrCodeExpectedToken, "expected denominator after OFFSET /", 39, "SAMPLE OFFSET N/D fraction requires an integer denominator"},

		{"cast type param", "SELECT CAST(a AS DECIMAL(,2)) FROM t", "", goerrors.ErrCodeInvalidSyntax, "expected numeric type parameter", 26, "Use CAST(expr AS TYPE(precision[, scale]))"},
		{"interval", "SELECT INTERVAL FROM t", "", goerrors.ErrCodeInvalidSyntax, "expected string literal or number after INTERVAL keyword", 17, "Use INTERVAL '1 day' or INTERVAL 1 DAY syntax"},
		{"empty subscript", "SELECT arr[] FROM t", "", goerrors.ErrCodeInvalidSyntax, "empty array subscript [] is not allowed", 12, "Use arr[index] or arr[start:end] syntax"},
		{"cast operator type param", "SELECT a::DECIMAL('x') FROM t", "", goerrors.ErrCodeInvalidSyntax, "expected numeric type parameter", 19, "Use TYPE(precision[, scale]) syntax"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.dialect == "" {
				_, err = gosqlx.Parse(tt.sql)
			} else {
				_, err = gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			}
			assertIssue616Error(t, err, tt.sql, tt.code, tt.msg, 1, tt.col, tt.hint)
		})
	}
}

func assertIssue616Error(t *testing.T, err error, sql string, code goerrors.ErrorCode, msg string, line, col int, hint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error for %q", sql)
	}
	var pe *goerrors.Error
	if !errors.As(err, &pe) {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if pe.Code != code {
		t.Errorf("code = %s, want %s", pe.Code, code)
	}
	if !strings.Contains(err.Error(), msg) {
		t.Errorf("error %q does not contain %q", err.Error(), msg)
	}
	if pe.Location.Line != line || pe.Location.Column != col {
		t.Errorf("location = %d:%d, want %d:%d", pe.Location.Line, pe.Location.Column, line, col)
	}
	if pe.Context != nil && pe.Context.SQL != "" && pe.Context.SQL != sql {
		t.Errorf("Context.SQL = %q, want empty or the real source %q", pe.Context.SQL, sql)
	}
	if pe.Hint != hint {
		t.Errorf("Hint = %q, want %q", pe.Hint, hint)
	}
	if strings.Contains(err.Error(), "| "+hint) {
		t.Errorf("hint text printed as a source line:\n%s", err.Error())
	}
}

// TestIssue616_WrappedOperandErrorsHaveNoTokenSnippet covers operator paths
// that wrapped an operand error and passed the current token's text as `sql`,
// which printed a fake "1 | )" source line with the caret at the real column.
func TestIssue616_WrappedOperandErrorsHaveNoTokenSnippet(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		dialect keywords.SQLDialect
		msg     string
		col     int
	}{
		{"between lower", "SELECT * FROM t WHERE a BETWEEN ) AND 2", "", "failed to parse BETWEEN lower bound", 33},
		{"between upper", "SELECT * FROM t WHERE a BETWEEN 1 AND )", "", "failed to parse BETWEEN upper bound", 39},
		{"like pattern", "SELECT * FROM t WHERE a LIKE )", "", "failed to parse LIKE pattern", 30},
		{"regexp pattern", "SELECT * FROM t WHERE a REGEXP )", keywords.DialectMySQL, "failed to parse REGEXP pattern", 32},
		{"in subquery", "SELECT * FROM t WHERE a IN (SELECT FROM x)", "", "failed to parse IN subquery", 36},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.dialect == "" {
				_, err = gosqlx.Parse(tt.sql)
			} else {
				_, err = gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			}
			if err == nil {
				t.Fatalf("expected an error for %q", tt.sql)
			}
			var pe *goerrors.Error
			if !errors.As(err, &pe) {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if pe.Code != goerrors.ErrCodeInvalidSyntax {
				t.Errorf("code = %s, want %s", pe.Code, goerrors.ErrCodeInvalidSyntax)
			}
			if !strings.Contains(pe.Message, tt.msg) {
				t.Errorf("message %q does not contain %q", pe.Message, tt.msg)
			}
			if pe.Location.Line != 1 || pe.Location.Column != tt.col {
				t.Errorf("location = %d:%d, want 1:%d", pe.Location.Line, pe.Location.Column, tt.col)
			}
			if pe.Context != nil && pe.Context.SQL != "" && pe.Context.SQL != tt.sql {
				t.Errorf("Context.SQL = %q, want empty or the real source %q", pe.Context.SQL, tt.sql)
			}
			if pe.Cause == nil {
				t.Errorf("Cause is nil, want the wrapped operand error")
			}
		})
	}
}

func TestIssue616_StrictModeEmptyStatementContext(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		hint string
	}{
		{"empty input", "", "provide at least one SQL statement"},
		{"extra semicolon", "SELECT 1;;", "remove extra semicolons or disable strict mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			toks, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenize: %v", err)
			}
			p := parser.NewParser(parser.WithStrictMode())
			defer p.Release()
			_, err = p.ParseFromModelTokens(toks)
			if err == nil {
				t.Fatalf("expected strict-mode error for %q", tt.sql)
			}
			var pe *goerrors.Error
			if !errors.As(err, &pe) {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if pe.Code != goerrors.ErrCodeInvalidSyntax {
				t.Errorf("code = %s, want %s", pe.Code, goerrors.ErrCodeInvalidSyntax)
			}
			if pe.Context != nil && pe.Context.SQL != "" && pe.Context.SQL != tt.sql {
				t.Errorf("Context.SQL = %q, want empty or the real source %q", pe.Context.SQL, tt.sql)
			}
			if pe.Hint != tt.hint {
				t.Errorf("Hint = %q, want %q", pe.Hint, tt.hint)
			}
			if strings.Contains(err.Error(), "| "+tt.hint) {
				t.Errorf("hint text printed as a source line:\n%s", err.Error())
			}
		})
	}
}

// TestIssue616_NoLiteralSQLArgInParserErrorBuilders fails if any non-test file
// in the parser package passes anything other than the literal "" as the `sql`
// parameter of a pkg/errors builder. The parser does not hold the query source,
// so any other value (a hint sentence, the current token's text) would be
// printed as a bogus source line. The only exceptions are the expressions in
// realSourceSQLArgs, which hold the caller's full query text.
func TestIssue616_NoLiteralSQLArgInParserErrorBuilders(t *testing.T) {
	const errorsImport = "github.com/ajitpratap0/GoSQLX/pkg/errors"
	// realSourceSQLArgs are `sql` argument expressions that carry the real
	// query source (validate.go receives the raw input as bytes or a string;
	// sqlText.source returns it).
	realSourceSQLArgs := map[string]bool{"string(input)": true, "in.source()": true}
	fset := token.NewFileSet()

	// builder name -> flattened index of its `sql` parameter
	sqlIdx := map[string]int{}
	bf, err := goparser.ParseFile(fset, filepath.Join("..", "..", "errors", "builders.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse builders.go: %v", err)
	}
	for _, d := range bf.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || !fd.Name.IsExported() || fd.Type.Params == nil {
			continue
		}
		i := 0
		for _, f := range fd.Type.Params.List {
			n := len(f.Names)
			if n == 0 {
				n = 1
			}
			for j := 0; j < n; j++ {
				if j < len(f.Names) && f.Names[j].Name == "sql" {
					sqlIdx[fd.Name.Name] = i
				}
				i++
			}
		}
	}
	if len(sqlIdx) == 0 {
		t.Fatal("found no builders with a sql parameter; guard is broken")
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := goparser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		alias := ""
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if path != errorsImport {
				continue
			}
			alias = "errors"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
		}
		if alias == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != alias {
				return true
			}
			idx, ok := sqlIdx[sel.Sel.Name]
			if !ok || idx >= len(call.Args) {
				return true
			}
			arg := call.Args[idx]
			if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil && v == "" {
					return true
				}
			}
			expr := types.ExprString(arg)
			if realSourceSQLArgs[expr] {
				return true
			}
			offenders = append(offenders, fset.Position(arg.Pos()).String()+": "+sel.Sel.Name+" sql="+expr)
			return true
		})
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("%d builder call(s) pass something other than \"\" as sql (use \"\", WithHint for hints, WithCause for wrapped errors):\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}
