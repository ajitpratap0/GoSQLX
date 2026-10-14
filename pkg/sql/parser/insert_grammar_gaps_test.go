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

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// grammarGapCase is one #610 parse case: sql parsed in dialect must render
// as wantSQL, and wantSQL must re-parse to the same SQL() (fixpoint).
type grammarGapCase struct {
	name    string
	dialect string
	sql     string
	wantSQL string
	check   func(t *testing.T, stmt ast.Statement)
}

// parseGapSingle parses sql in dialect and returns its only statement. The
// caller must release the returned AST.
func parseGapSingle(t *testing.T, sql, dialect string) (ast.Statement, *ast.AST) {
	t.Helper()
	tree, err := parseInsertCTEWithDialect(t, sql, dialect)
	if err != nil {
		if tree != nil {
			ast.ReleaseAST(tree)
		}
		t.Fatalf("parse(%q, dialect %q): %v", sql, dialect, err)
	}
	if len(tree.Statements) != 1 {
		n := len(tree.Statements)
		ast.ReleaseAST(tree)
		t.Fatalf("parse(%q, dialect %q): expected 1 statement, got %d", sql, dialect, n)
	}
	return tree.Statements[0], tree
}

func runGrammarGapCases(t *testing.T, cases []grammarGapCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name+"/"+dialectLabel(tc.dialect), func(t *testing.T) {
			stmt, tree := parseGapSingle(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			if tc.check != nil {
				tc.check(t, stmt)
			}
			got := tree.SQL()
			if got != tc.wantSQL {
				t.Fatalf("SQL() = %q, want %q", got, tc.wantSQL)
			}
			_, tree2 := parseGapSingle(t, got, tc.dialect)
			defer ast.ReleaseAST(tree2)
			if again := tree2.SQL(); again != got {
				t.Fatalf("re-parse SQL() = %q, want fixpoint %q", again, got)
			}
		})
	}
}

func dialectLabel(d string) string {
	if d == "" {
		return "generic"
	}
	return d
}

func asInsert(t *testing.T, stmt ast.Statement) *ast.InsertStatement {
	t.Helper()
	ins, ok := stmt.(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected *ast.InsertStatement, got %T", stmt)
	}
	return ins
}

func asUpdate(t *testing.T, stmt ast.Statement) *ast.UpdateStatement {
	t.Helper()
	upd, ok := stmt.(*ast.UpdateStatement)
	if !ok {
		t.Fatalf("expected *ast.UpdateStatement, got %T", stmt)
	}
	return upd
}

// insertSelectSource returns the INSERT's query source as a SelectStatement.
func insertSelectSource(t *testing.T, ins *ast.InsertStatement) *ast.SelectStatement {
	t.Helper()
	sel, ok := ins.Query.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected Query *ast.SelectStatement, got %T", ins.Query)
	}
	return sel
}

func wantReturning(n int) func(t *testing.T, stmt ast.Statement) {
	return func(t *testing.T, stmt ast.Statement) {
		t.Helper()
		ins := asInsert(t, stmt)
		if len(ins.Returning) != n {
			t.Fatalf("len(Returning) = %d, want %d", len(ins.Returning), n)
		}
	}
}

// fromUnaliasedReturning checks the #610 RETURNING case: the FROM table s
// keeps no alias and RETURNING has one item.
func fromUnaliasedReturning(t *testing.T, stmt ast.Statement) {
	t.Helper()
	ins := asInsert(t, stmt)
	sel := insertSelectSource(t, ins)
	if len(sel.From) != 1 || sel.From[0].Name != "s" || sel.From[0].Alias != "" {
		t.Fatalf("FROM = %+v, want single unaliased table s", sel.From)
	}
	if len(ins.Returning) != 1 {
		t.Fatalf("len(Returning) = %d, want 1", len(ins.Returning))
	}
}

func parenSource(wantCols int) func(t *testing.T, stmt ast.Statement) {
	return func(t *testing.T, stmt ast.Statement) {
		t.Helper()
		ins := asInsert(t, stmt)
		if len(ins.Columns) != wantCols {
			t.Fatalf("len(Columns) = %d, want %d", len(ins.Columns), wantCols)
		}
		if ins.Query == nil {
			t.Fatal("Query is nil, want the parenthesized source")
		}
		if len(ins.Values) != 0 {
			t.Fatalf("len(Values) = %d, want 0", len(ins.Values))
		}
	}
}

func TestInsertGrammarGaps_ReturningAfterSelect(t *testing.T) {
	runGrammarGapCases(t, []grammarGapCase{
		{
			name: "select star from s returning id", dialect: "postgresql",
			sql:     "INSERT INTO t SELECT * FROM s RETURNING id",
			wantSQL: "INSERT INTO t SELECT * FROM s RETURNING id",
			check:   fromUnaliasedReturning,
		},
		{
			name: "column list returning star", dialect: "postgresql",
			sql:     "INSERT INTO t (a) SELECT b FROM s RETURNING *",
			wantSQL: "INSERT INTO t (a) SELECT b FROM s RETURNING *",
			check: func(t *testing.T, stmt ast.Statement) {
				ins := asInsert(t, stmt)
				fromUnaliasedReturning(t, stmt)
				id, ok := ins.Returning[0].(*ast.Identifier)
				if !ok || id.Name != "*" {
					t.Fatalf("Returning[0] = %#v, want Identifier *", ins.Returning[0])
				}
			},
		},
		{
			name: "lowercase select source", dialect: "postgresql",
			sql:     "insert into t select * from s returning id",
			wantSQL: "INSERT INTO t SELECT * FROM s RETURNING id",
			check:   fromUnaliasedReturning,
		},
		{
			name: "lowercase values source", dialect: "postgresql",
			sql:     "insert into t (a) values (1) returning a",
			wantSQL: "INSERT INTO t (a) VALUES (1) RETURNING a",
			check:   wantReturning(1),
		},
		{
			name: "union source", dialect: "postgresql",
			sql:     "INSERT INTO t SELECT a FROM s UNION SELECT b FROM u RETURNING a",
			wantSQL: "INSERT INTO t SELECT a FROM s UNION SELECT b FROM u RETURNING a",
			check: func(t *testing.T, stmt ast.Statement) {
				ins := asInsert(t, stmt)
				if _, ok := ins.Query.(*ast.SetOperation); !ok {
					t.Fatalf("Query = %T, want *ast.SetOperation", ins.Query)
				}
				if len(ins.Returning) != 1 {
					t.Fatalf("len(Returning) = %d, want 1", len(ins.Returning))
				}
			},
		},
		{
			name: "cross join source", dialect: "postgresql",
			sql:     "INSERT INTO t SELECT a FROM s CROSS JOIN u RETURNING a",
			wantSQL: "INSERT INTO t SELECT a FROM s CROSS JOIN u RETURNING a",
			check: func(t *testing.T, stmt ast.Statement) {
				ins := asInsert(t, stmt)
				sel := insertSelectSource(t, ins)
				if len(sel.Joins) != 1 || sel.Joins[0].Right.Name != "u" || sel.Joins[0].Right.Alias != "" {
					t.Fatalf("Joins = %+v, want one join to unaliased u", sel.Joins)
				}
				if len(ins.Returning) != 1 {
					t.Fatalf("len(Returning) = %d, want 1", len(ins.Returning))
				}
			},
		},
		{
			name: "from-less select source", dialect: "postgresql",
			sql:     "INSERT INTO t SELECT 1 RETURNING id",
			wantSQL: "INSERT INTO t SELECT 1 RETURNING id",
			check:   wantReturning(1),
		},
		{
			name: "leading cte", dialect: "postgresql",
			sql:     "WITH c AS (SELECT 1 AS a) INSERT INTO t SELECT a FROM c RETURNING a",
			wantSQL: "WITH c AS (SELECT 1 AS a) INSERT INTO t SELECT a FROM c RETURNING a",
			check:   wantReturning(1),
		},
		{
			name: "explicit alias control", dialect: "postgresql",
			sql:     "INSERT INTO t SELECT * FROM s AS x RETURNING id",
			wantSQL: "INSERT INTO t SELECT * FROM s x RETURNING id",
			check: func(t *testing.T, stmt ast.Statement) {
				sel := insertSelectSource(t, asInsert(t, stmt))
				if len(sel.From) != 1 || sel.From[0].Alias != "x" {
					t.Fatalf("FROM = %+v, want alias x", sel.From)
				}
			},
		},
		{
			name: "on conflict then returning", dialect: "postgresql",
			sql:     "INSERT INTO t SELECT * FROM s ON CONFLICT DO NOTHING RETURNING id",
			wantSQL: "INSERT INTO t SELECT * FROM s ON CONFLICT DO NOTHING RETURNING id",
			check: func(t *testing.T, stmt ast.Statement) {
				ins := asInsert(t, stmt)
				if ins.OnConflict == nil {
					t.Fatal("OnConflict is nil")
				}
				fromUnaliasedReturning(t, stmt)
			},
		},
	})
}

func TestInsertGrammarGaps_DefaultValues(t *testing.T) {
	check := func(t *testing.T, stmt ast.Statement) {
		ins := asInsert(t, stmt)
		if !ins.DefaultValues {
			t.Fatal("DefaultValues = false, want true")
		}
		if len(ins.Columns) != 0 || len(ins.Values) != 0 || ins.Query != nil {
			t.Fatalf("Columns=%d Values=%d Query=%v, want all empty", len(ins.Columns), len(ins.Values), ins.Query)
		}
	}
	var cases []grammarGapCase
	for _, d := range []string{"", "postgresql", "sqlserver", "sqlite"} {
		cases = append(cases, grammarGapCase{
			name: "default values", dialect: d,
			sql:     "INSERT INTO t DEFAULT VALUES",
			wantSQL: "INSERT INTO t DEFAULT VALUES",
			check:   check,
		})
	}
	cases = append(cases,
		grammarGapCase{
			name: "default values returning", dialect: "postgresql",
			sql:     "INSERT INTO t DEFAULT VALUES RETURNING id",
			wantSQL: "INSERT INTO t DEFAULT VALUES RETURNING id",
			check: func(t *testing.T, stmt ast.Statement) {
				check(t, stmt)
				wantReturning(1)(t, stmt)
			},
		},
		grammarGapCase{
			name: "default values on conflict", dialect: "postgresql",
			sql:     "INSERT INTO t DEFAULT VALUES ON CONFLICT DO NOTHING",
			wantSQL: "INSERT INTO t DEFAULT VALUES ON CONFLICT DO NOTHING",
			check:   check,
		},
	)
	runGrammarGapCases(t, cases)
}

func TestInsertGrammarGaps_SetSyntax(t *testing.T) {
	check := func(wantCells int) func(t *testing.T, stmt ast.Statement) {
		return func(t *testing.T, stmt ast.Statement) {
			ins := asInsert(t, stmt)
			if !ins.SetSyntax {
				t.Fatal("SetSyntax = false, want true")
			}
			if len(ins.Columns) != wantCells {
				t.Fatalf("len(Columns) = %d, want %d", len(ins.Columns), wantCells)
			}
			for i, want := range []string{"a", "b"}[:wantCells] {
				id, ok := ins.Columns[i].(*ast.Identifier)
				if !ok || id.Name != want {
					t.Fatalf("Columns[%d] = %#v, want Identifier %s", i, ins.Columns[i], want)
				}
			}
			if len(ins.Values) != 1 || len(ins.Values[0]) != wantCells {
				t.Fatalf("Values = %v, want one row of %d cells", ins.Values, wantCells)
			}
		}
	}
	runGrammarGapCases(t, []grammarGapCase{
		{
			name: "set", dialect: "mysql",
			sql:     "INSERT INTO t SET a = 1, b = 2",
			wantSQL: "INSERT INTO t SET a = 1, b = 2",
			check:   check(2),
		},
		{
			name: "set", dialect: "mariadb",
			sql:     "INSERT INTO t SET a = 1, b = 2",
			wantSQL: "INSERT INTO t SET a = 1, b = 2",
			check:   check(2),
		},
		{
			name: "set string", dialect: "mariadb",
			sql:     "INSERT INTO t SET a = 1, b = 'x'",
			wantSQL: "INSERT INTO t SET a = 1, b = 'x'",
			check:   check(2),
		},
	})
}

func TestInsertGrammarGaps_ParenthesizedSource(t *testing.T) {
	var cases []grammarGapCase
	for _, d := range []string{"", "postgresql", "mysql"} {
		cases = append(cases, grammarGapCase{
			name: "paren select", dialect: d,
			sql:     "INSERT INTO t (SELECT * FROM s)",
			wantSQL: "INSERT INTO t SELECT * FROM s",
			check:   parenSource(0),
		})
	}
	cases = append(cases,
		grammarGapCase{
			name: "column list then paren select", dialect: "postgresql",
			sql:     "INSERT INTO t (a, b) (SELECT x, y FROM s)",
			wantSQL: "INSERT INTO t (a, b) SELECT x, y FROM s",
			check:   parenSource(2),
		},
		grammarGapCase{
			name: "double paren select", dialect: "",
			sql:     "INSERT INTO t ((SELECT * FROM s))",
			wantSQL: "INSERT INTO t SELECT * FROM s",
			check:   parenSource(0),
		},
		grammarGapCase{
			name: "paren union", dialect: "",
			sql:     "INSERT INTO t (SELECT a FROM s UNION SELECT b FROM u)",
			wantSQL: "INSERT INTO t SELECT a FROM s UNION SELECT b FROM u",
			check:   parenSource(0),
		},
		grammarGapCase{
			name: "paren with", dialect: "",
			sql:     "INSERT INTO t (WITH c AS (SELECT 1) SELECT * FROM c)",
			wantSQL: "INSERT INTO t WITH c AS (SELECT 1) SELECT * FROM c",
			check:   parenSource(0),
		},
		grammarGapCase{
			name: "paren select returning", dialect: "postgresql",
			sql:     "INSERT INTO t (SELECT * FROM s) RETURNING id",
			wantSQL: "INSERT INTO t SELECT * FROM s RETURNING id",
			check: func(t *testing.T, stmt ast.Statement) {
				parenSource(0)(t, stmt)
				fromUnaliasedReturning(t, stmt)
			},
		},
	)
	runGrammarGapCases(t, cases)
}

func TestUpdateFrom(t *testing.T) {
	fromNames := func(want ...string) func(t *testing.T, stmt ast.Statement) {
		return func(t *testing.T, stmt ast.Statement) {
			upd := asUpdate(t, stmt)
			if len(upd.From) != len(want) {
				t.Fatalf("len(From) = %d, want %d", len(upd.From), len(want))
			}
			for i, name := range want {
				if upd.From[i].Name != name || upd.From[i].Alias != "" {
					t.Fatalf("From[%d] = %+v, want unaliased %s", i, upd.From[i], name)
				}
			}
		}
	}
	runGrammarGapCases(t, []grammarGapCase{
		{
			name: "from where", dialect: "postgresql",
			sql:     "UPDATE t SET a = s.b FROM s WHERE t.id = s.id",
			wantSQL: "UPDATE t SET a = s.b FROM s WHERE t.id = s.id",
			check:   fromNames("s"),
		},
		{
			name: "from list returning", dialect: "postgresql",
			sql:     "UPDATE t SET a = s.b FROM s, u WHERE t.id = s.id RETURNING t.a",
			wantSQL: "UPDATE t SET a = s.b FROM s, u WHERE t.id = s.id RETURNING t.a",
			check:   fromNames("s", "u"),
		},
		{
			name: "from returning", dialect: "postgresql",
			sql:     "UPDATE t SET a = s.b FROM s RETURNING id",
			wantSQL: "UPDATE t SET a = s.b FROM s RETURNING id",
			check:   fromNames("s"),
		},
		{
			name: "from where", dialect: "sqlserver",
			sql:     "UPDATE t SET a = s.b FROM s WHERE t.id = s.id",
			wantSQL: "UPDATE t SET a = s.b FROM s WHERE t.id = s.id",
			check:   fromNames("s"),
		},
	})
}

func TestInsertGrammarGapsErrors(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		sql     string
		wantErr string
	}{
		{"set outside mysql", "postgresql", "INSERT INTO t SET a = 1", "VALUES, SELECT, or WITH"},
		{"set after column list", "mysql", "INSERT INTO t (a) SET a = 1", ""},
		{"default values after column list", "postgresql", "INSERT INTO t (a) DEFAULT VALUES", "DEFAULT VALUES cannot follow a column list"},
		{"bare default", "", "INSERT INTO t1 (a) DEFAULT", "VALUES, SELECT, or WITH"},
		{"unclosed paren source", "", "INSERT INTO t (SELECT * FROM s", ")"},
		{"paren non-query source", "", "INSERT INTO t (a) (1)", "VALUES, SELECT, or WITH"},
		{"update from join", "postgresql", "UPDATE t SET a = s.b FROM s JOIN u ON s.id = u.id WHERE t.id = s.id", "JOIN in UPDATE ... FROM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseInsertCTEWithDialect(t, tt.sql, tt.dialect)
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			if err == nil {
				t.Fatalf("parse(%q, %q): expected error, got nil", tt.sql, tt.dialect)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parse(%q, %q) error = %q, want it to contain %q", tt.sql, tt.dialect, err.Error(), tt.wantErr)
			}
		})
	}
}

// selectFromAlias parses sql as a SELECT and returns FROM[0].Alias.
func selectFromAlias(t *testing.T, p *Parser, sql, dialect string) string {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if dialect != "" {
		tkz.SetDialect(keywords.SQLDialect(dialect))
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenize(%q): %v", sql, err)
	}
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse(%q, %q): %v", sql, dialect, err)
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.From) != 1 {
		t.Fatalf("len(From) = %d, want 1", len(sel.From))
	}
	return sel.From[0].Alias
}

// TestReturningAliasOutsideDML pins that RETURNING stays a valid implicit
// alias outside an INSERT source or UPDATE ... FROM list (#610).
func TestReturningAliasOutsideDML(t *testing.T) {
	for _, d := range []string{"", "postgresql"} {
		t.Run("bare/"+dialectLabel(d), func(t *testing.T) {
			p := NewParser(WithDialect(d))
			defer p.Release()
			if got := selectFromAlias(t, p, "SELECT * FROM s returning", d); got != "returning" {
				t.Fatalf("Alias = %q, want %q", got, "returning")
			}
		})
	}
	t.Run("as returning re-parses", func(t *testing.T) {
		_, tree := parseGapSingle(t, "SELECT * FROM s AS returning", "postgresql")
		defer ast.ReleaseAST(tree)
		_, tree2 := parseGapSingle(t, tree.SQL(), "postgresql")
		ast.ReleaseAST(tree2)
	})
	t.Run("quoted", func(t *testing.T) {
		p := NewParser()
		defer p.Release()
		if got := selectFromAlias(t, p, `SELECT * FROM s "RETURNING"`, ""); got != "RETURNING" {
			t.Fatalf("Alias = %q, want %q", got, "RETURNING")
		}
	})
}

// TestDMLReturningFlagRestored pins that the INSERT-source context flag is
// restored on error paths and cleared by Reset (#610).
func TestDMLReturningFlagRestored(t *testing.T) {
	const dialect = "postgresql"
	parseErr := func(p *Parser, sql string) {
		t.Helper()
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		tkz.SetDialect(keywords.SQLDialect(dialect))
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			t.Fatalf("Tokenize(%q): %v", sql, err)
		}
		tree, err := p.ParseFromModelTokens(tokens)
		if tree != nil {
			ast.ReleaseAST(tree)
		}
		if err == nil {
			t.Fatalf("parse(%q): expected error", sql)
		}
	}

	t.Run("same instance", func(t *testing.T) {
		p := NewParser(WithDialect(dialect))
		defer p.Release()
		parseErr(p, "INSERT INTO t SELECT * FROM (")
		if p.dmlReturning {
			t.Fatal("dmlReturning still set after a failed INSERT source parse")
		}
		if got := selectFromAlias(t, p, "SELECT * FROM s returning", dialect); got != "returning" {
			t.Fatalf("Alias = %q, want %q", got, "returning")
		}
	})
	t.Run("update from error", func(t *testing.T) {
		p := NewParser(WithDialect(dialect))
		defer p.Release()
		parseErr(p, "UPDATE t SET a = 1 FROM (")
		if p.dmlReturning {
			t.Fatal("dmlReturning still set after a failed UPDATE ... FROM parse")
		}
	})
	t.Run("reset clears", func(t *testing.T) {
		p := GetParser()
		p.dmlReturning = true
		PutParser(p)
		if p.dmlReturning {
			t.Fatal("Reset did not clear dmlReturning")
		}
		p2 := GetParser()
		defer PutParser(p2)
		p2.ApplyOptions(WithDialect(dialect))
		if got := selectFromAlias(t, p2, "SELECT * FROM s returning", dialect); got != "returning" {
			t.Fatalf("Alias = %q, want %q", got, "returning")
		}
	})
}

// TestDMLReturningQuotedAlias pins that a backtick- or bracket-quoted alias
// named returning stays an alias inside an INSERT source or UPDATE ... FROM
// list. Quoting is the escape hatch for keyword-named identifiers, so only an
// unquoted RETURNING may start the DML RETURNING clause (#610 review).
func TestDMLReturningQuotedAlias(t *testing.T) {
	insertFromAlias := func(wantReturning int) func(t *testing.T, stmt ast.Statement) {
		return func(t *testing.T, stmt ast.Statement) {
			t.Helper()
			ins := asInsert(t, stmt)
			sel := insertSelectSource(t, ins)
			if len(sel.From) != 1 || sel.From[0].Name != "s" || sel.From[0].Alias != "returning" {
				t.Fatalf("FROM = %+v, want s aliased returning", sel.From)
			}
			if len(ins.Returning) != wantReturning {
				t.Fatalf("len(Returning) = %d, want %d", len(ins.Returning), wantReturning)
			}
		}
	}
	insertJoinAlias := func(t *testing.T, stmt ast.Statement) {
		t.Helper()
		sel := insertSelectSource(t, asInsert(t, stmt))
		if len(sel.Joins) != 1 {
			t.Fatalf("len(Joins) = %d, want 1", len(sel.Joins))
		}
		if got := sel.Joins[0].Right.Alias; got != "returning" {
			t.Fatalf("join alias = %q, want %q", got, "returning")
		}
	}
	updateFromAlias := func(t *testing.T, stmt ast.Statement) {
		t.Helper()
		upd := asUpdate(t, stmt)
		if len(upd.From) != 1 || upd.From[0].Name != "s" || upd.From[0].Alias != "returning" {
			t.Fatalf("From = %+v, want s aliased returning", upd.From)
		}
	}
	nestedAlias := func(t *testing.T, stmt ast.Statement) {
		t.Helper()
		sel := insertSelectSource(t, asInsert(t, stmt))
		if len(sel.From) != 1 || sel.From[0].Subquery == nil {
			t.Fatalf("FROM = %+v, want one derived table", sel.From)
		}
		inner := sel.From[0].Subquery
		if len(inner.From) != 1 || inner.From[0].Alias != "returning" {
			t.Fatalf("inner FROM = %+v, want s aliased returning", inner.From)
		}
	}

	cases := []struct {
		name, dialect, sql string
		check              func(t *testing.T, stmt ast.Statement)
	}{
		{"insert from alias where", "mysql", "INSERT INTO t SELECT * FROM s `returning` WHERE `returning`.a = 1", insertFromAlias(0)},
		{"insert from alias where", "mariadb", "INSERT INTO t SELECT * FROM s `returning` WHERE `returning`.a = 1", insertFromAlias(0)},
		{"insert from alias eof", "mysql", "INSERT INTO t SELECT * FROM s `returning`", insertFromAlias(0)},
		{"insert from alias where", "sqlserver", "INSERT INTO t SELECT * FROM s [returning] WHERE [returning].id = 1", insertFromAlias(0)},
		{"insert from alias then returning", "postgresql", "INSERT INTO t SELECT * FROM s `returning` RETURNING id", insertFromAlias(1)},
		{"insert join alias", "mysql", "INSERT INTO t SELECT * FROM s JOIN r `returning` ON s.id = `returning`.id", insertJoinAlias},
		{"insert join alias", "sqlserver", "INSERT INTO t SELECT * FROM s JOIN r [returning] ON s.id = [returning].id", insertJoinAlias},
		{"insert nested subquery alias", "mysql", "INSERT INTO t SELECT * FROM (SELECT * FROM s `returning`) x", nestedAlias},
		{"update from alias", "sqlserver", "UPDATE t SET a = 1 FROM s [returning] WHERE t.id = [returning].id", updateFromAlias},
		{"update from alias", "postgresql", "UPDATE t SET a = 1 FROM s `returning` WHERE t.id = `returning`.id", updateFromAlias},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/"+dialectLabel(tc.dialect), func(t *testing.T) {
			stmt, tree := parseGapSingle(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, stmt)
		})
	}
}

// TestDMLReturningNestedScopes pins that the RETURNING stop applies only to the
// outermost INSERT source query: nested derived tables, subqueries and CTE
// bodies, and aliases that cannot start a RETURNING clause, keep parsing
// "returning" as an ordinary identifier (#610 review).
func TestDMLReturningNestedScopes(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"cte body", "INSERT INTO t WITH c AS (SELECT * FROM s returning) SELECT * FROM c"},
		{"in subquery", "INSERT INTO t SELECT a FROM s WHERE a IN (SELECT b FROM r returning)"},
		{"exists subquery", "INSERT INTO t SELECT a FROM s WHERE EXISTS (SELECT 1 FROM r returning)"},
		{"scalar subquery", "INSERT INTO t SELECT (SELECT max(b) FROM r returning) FROM s"},
		{"derived table", "INSERT INTO t SELECT a FROM (SELECT a FROM r) returning"},
		{"join alias on", "INSERT INTO t SELECT * FROM s JOIN r returning ON s.id = returning.id"},
		{"update from subquery", "UPDATE t SET a = 1 FROM (SELECT a FROM r returning) x WHERE t.id = x.a"},
		{"update from alias then where", "UPDATE t SET a = 1 FROM s returning WHERE t.id = returning.id"},
	}
	for _, d := range []string{"mysql", "sqlserver", "snowflake", "clickhouse"} {
		for _, tc := range cases {
			t.Run(tc.name+"/"+d, func(t *testing.T) {
				tree, err := parseInsertCTEWithDialect(t, tc.sql, d)
				if tree != nil {
					defer ast.ReleaseAST(tree)
				}
				if err != nil {
					t.Fatalf("parse(%q, %s): %v", tc.sql, d, err)
				}
			})
		}
	}

	// The outermost RETURNING clause is still recognised.
	for _, sql := range []string{
		"INSERT INTO t SELECT a FROM s WHERE a IN (SELECT b FROM r) RETURNING id",
		"INSERT INTO t WITH c AS (SELECT * FROM s) SELECT * FROM c RETURNING id",
		"INSERT INTO t SELECT a FROM (SELECT a FROM r) d RETURNING id",
	} {
		stmt, tree := parseGapSingle(t, sql, "postgresql")
		ins, ok := stmt.(*ast.InsertStatement)
		if !ok {
			ast.ReleaseAST(tree)
			t.Fatalf("parse(%q): got %T", sql, stmt)
		}
		if len(ins.Returning) != 1 {
			ast.ReleaseAST(tree)
			t.Fatalf("parse(%q): Returning = %d, want 1", sql, len(ins.Returning))
		}
		ast.ReleaseAST(tree)
	}
}
