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

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// keywordFieldCase sets one keyword-valued string field of a parsed
// statement. small marks a field whose parser values form a small fixed set,
// which the renderers accept only from an allow-list, so even plain-word text
// outside the set is dropped.
type keywordFieldCase struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
	small   bool
	set     func(t *testing.T, s ast.Statement, v string)
}

func selectOf(t *testing.T, s ast.Statement) *ast.SelectStatement {
	t.Helper()
	sel, ok := s.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", s)
	}
	return sel
}

func createTableOf(t *testing.T, s ast.Statement) *ast.CreateTableStatement {
	t.Helper()
	c, ok := s.(*ast.CreateTableStatement)
	if !ok {
		t.Fatalf("expected *ast.CreateTableStatement, got %T", s)
	}
	return c
}

func overFrame(t *testing.T, s ast.Statement) *ast.WindowFrame {
	t.Helper()
	sel := selectOf(t, s)
	fc, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok || fc.Over == nil || fc.Over.FrameClause == nil {
		t.Fatalf("expected a framed window function, got %T", sel.Columns[0])
	}
	return fc.Over.FrameClause
}

func mergeOf(t *testing.T, s ast.Statement) *ast.MergeStatement {
	t.Helper()
	m, ok := s.(*ast.MergeStatement)
	if !ok || len(m.WhenClauses) == 0 || m.WhenClauses[0].Action == nil {
		t.Fatalf("expected a MERGE with a WHEN clause, got %T", s)
	}
	return m
}

var keywordFieldCases = []keywordFieldCase{
	{"join_type", keywords.DialectGeneric, "SELECT a FROM t LEFT JOIN u ON t.id = u.id", false,
		func(t *testing.T, s ast.Statement, v string) { selectOf(t, s).Joins[0].Type = v }},
	{"index_direction", keywords.DialectGeneric, "CREATE INDEX i ON t (a DESC)", true,
		func(t *testing.T, s ast.Statement, v string) {
			c, ok := s.(*ast.CreateIndexStatement)
			if !ok {
				t.Fatalf("got %T", s)
			}
			c.Columns[0].Direction = v
		}},
	{"truncate_cascade", keywords.DialectPostgreSQL, "TRUNCATE TABLE t CASCADE", true,
		func(t *testing.T, s ast.Statement, v string) {
			tr, ok := s.(*ast.TruncateStatement)
			if !ok {
				t.Fatalf("got %T", s)
			}
			tr.CascadeType = v
		}},
	{"drop_cascade", keywords.DialectGeneric, "DROP TABLE t CASCADE", true,
		func(t *testing.T, s ast.Statement, v string) {
			d, ok := s.(*ast.DropStatement)
			if !ok {
				t.Fatalf("got %T", s)
			}
			d.CascadeType = v
		}},
	{"drop_object_type", keywords.DialectGeneric, "DROP TABLE t", false,
		func(t *testing.T, s ast.Statement, v string) {
			d, ok := s.(*ast.DropStatement)
			if !ok {
				t.Fatalf("got %T", s)
			}
			d.ObjectType = v
		}},
	{"for_lock_type", keywords.DialectPostgreSQL, "SELECT a FROM t FOR UPDATE", true,
		func(t *testing.T, s ast.Statement, v string) { selectOf(t, s).For.LockType = v }},
	{"fetch_type", keywords.DialectGeneric, "SELECT a FROM t ORDER BY a FETCH FIRST 5 ROWS ONLY", true,
		func(t *testing.T, s ast.Statement, v string) { selectOf(t, s).Fetch.FetchType = v }},
	{"column_ref_on_delete", keywords.DialectGeneric, "CREATE TABLE t (a INT REFERENCES r (b) ON DELETE CASCADE)", true,
		func(t *testing.T, s ast.Statement, v string) {
			createTableOf(t, s).Columns[0].Constraints[0].References.OnDelete = v
		}},
	{"table_ref_on_update", keywords.DialectGeneric, "CREATE TABLE t (a INT, FOREIGN KEY (a) REFERENCES r (b) ON UPDATE SET NULL)", true,
		func(t *testing.T, s ast.Statement, v string) {
			createTableOf(t, s).Constraints[0].References.OnUpdate = v
		}},
	{"column_constraint_type", keywords.DialectGeneric, "CREATE TABLE t (a INT NOT NULL)", false,
		func(t *testing.T, s ast.Statement, v string) { createTableOf(t, s).Columns[0].Constraints[0].Type = v }},
	{"table_constraint_type", keywords.DialectGeneric, "CREATE TABLE t (a INT, UNIQUE (a))", false,
		func(t *testing.T, s ast.Statement, v string) { createTableOf(t, s).Constraints[0].Type = v }},
	{"table_option_name", keywords.DialectMySQL, "CREATE TABLE t (a INT) ENGINE = InnoDB", false,
		func(t *testing.T, s ast.Statement, v string) { createTableOf(t, s).Options[0].Name = v }},
	{"partition_by_type", keywords.DialectPostgreSQL, "CREATE TABLE t (a INT) PARTITION BY RANGE (a)", false,
		func(t *testing.T, s ast.Statement, v string) { createTableOf(t, s).PartitionBy.Type = v }},
	{"merge_when_type", keywords.DialectGeneric, "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", false,
		func(t *testing.T, s ast.Statement, v string) { mergeOf(t, s).WhenClauses[0].Type = v }},
	{"merge_action_type", keywords.DialectGeneric, "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", false,
		func(t *testing.T, s ast.Statement, v string) { mergeOf(t, s).WhenClauses[0].Action.ActionType = v }},
	{"window_frame_type", keywords.DialectGeneric, "SELECT SUM(a) OVER (ORDER BY b ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t", true,
		func(t *testing.T, s ast.Statement, v string) { overFrame(t, s).Type = v }},
	{"window_frame_exclude", keywords.DialectPostgreSQL, "SELECT SUM(a) OVER (ORDER BY b ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES) FROM t", true,
		func(t *testing.T, s ast.Statement, v string) { overFrame(t, s).Exclude = v }},
	{"window_frame_start", keywords.DialectGeneric, "SELECT SUM(a) OVER (ORDER BY b ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t", true,
		func(t *testing.T, s ast.Statement, v string) { overFrame(t, s).Start.Type = v }},
	{"window_frame_end", keywords.DialectGeneric, "SELECT SUM(a) OVER (ORDER BY b ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t", true,
		func(t *testing.T, s ast.Statement, v string) { overFrame(t, s).End.Type = v }},
	{"sample_value", keywords.DialectClickHouse, "SELECT a FROM t SAMPLE 1/10 OFFSET 2/10", true,
		func(t *testing.T, s ast.Statement, v string) { selectOf(t, s).Sample.Value = v }},
	{"sample_denominator", keywords.DialectClickHouse, "SELECT a FROM t SAMPLE 1/10 OFFSET 2/10", true,
		func(t *testing.T, s ast.Statement, v string) { selectOf(t, s).Sample.Denominator = v }},
	{"sample_offset", keywords.DialectClickHouse, "SELECT a FROM t SAMPLE 1/10 OFFSET 2/10", true,
		func(t *testing.T, s ast.Statement, v string) { selectOf(t, s).Sample.Offset = v }},
	{"sample_offset_denominator", keywords.DialectClickHouse, "SELECT a FROM t SAMPLE 1/10 OFFSET 2/10", true,
		func(t *testing.T, s ast.Statement, v string) { selectOf(t, s).Sample.OffsetDenominator = v }},
}

// keywordFieldPayloads would end the statement, open a comment or a string,
// or break out of a quote if a renderer wrote them raw.
var keywordFieldPayloads = []string{
	"x; DROP TABLE pwn; --",
	"x\n; DROP TABLE pwn; --",
	"x */; DROP TABLE pwn; /*",
	"x'; DROP TABLE pwn; --",
	"x\"; DROP TABLE pwn; --",
	"x) ; DROP TABLE pwn; --",
}

// TestKeywordFieldsNeverWrittenRaw_PR632 sets each keyword-valued string
// field of a parsed statement to hostile text and checks that no renderer
// (SQL(), compact and readable FormatAST) writes it: keyword fields are
// written only when they are one of the field's known keywords, so a
// hand-built AST cannot inject SQL.
func TestKeywordFieldsNeverWrittenRaw_PR632(t *testing.T) {
	for _, tc := range keywordFieldCases {
		payloads := keywordFieldPayloads
		if tc.small {
			// Plain words outside the known set are dropped too.
			payloads = append(append([]string(nil), payloads...), "pwn", "CASCADE pwn")
		}
		for _, p := range payloads {
			t.Run(tc.name, func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.sql, err)
				}
				defer ast.ReleaseAST(tree)
				tc.set(t, tree.Statements[0], p)
				for name, out := range renderings(tree, tc.dialect) {
					if strings.Contains(strings.ToLower(out), "pwn") {
						t.Errorf("%s writes the %s field %q raw: %s", name, tc.name, p, out)
					}
				}
			})
		}
	}
}

// TestHandBuiltAlterTableActionType_PR632 covers AlterTableStatement, which
// the parser never produces: its action type is keyword text too.
func TestHandBuiltAlterTableActionType_PR632(t *testing.T) {
	for _, p := range keywordFieldPayloads {
		stmt := &ast.AlterTableStatement{ //nolint:staticcheck // AlterTableStatement kept for backward compatibility
			Table:   "t",
			Actions: []ast.AlterTableAction{{Type: p}},
		}
		for name, out := range map[string]string{
			"SQL":        stmt.SQL(),
			"FmtCompact": formatter.FormatStatement(stmt, ast.CompactStyle()),
		} {
			if strings.Contains(out, "pwn") {
				t.Errorf("%s writes the alter action type %q raw: %s", name, p, out)
			}
		}
	}
}

// TestKeywordFieldsParserValuesUnchanged_PR632 pins that every keyword value
// the parser stores for the gated fields still renders and round-trips.
func TestKeywordFieldsParserValuesUnchanged_PR632(t *testing.T) {
	cases := []struct {
		d    keywords.SQLDialect
		in   string
		want []string
	}{
		{keywords.DialectGeneric, "SELECT a FROM t NATURAL LEFT JOIN u", []string{"NATURAL LEFT JOIN u"}},
		{keywords.DialectGeneric, "SELECT a FROM t CROSS JOIN u", []string{"CROSS JOIN u"}},
		{keywords.DialectGeneric, "SELECT a FROM t FULL OUTER JOIN u ON t.id = u.id", []string{"FULL JOIN u"}},
		{keywords.DialectGeneric, "CREATE INDEX i ON t (a ASC, b DESC)", []string{"(a ASC, b DESC)"}},
		{keywords.DialectPostgreSQL, "TRUNCATE TABLE t RESTRICT", []string{"TRUNCATE TABLE t RESTRICT"}},
		{keywords.DialectGeneric, "DROP MATERIALIZED VIEW v CASCADE", []string{"DROP MATERIALIZED VIEW v CASCADE"}},
		{keywords.DialectPostgreSQL, "SELECT a FROM t FOR NO KEY UPDATE", []string{"FOR NO KEY UPDATE"}},
		{keywords.DialectPostgreSQL, "SELECT a FROM t FOR KEY SHARE", []string{"FOR KEY SHARE"}},
		{keywords.DialectGeneric, "SELECT a FROM t ORDER BY a OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY", []string{"FETCH NEXT 5 ROWS ONLY"}},
		{keywords.DialectGeneric, "CREATE TABLE t (a INT REFERENCES r (b) ON DELETE SET DEFAULT ON UPDATE NO ACTION)", []string{"ON DELETE SET DEFAULT ON UPDATE NO ACTION"}},
		{keywords.DialectMySQL, "CREATE TABLE t (a INT AUTO_INCREMENT) ENGINE = InnoDB", []string{"AUTO_INCREMENT", "ENGINE="}},
		{keywords.DialectPostgreSQL, "CREATE TABLE t (a INT) PARTITION BY LIST (a)", []string{"PARTITION BY LIST (a)"}},
		{keywords.DialectGeneric, "MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)", []string{"WHEN NOT MATCHED THEN INSERT"}},
		{keywords.DialectPostgreSQL, "SELECT SUM(a) OVER (ORDER BY b GROUPS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING EXCLUDE NO OTHERS) FROM t",
			[]string{"GROUPS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING EXCLUDE NO OTHERS"}},
		{keywords.DialectGeneric, "SELECT SUM(a) OVER (ORDER BY b RANGE 2 FOLLOWING) FROM t", []string{"RANGE 2 FOLLOWING"}},
		{keywords.DialectClickHouse, "SELECT a FROM t SAMPLE 0.1", []string{"SAMPLE 0.1"}},
		{keywords.DialectClickHouse, "SELECT a FROM t SAMPLE 1/10 OFFSET 2/10", []string{"SAMPLE 1/10 OFFSET 2/10"}},
	}
	for _, tc := range cases {
		rs := assertRoundTrip(t, tc.d, tc.in)
		for name, out := range rs {
			for _, w := range tc.want {
				if name != "FmtReadable" && !strings.Contains(out, w) {
					t.Errorf("[%s] %s of %q = %q, want it to contain %q", tc.d, name, tc.in, out, w)
				}
			}
		}
	}
}

// TestQuotedConstraintNamesRoundTrip_PR632 checks that a table constraint
// name that is a keyword, or that is not lower-case plain, is written quoted
// so it re-parses as the same name, while a plain lower-case name stays bare.
func TestQuotedConstraintNamesRoundTrip_PR632(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`CREATE TABLE t (a INT, CONSTRAINT "key" PRIMARY KEY (a))`, `CONSTRAINT "key" PRIMARY KEY`},
		{`CREATE TABLE t (a INT, CONSTRAINT "index" UNIQUE (a))`, `CONSTRAINT "index" UNIQUE`},
		{`CREATE TABLE t (a INT, CONSTRAINT "default" CHECK (a > 0))`, `CONSTRAINT "default" CHECK`},
		{`CREATE TABLE t (a INT, CONSTRAINT "table" PRIMARY KEY (a))`, `CONSTRAINT "table" PRIMARY KEY`},
		{`CREATE TABLE t (a INT, CONSTRAINT "owner" PRIMARY KEY (a))`, `CONSTRAINT "owner" PRIMARY KEY`},
		// Quoted only for case: rendered bare, like Identifier.SQL().
		{`CREATE TABLE t (a INT, CONSTRAINT "MixedCase" PRIMARY KEY (a))`, `CONSTRAINT MixedCase PRIMARY KEY`},
		{`CREATE TABLE t (a INT, CONSTRAINT PK_USERS PRIMARY KEY (a))`, `CONSTRAINT PK_USERS PRIMARY KEY`},
		{`CREATE TABLE t (a INT, CONSTRAINT pk_t PRIMARY KEY (a))`, `CONSTRAINT pk_t PRIMARY KEY`},
	}
	for _, tc := range cases {
		for _, d := range []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectSQLite} {
			tree, err := gosqlx.ParseWithDialect(tc.in, d)
			if err != nil {
				t.Fatalf("[%s] parse %q: %v", d, tc.in, err)
			}
			wantName := createTableOf(t, tree.Statements[0]).Constraints[0].Name
			for name, out := range renderings(tree, d) {
				if name != "FmtReadable" && !strings.Contains(out, tc.want) {
					t.Errorf("[%s] %s of %q = %q, want it to contain %q", d, name, tc.in, out, tc.want)
				}
				re, err := gosqlx.ParseWithDialect(out, d)
				if err != nil {
					t.Errorf("[%s] %s output %q does not re-parse: %v", d, name, out, err)
					continue
				}
				if got := createTableOf(t, re.Statements[0]).Constraints[0].Name; got != wantName {
					t.Errorf("[%s] %s output %q re-parses with constraint name %q, want %q", d, name, out, got, wantName)
				}
				ast.ReleaseAST(re)
			}
			ast.ReleaseAST(tree)
		}
	}
}

// TestDotlessILikeOperator_PR632 checks that the parser stores the canonical
// LIKE operator for a keyword that only matches LIKE by Unicode case mapping
// (lıke, with a dotless ı), so renderers write plain LIKE.
func TestDotlessILikeOperator_PR632(t *testing.T) {
	for _, in := range []string{
		"SELECT a FROM t WHERE x NOT lıke 'a'",
		"SELECT a FROM t WHERE x lıke 'a'",
	} {
		rs := assertRoundTrip(t, keywords.DialectGeneric, in)
		for name, out := range rs {
			if strings.Contains(out, `"`) || !strings.Contains(out, "LIKE 'a'") {
				t.Errorf("%s of %q = %q, want plain LIKE", name, in, out)
			}
		}
	}
	// ASCII spellings keep their case.
	tree, err := gosqlx.Parse("SELECT a FROM t WHERE x like 'a'")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	if out := tree.SQL(); !strings.Contains(out, "x like 'a'") && !strings.Contains(out, "x LIKE 'a'") {
		t.Errorf("SQL() = %q", out)
	}
}
