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
	"strings"
	"testing"

	pkgformatter "github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseWithDialect tokenizes and parses sql with the CLI's dialect-aware
// tokenizer and parser. The caller must release the returned AST.
func parseWithDialect(t *testing.T, sql, dialect string) (*ast.AST, error) {
	t.Helper()
	tkz, release, err := tokenizerForDialect(dialect)
	if err != nil {
		return nil, err
	}
	defer release()
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return nil, err
	}
	return parserForDialect(dialect).ParseFromModelTokens(tokens)
}

// formatWith runs the CLI formatSQL path with the given options.
func formatWith(sql string, opts CLIFormatterOptions) (string, error) {
	var out, errBuf bytes.Buffer
	return NewFormatter(&out, &errBuf, opts).formatSQL(sql)
}

// assertRoundTrip checks that formatted re-parses with dialect to a tree whose
// SQL() matches the original input's SQL() (ignoring case), with the same
// statement count.
func assertRoundTrip(t *testing.T, input, formatted, dialect string) {
	t.Helper()
	orig, err := parseWithDialect(t, input, dialect)
	if err != nil {
		t.Fatalf("input does not parse: %v", err)
	}
	defer ast.ReleaseAST(orig)
	reparsed, err := parseWithDialect(t, formatted, dialect)
	if err != nil {
		t.Fatalf("formatted output does not re-parse: %v\noutput:\n%s", err, formatted)
	}
	defer ast.ReleaseAST(reparsed)
	if len(orig.Statements) != len(reparsed.Statements) {
		t.Fatalf("statement count changed: %d -> %d\noutput:\n%s", len(orig.Statements), len(reparsed.Statements), formatted)
	}
	if o, r := orig.SQL(), reparsed.SQL(); !strings.EqualFold(o, r) {
		t.Fatalf("formatted output changes the query\n original SQL(): %s\nreparsed SQL(): %s\noutput:\n%s", o, r, formatted)
	}
}

// libraryCompact renders input with pkg/formatter using the same style the CLI
// adapter builds for compact, uppercase-keyword output.
func libraryCompact(t *testing.T, input, dialect string) string {
	t.Helper()
	tree, err := parseWithDialect(t, input, dialect)
	if err != nil {
		t.Fatalf("input does not parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	style := ast.CompactStyle()
	style.KeywordCase = ast.KeywordUpper
	style.AddSemicolon = false
	style.Dialect = dialect
	parts := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		parts = append(parts, pkgformatter.FormatStatement(stmt, style))
	}
	return strings.Join(parts, "; ")
}

// TestFormatSQL_Issue599 reproduces every case from issue #599: the CLI
// formatter used its own renderer, which replaced unhandled expressions with
// their token literal and dropped INSERT clauses, exiting 0 with SQL of a
// different meaning. Rows with blockedOn set are lost by pkg/formatter itself;
// they skip (after checking the CLI either refuses the output or matches the
// library) until the referenced library fix lands, and never fail once it does.
func TestFormatSQL_Issue599(t *testing.T) {
	tests := []struct {
		name      string
		dialect   string
		in        string
		want      string // exact compact output (or substring when contains)
		contains  bool
		blockedOn string
	}{
		{name: "cast and double colon", in: "SELECT CAST(a AS INT), b::text FROM t", want: "SELECT CAST(a AS INT), CAST(b AS text) FROM t"},
		{name: "extract", in: "SELECT EXTRACT(YEAR FROM d) FROM t", want: "SELECT EXTRACT(YEAR FROM d) FROM t"},
		{name: "interval", in: "SELECT d + INTERVAL '1 day' FROM t", want: "SELECT d + INTERVAL '1 day' FROM t"},
		{name: "interval frame bound", in: "SELECT SUM(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1 day' PRECEDING AND CURRENT ROW) FROM t", want: "SELECT SUM(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1 day' PRECEDING AND CURRENT ROW) FROM t"},
		{name: "any all", in: "SELECT * FROM t WHERE a = ANY(SELECT x FROM u) AND b > ALL(SELECT x FROM u)", want: "SELECT * FROM t WHERE a = ANY (SELECT x FROM u) AND b > ALL (SELECT x FROM u)"},
		{name: "tuples", in: "SELECT * FROM t WHERE (a, b) IN ((1, 2), (3, 4))", want: "SELECT * FROM t WHERE (a, b) IN ((1, 2), (3, 4))"},
		{name: "subscripts slices array", in: "SELECT arr[1], arr[1:2], ARRAY[1,2] FROM t", want: "SELECT arr[1], arr[1:2], ARRAY[1, 2] FROM t"},
		{name: "rollup", in: "SELECT a, b, COUNT(*) FROM t GROUP BY ROLLUP(a, b)", want: "SELECT a, b, COUNT(*) FROM t GROUP BY ROLLUP(a, b)"},
		{name: "cube", in: "SELECT a, b, COUNT(*) FROM t GROUP BY CUBE(a, b)", want: "SELECT a, b, COUNT(*) FROM t GROUP BY CUBE(a, b)"},
		{name: "grouping sets", in: "SELECT a, b, COUNT(*) FROM t GROUP BY GROUPING SETS ((a), (b), ())", want: "SELECT a, b, COUNT(*) FROM t GROUP BY GROUPING SETS((a), (b), ())"},
		{name: "within group", in: "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY x) FROM t", want: "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY x) FROM t"},
		{name: "exists set operation", in: "SELECT * FROM t WHERE EXISTS (SELECT 1 UNION SELECT 2)", want: "SELECT * FROM t WHERE EXISTS (SELECT 1 UNION SELECT 2)"},
		{name: "in set operation", in: "SELECT * FROM t WHERE a IN (SELECT 1 UNION SELECT 2)", want: "SELECT * FROM t WHERE a IN (SELECT 1 UNION SELECT 2)"},
		{name: "insert on conflict", in: "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = 2", want: "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = 2"},
		{name: "insert returning", in: "INSERT INTO t (a) VALUES (1) RETURNING id", want: "INSERT INTO t (a) VALUES (1) RETURNING id"},
		{name: "sqlserver pivot", dialect: "sqlserver", in: "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p", want: "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p"},

		// Already correct before #599; guard against regressions.
		{name: "rows current row", in: "SELECT SUM(x) OVER (ORDER BY d ROWS CURRENT ROW) FROM t", want: "SELECT SUM(x) OVER (ORDER BY d ROWS CURRENT ROW) FROM t"},
		{name: "rows numeric frame", in: "SELECT SUM(x) OVER (ORDER BY d ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM t", want: "SELECT SUM(x) OVER (ORDER BY d ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM t"},
		{name: "lowercase set operation", in: "select a from t union select b from u", want: "SELECT a FROM t UNION SELECT b FROM u"},
		{name: "statement separator", in: "SELECT 1; SELECT 2", want: "SELECT 1; SELECT 2"},

		// ALTER TABLE: the old CLI emitted `ADD c INT`, a bare `DROP`,
		// `ADD CONSTRAINT pk`, `RENAME COLUMN TO b` and `...`.
		{name: "alter add column", in: "ALTER TABLE t ADD COLUMN c INT NOT NULL DEFAULT 0", want: "ALTER TABLE t ADD COLUMN c INT NOT NULL DEFAULT 0"},
		{name: "alter drop column cascade", in: "ALTER TABLE t DROP COLUMN c CASCADE", want: "ALTER TABLE t DROP COLUMN c CASCADE"},
		{name: "alter add primary key", in: "ALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (id)", want: "ALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (id)"},
		{name: "alter add foreign key", in: "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u (id) ON DELETE CASCADE", want: "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u (id) ON DELETE CASCADE"},
		{name: "alter drop constraint", in: "ALTER TABLE t DROP CONSTRAINT pk", want: "ALTER TABLE t DROP CONSTRAINT pk"},
		{name: "alter rename column", in: "ALTER TABLE t RENAME COLUMN a TO b", want: "ALTER TABLE t RENAME COLUMN a TO b"},
		{name: "alter rename table", in: "ALTER TABLE t RENAME TO u", want: "ALTER TABLE t RENAME TO u"},

		// Lost by pkg/formatter itself; fixed by the referenced library issue.
		{name: "named argument", in: "SELECT f(x => 1) FROM t", want: "SELECT f(x => 1) FROM t", blockedOn: "#600"},
		{name: "ignore nulls", in: "SELECT FIRST_VALUE(x) IGNORE NULLS OVER (ORDER BY y) FROM t", want: "SELECT FIRST_VALUE(x) IGNORE NULLS OVER (ORDER BY y) FROM t", blockedOn: "#600"},
		{name: "clickhouse settings", dialect: "clickhouse", in: "SELECT a FROM t SETTINGS max_threads = 4", want: "SELECT a FROM t SETTINGS max_threads = 4", blockedOn: "#600"},
		{name: "mysql on duplicate key", dialect: "mysql", in: "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = 2", want: "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = 2", blockedOn: "#600"},
		{name: "sqlserver insert output", dialect: "sqlserver", in: "INSERT INTO t (a) OUTPUT INSERTED.id VALUES (1)", want: "INSERT INTO t (a) OUTPUT INSERTED.id VALUES (1)", blockedOn: "#600"},
		{name: "join using", in: "SELECT * FROM a JOIN b USING (id)", want: "USING (id)", contains: true, blockedOn: "#603"},
		{name: "sqlserver nolock", dialect: "sqlserver", in: "SELECT * FROM t WITH (NOLOCK)", want: "SELECT * FROM t WITH (NOLOCK)", blockedOn: "#604"},
		{name: "not exists", in: "SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM u)", want: "SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM u)", blockedOn: "#601"},
		{name: "quoted alias", dialect: "postgresql", in: `SELECT a AS "my alias" FROM t`, want: `SELECT a AS "my alias" FROM t`, blockedOn: "#611"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := func(out string) bool {
				if tc.contains {
					return strings.Contains(out, tc.want)
				}
				return out == tc.want
			}

			out, err := formatWith(tc.in, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tc.dialect})
			if tc.blockedOn != "" && (err != nil || !matches(out)) {
				if err != nil {
					if !strings.Contains(err.Error(), "formatted output") {
						t.Fatalf("expected the round-trip safety net to refuse the output, got: %v", err)
					}
					t.Skipf("blocked on %s: %v", tc.blockedOn, err)
				}
				if lib := libraryCompact(t, tc.in, tc.dialect); out != lib {
					t.Fatalf("CLI output diverges from pkg/formatter\n    cli: %s\nlibrary: %s", out, lib)
				}
				t.Skipf("blocked on %s: got %q", tc.blockedOn, out)
			}
			if err != nil {
				t.Fatalf("compact formatSQL(%q) error: %v", tc.in, err)
			}
			if !matches(out) {
				t.Fatalf("compact formatSQL(%q)\n got: %s\nwant: %s", tc.in, out, tc.want)
			}

			readableOpts := CLIFormatterOptions{IndentSize: 2, Uppercase: true, Dialect: tc.dialect}
			readable, err := formatWith(tc.in, readableOpts)
			if err != nil {
				t.Fatalf("readable formatSQL(%q) error: %v", tc.in, err)
			}
			assertRoundTrip(t, tc.in, readable, tc.dialect)
			again, err := formatWith(readable, readableOpts)
			if err != nil {
				t.Fatalf("re-formatting readable output failed: %v\noutput:\n%s", err, readable)
			}
			if again != readable {
				t.Fatalf("readable formatting is not idempotent\nfirst:\n%s\nsecond:\n%s", readable, again)
			}
		})
	}
}
