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
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSelectWithDialect parses sql and returns its first statement as a
// SELECT. The caller must release the returned AST.
func parseSelectWithDialect(t *testing.T, sql string, dialect keywords.SQLDialect) (*ast.SelectStatement, *ast.AST) {
	t.Helper()
	tree, err := ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("ParseWithDialect(%q, %s): %v", sql, dialect, err)
	}
	if len(tree.Statements) == 0 {
		ast.ReleaseAST(tree)
		t.Fatalf("no statements for %q", sql)
	}
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		ast.ReleaseAST(tree)
		t.Fatalf("expected SelectStatement for %q, got %T", sql, tree.Statements[0])
	}
	return stmt, tree
}

// TestParseLeadingInt_MatchesSscanf pins parseLeadingInt against
// fmt.Sscanf("%d"), the implementation it replaces. Leading whitespace is
// excluded on purpose: Number tokens never carry it.
func TestParseLeadingInt_MatchesSscanf(t *testing.T) {
	inputs := []string{
		"10", "-5", "+5", "10.5", "", "abc",
		"99999999999999999999", "9223372036854775807", "9223372036854775808",
		"-9223372036854775808", "1e5", "0x10", "007", "1_000", "5abc", "-", "+-5",
	}
	for _, in := range inputs {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			var wantInt int
			_, _ = fmt.Sscanf(in, "%d", &wantInt)
			if got := int(parseLeadingInt(in, strconv.IntSize)); got != wantInt {
				t.Errorf("int: parseLeadingInt = %d, Sscanf = %d", got, wantInt)
			}
			var want64 int64
			_, _ = fmt.Sscanf(in, "%d", &want64)
			if got := parseLeadingInt(in, 64); got != want64 {
				t.Errorf("int64: parseLeadingInt = %d, Sscanf = %d", got, want64)
			}
		})
	}

	if raceEnabled {
		return
	}
	if n := testing.AllocsPerRun(1000, func() { _ = parseLeadingInt("20", strconv.IntSize) }); n != 0 {
		t.Errorf("parseLeadingInt allocs = %v, want 0", n)
	}
}

// TestParseLimitOffsetFetch_LenientNumeric pins the lenient numeric handling
// of LIMIT, OFFSET and FETCH end to end.
func TestParseLimitOffsetFetch_LenientNumeric(t *testing.T) {
	intp := func(v int) *int { return &v }
	i64p := func(v int64) *int64 { return &v }

	tests := []struct {
		name      string
		sql       string
		dialect   keywords.SQLDialect
		wantLimit *int
		wantOff   *int
		wantFetch *int64
	}{
		{"limit offset", "SELECT id FROM t LIMIT 10 OFFSET 20", keywords.DialectPostgreSQL, intp(10), intp(20), nil},
		{"decimal literals", "SELECT id FROM t LIMIT 10.5 OFFSET 2.75", keywords.DialectPostgreSQL, intp(10), intp(2), nil},
		{"exponent literal", "SELECT id FROM t LIMIT 1e2", keywords.DialectPostgreSQL, intp(1), nil, nil},
		{"overflow limit", "SELECT id FROM t LIMIT 99999999999999999999", keywords.DialectPostgreSQL, intp(0), nil, nil},
		{"mysql offset,count", "SELECT id FROM t LIMIT 2.5, 7.9", keywords.DialectMySQL, intp(7), intp(2), nil},
		{"fetch first", "SELECT id FROM t FETCH FIRST 5 ROWS ONLY", keywords.DialectPostgreSQL, nil, nil, i64p(5)},
		{"fetch decimal", "SELECT id FROM t OFFSET 20 ROWS FETCH NEXT 5.5 ROWS ONLY", keywords.DialectPostgreSQL, nil, nil, i64p(5)},
		{"fetch overflow", "SELECT id FROM t FETCH FIRST 99999999999999999999 ROWS ONLY", keywords.DialectPostgreSQL, nil, nil, i64p(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt, tree := parseSelectWithDialect(t, tt.sql, tt.dialect)
			defer ast.ReleaseAST(tree)

			cmpInt := func(label string, got, want *int) {
				switch {
				case got == nil && want == nil:
				case got == nil || want == nil:
					t.Errorf("%s = %v, want %v", label, got, want)
				case *got != *want:
					t.Errorf("%s = %d, want %d", label, *got, *want)
				}
			}
			cmpInt("Limit", stmt.Limit, tt.wantLimit)
			if tt.wantFetch == nil {
				cmpInt("Offset", stmt.Offset, tt.wantOff)
				return
			}
			if stmt.Fetch == nil || stmt.Fetch.FetchValue == nil {
				t.Fatalf("expected FetchValue %d, got Fetch=%+v", *tt.wantFetch, stmt.Fetch)
			}
			if *stmt.Fetch.FetchValue != *tt.wantFetch {
				t.Errorf("FetchValue = %d, want %d", *stmt.Fetch.FetchValue, *tt.wantFetch)
			}
		})
	}
}

// TestParseJoinClauses_SyntheticLeftNames is a golden test for the synthetic
// left-side names of chained joins and the non-nil Joins contract.
func TestParseJoinClauses_SyntheticLeftNames(t *testing.T) {
	stmt, tree := parseSelectWithDialect(t,
		"SELECT * FROM a JOIN b ON a.id = b.a_id JOIN c ON b.id = c.b_id JOIN d ON c.id = d.c_id",
		keywords.DialectPostgreSQL)
	defer ast.ReleaseAST(tree)

	want := []string{"a", "(a_with_1_joins)", "(a_with_2_joins)"}
	if len(stmt.Joins) != len(want) {
		t.Fatalf("len(Joins) = %d, want %d", len(stmt.Joins), len(want))
	}
	for i, w := range want {
		if got := stmt.Joins[i].Left.Name; got != w {
			t.Errorf("Joins[%d].Left.Name = %q, want %q", i, got, w)
		}
	}

	noJoin, tree2 := parseSelectWithDialect(t, "SELECT id FROM t", keywords.DialectPostgreSQL)
	defer ast.ReleaseAST(tree2)
	if noJoin.Joins == nil || len(noJoin.Joins) != 0 {
		t.Errorf("join-free SELECT: Joins = %#v, want non-nil empty slice", noJoin.Joins)
	}
}

// TestClauseKeywordDetection_CaseInsensitive checks that keyword detection
// behaves identically for upper, lower and mixed case spellings.
func TestClauseKeywordDetection_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		dialect keywords.SQLDialect
		wantErr bool
	}{
		{"sqlserver top percent", "SELECT TOP 5 PERCENT name FROM t", keywords.DialectSQLServer, false},
		{"sqlserver top parens with ties", "SELECT TOP (3) WITH TIES name FROM t ORDER BY name", keywords.DialectSQLServer, false},
		{"mysql rejects top", "SELECT TOP 5 name FROM t", keywords.DialectMySQL, true},
		{"postgresql rejects top", "SELECT TOP 5 name FROM t", keywords.DialectPostgreSQL, true},
		{"sqlite rejects top", "SELECT TOP 5 name FROM t", keywords.DialectSQLite, true},
		{"oracle rejects top", "SELECT TOP 5 name FROM t", keywords.DialectOracle, true},
		{"insert output", "INSERT INTO t (a) OUTPUT inserted.a VALUES (1)", keywords.DialectSQLServer, false},
		{"not between", "SELECT a FROM t WHERE x NOT BETWEEN 1 AND 2", keywords.DialectPostgreSQL, false},
		{"not like", "SELECT a FROM t WHERE x NOT LIKE 'a%'", keywords.DialectPostgreSQL, false},
		{"not in", "SELECT a FROM t WHERE x NOT IN (1)", keywords.DialectPostgreSQL, false},
		{"not ilike", "SELECT a FROM t WHERE x NOT ILIKE 'a'", keywords.DialectPostgreSQL, false},
		{"not prefix operator", "SELECT a FROM t WHERE NOT active AND name LIKE '%'", keywords.DialectPostgreSQL, false},
		{"snowflake sample", "SELECT * FROM t SAMPLE (10)", keywords.DialectSnowflake, false},
		{"snowflake tablesample", "SELECT * FROM t TABLESAMPLE BERNOULLI (10)", keywords.DialectSnowflake, false},
		{"snowflake at", "SELECT * FROM t AT (TIMESTAMP => '2024-01-01')", keywords.DialectSnowflake, false},
		{"snowflake before", "SELECT * FROM t BEFORE (STATEMENT => 'abc')", keywords.DialectSnowflake, false},
		{"oracle connect by", "SELECT id FROM t START WITH id = 1 CONNECT BY PRIOR id = parent_id", keywords.DialectOracle, false},
		{"clickhouse with fill", "SELECT d FROM t ORDER BY d WITH FILL FROM 1 TO 10 STEP 1", keywords.DialectClickHouse, false},
	}
	for _, tt := range tests {
		for _, variant := range []struct{ label, sql string }{
			{"upper", strings.ToUpper(tt.sql)},
			{"lower", strings.ToLower(tt.sql)},
			{"original", tt.sql},
		} {
			t.Run(tt.name+"/"+variant.label, func(t *testing.T) {
				tree, err := ParseWithDialect(variant.sql, tt.dialect)
				if tree != nil {
					defer ast.ReleaseAST(tree)
				}
				if (err != nil) != tt.wantErr {
					t.Fatalf("ParseWithDialect(%q, %s) err = %v, wantErr %v", variant.sql, tt.dialect, err, tt.wantErr)
				}
			})
		}
	}

	t.Run("lowercase top percent sets IsPercent", func(t *testing.T) {
		stmt, tree := parseSelectWithDialect(t, "select top 5 percent name from t", keywords.DialectSQLServer)
		defer ast.ReleaseAST(tree)
		if stmt.Top == nil || !stmt.Top.IsPercent {
			t.Errorf("Top = %+v, want IsPercent", stmt.Top)
		}
	})

	t.Run("lowercase with fill populates clause", func(t *testing.T) {
		stmt, tree := parseSelectWithDialect(t, "select d from t order by d with fill from 1 to 10 step 1", keywords.DialectClickHouse)
		defer ast.ReleaseAST(tree)
		if len(stmt.OrderBy) != 1 || stmt.OrderBy[0].WithFill == nil {
			t.Fatalf("expected WITH FILL on ORDER BY, got %+v", stmt.OrderBy)
		}
		wf := stmt.OrderBy[0].WithFill
		if wf.From == nil || wf.To == nil || wf.Step == nil {
			t.Errorf("WithFill = %+v, want From/To/Step set", wf)
		}
	})

	t.Run("table named sample stays a table", func(t *testing.T) {
		stmt, tree := parseSelectWithDialect(t, "select * from sample", keywords.DialectSnowflake)
		defer ast.ReleaseAST(tree)
		if len(stmt.From) != 1 || !strings.EqualFold(stmt.From[0].Name, "sample") {
			t.Errorf("From = %+v, want table sample", stmt.From)
		}
	})
}

// TestParse_PaginatedJoinAllocs guards the allocation count of a paginated
// three-table join, which exercises LIMIT/OFFSET parsing, chained join names
// and the alias keyword checks.
func TestParse_PaginatedJoinAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	toks, err := tkz.Tokenize([]byte("SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id JOIN items i ON o.id = i.order_id WHERE u.active = 1 ORDER BY o.created_at DESC LIMIT 10 OFFSET 20"))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	tokens := append([]models.TokenWithSpan(nil), toks...)

	p := NewParser()
	defer p.Release()

	var parseErr error
	n := testing.AllocsPerRun(1000, func() {
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			parseErr = err
			return
		}
		ast.ReleaseAST(tree)
	})
	if parseErr != nil {
		t.Fatalf("parse: %v", parseErr)
	}
	// Measured with AllocsPerRun: 35 allocs before removing Sscanf, Sprintf and
	// ToUpper, 24 after (benchmarks report 37 and 26 respectively).
	const maxAllocs = 26
	if n > maxAllocs {
		t.Errorf("AllocsPerRun = %v, want <= %d", n, maxAllocs)
	}
}
