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

package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	mcpmcp "github.com/mark3labs/mcp-go/mcp"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
)

const fmtProbeSQL = "select a, b from t where x = 1 and y in (select z from u where w > 2) or c is not null order by a"

func formattedSQL(t *testing.T, res map[string]any) string {
	t.Helper()
	s, ok := res["formatted_sql"].(string)
	if !ok {
		t.Fatalf("formatted_sql is %T, want string", res["formatted_sql"])
	}
	return s
}

func TestFormatSQLInternal_Options(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		indent    int
		upper     bool
		semicolon bool
		want      string
	}{
		{
			name: "default upper-cases AND and OR",
			sql:  fmtProbeSQL, indent: 2,
			want: "SELECT a, b\nFROM t\nWHERE x = 1 AND y IN (SELECT z FROM u WHERE w > 2) OR c IS NOT NULL\nORDER BY a",
		},
		{
			name: "default keeps the case of LIKE",
			sql:  "select a from t where name like 'x%' and id = 1", indent: 2,
			want: "SELECT a\nFROM t\nWHERE name like 'x%' AND id = 1",
		},
		{
			name: "uppercase_keywords upper-cases every keyword",
			sql:  fmtProbeSQL, indent: 2, upper: true,
			want: "SELECT a, b\nFROM t\nWHERE x = 1 AND y IN (SELECT z FROM u WHERE w > 2) OR c IS NOT NULL\nORDER BY a",
		},
		{
			name: "indent 0 is single line",
			sql:  fmtProbeSQL, indent: 0, upper: true,
			want: "SELECT a, b FROM t WHERE x = 1 AND y IN (SELECT z FROM u WHERE w > 2) OR c IS NOT NULL ORDER BY a",
		},
		{
			name: "indent 2 indents nested blocks",
			sql:  "create table t (a int primary key, b text not null)", indent: 2,
			want: "CREATE TABLE t (\n  a int PRIMARY KEY,\n  b text NOT NULL\n)",
		},
		{
			name: "indent 4 indents nested blocks by 4",
			sql:  "create table t (a int primary key, b text not null)", indent: 4,
			want: "CREATE TABLE t (\n    a int PRIMARY KEY,\n    b text NOT NULL\n)",
		},
		{
			name: "add_semicolon",
			sql:  "select 1", indent: 2, semicolon: true,
			want: "SELECT 1;",
		},
		{
			name: "uppercase keeps literals and function arguments intact",
			sql:  "select count(*), 'and or' from t where name like 'select%'", indent: 2, upper: true,
			want: "SELECT COUNT(*), 'and or'\nFROM t\nWHERE name LIKE 'select%'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := formatSQLInternal(tt.sql, tt.indent, tt.upper, tt.semicolon)
			if err != nil {
				t.Fatalf("formatSQLInternal: %v", err)
			}
			if got := formattedSQL(t, res); got != tt.want {
				t.Errorf("formatted_sql =\n%q\nwant\n%q", got, tt.want)
			}
			opts, ok := res["options"].(map[string]any)
			if !ok {
				t.Fatalf("options is %T", res["options"])
			}
			wantOpts := map[string]any{"indent_size": tt.indent, "uppercase_keywords": tt.upper, "add_semicolon": tt.semicolon}
			if !reflect.DeepEqual(opts, wantOpts) {
				t.Errorf("options = %v, want %v", opts, wantOpts)
			}
		})
	}
}

// TestFormatSQLInternal_DefaultMatchesGosqlxFormat pins the default output to
// gosqlx.Format, so analyze_sql's format section stays text-compatible.
func TestFormatSQLInternal_DefaultMatchesGosqlxFormat(t *testing.T) {
	for _, q := range []string{fmtProbeSQL, "insert into t (a) values (1); delete from t where a between 1 and 2"} {
		want, err := gosqlx.Format(q, gosqlx.FormatOptions{IndentSize: 2})
		if err != nil {
			t.Fatalf("gosqlx.Format: %v", err)
		}
		res, err := formatSQLInternal(q, 2, false, false)
		if err != nil {
			t.Fatalf("formatSQLInternal: %v", err)
		}
		if got := formattedSQL(t, res); got != want {
			t.Errorf("default output changed:\n got %q\nwant %q", got, want)
		}
	}
}

// TestFormatSQLInternal_UppercasePassesL007 checks that uppercase_keywords
// output satisfies lint_sql's keyword-case rule.
func TestFormatSQLInternal_UppercasePassesL007(t *testing.T) {
	q := "with c as (select a from t where exists (select 1 from u where u.a = t.a)) " +
		"select case when a > 1 then 'x' else 'y' end, coalesce(b, 0) from c left join d on c.a = d.a " +
		"where a between 1 and 9 and b not like 'z%' group by a having count(*) > 1 order by a desc"
	res, err := formatSQLInternal(q, 2, true, false)
	if err != nil {
		t.Fatalf("formatSQLInternal: %v", err)
	}
	out := formattedSQL(t, res)
	result := linter.New(keywords.NewKeywordCaseRule(keywords.CaseUpper)).LintString(out, "<test>")
	if len(result.Violations) != 0 {
		t.Errorf("uppercase output has %d L007 violations: %+v\n%s", len(result.Violations), result.Violations, out)
	}
}

func TestUppercaseSQLKeywords(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"keywords", "select a from t where b and c or not d", "SELECT a FROM t WHERE b AND c OR NOT d"},
		{"identifiers unchanged", "select users, Email from orders", "SELECT users, Email FROM orders"},
		{"single-quoted", "select 'and or select' from t", "SELECT 'and or select' FROM t"},
		{"doubled quote", "select 'it''s and' and x", "SELECT 'it''s and' AND x"},
		{"backslash escape", `select 'a\' and' and x`, `SELECT 'a\' and' AND x`},
		{"double-quoted identifier", `select "select", "and" from t`, `SELECT "select", "and" FROM t`},
		{"backtick identifier", "select `from` from t", "SELECT `from` FROM t"},
		{"bracket identifier", "select [order] from t", "SELECT [order] FROM t"},
		{"line comment", "select a -- and or\nfrom t", "SELECT a -- and or\nFROM t"},
		{"block comment", "select /* and or */ a from t", "SELECT /* and or */ a FROM t"},
		{"dollar quoted", "select $$ and or $$, $tag$ select $tag$ from t", "SELECT $$ and or $$, $tag$ select $tag$ FROM t"},
		{"positional parameter", "select a from t where b = $1 and c = $2", "SELECT a FROM t WHERE b = $1 AND c = $2"},
		{"named parameters", "select a from t where b = :select and c = @from", "SELECT a FROM t WHERE b = :select AND c = @from"},
		{"qualified names", "select t.end, end.x from t", "SELECT t.end, end.x FROM t"},
		{"numbers", "select 1e5, 0x1f from t", "SELECT 1e5, 0x1f FROM t"},
		{"non-ascii identifiers", "select café, naïve from t", "SELECT café, naïve FROM t"},
		{"unterminated string", "select 'and", "SELECT 'and"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uppercaseSQLKeywords(tt.in); got != tt.want {
				t.Errorf("uppercaseSQLKeywords(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestHandleFormatSQL_OptionsChangeOutput calls the tool handler the way an
// MCP client does and checks that each option changes the result.
func TestHandleFormatSQL_OptionsChangeOutput(t *testing.T) {
	call := func(args map[string]any) string {
		t.Helper()
		req := mcpmcp.CallToolRequest{}
		req.Params.Name = "format_sql"
		req.Params.Arguments = args
		res, err := handleFormatSQL(context.Background(), req)
		if err != nil {
			t.Fatalf("handleFormatSQL(%v): %v", args, err)
		}
		sc, ok := res.StructuredContent.(map[string]any)
		if !ok {
			t.Fatalf("structuredContent is %T", res.StructuredContent)
		}
		return formattedSQL(t, sc)
	}
	base := call(map[string]any{"sql": fmtProbeSQL})
	likeSQL := "select a from t where name like 'x%'"
	if upper := call(map[string]any{"sql": likeSQL, "uppercase_keywords": true}); upper == call(map[string]any{"sql": likeSQL}) {
		t.Error("uppercase_keywords:true did not change the output")
	}
	if one := call(map[string]any{"sql": fmtProbeSQL, "indent_size": 0}); one == base {
		t.Error("indent_size:0 did not change the output")
	}
	ddl := "create table t (a int, b text)"
	if call(map[string]any{"sql": ddl, "indent_size": 4}) == call(map[string]any{"sql": ddl, "indent_size": 2}) {
		t.Error("indent_size 4 and 2 gave the same CREATE TABLE output")
	}
	if semi := call(map[string]any{"sql": fmtProbeSQL, "add_semicolon": true}); semi != base+";" {
		t.Errorf("add_semicolon:true = %q, want %q", semi, base+";")
	}
}

// TestAnalyzeSQL_FormatSectionUsesDefaults pins analyze_sql's format section
// (formatted_sql and options) to formatSQLInternal(sql, 2, false, false).
func TestAnalyzeSQL_FormatSectionUsesDefaults(t *testing.T) {
	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "analyze_sql"
	req.Params.Arguments = map[string]any{"sql": fmtProbeSQL}
	res, err := handleAnalyzeSQL(context.Background(), req)
	if err != nil {
		t.Fatalf("handleAnalyzeSQL: %v", err)
	}
	sc, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T", res.StructuredContent)
	}
	want, err := formatSQLInternal(fmtProbeSQL, 2, false, false)
	if err != nil {
		t.Fatalf("formatSQLInternal: %v", err)
	}
	roundTrip := func(v any) any {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return out
	}
	if got := roundTrip(sc["format"]); !reflect.DeepEqual(got, roundTrip(want)) {
		t.Errorf("analyze_sql format section = %v, want %v", got, roundTrip(want))
	}
}
