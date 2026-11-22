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

package astjson

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

var goldenQueries = []struct{ name, sql, dialect, want string }{
	{"small", "SELECT id, name FROM users WHERE id = 1", "", `{"version":1,"node_type":"AST","Statements":[{"node_type":"SelectStatement","Columns":[{"node_type":"Identifier","Name":"id","Pos":{"Line":1,"Column":8}},{"node_type":"Identifier","Name":"name","Pos":{"Line":1,"Column":12}}],"From":[{"node_type":"TableReference","Name":"users"}],"TableName":"users","Where":{"node_type":"BinaryExpression","Left":{"node_type":"Identifier","Name":"id","Pos":{"Line":1,"Column":34}},"Operator":"=","Right":{"node_type":"LiteralValue","Value":"1","Type":"int"},"Pos":{"Line":1,"Column":37}},"Pos":{"Line":1,"Column":1}}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":1,"Column":40}]}`},
	{"medium", "SELECT u.id, u.name, COUNT(o.id) AS orders, SUM(o.total) AS spent FROM users u LEFT JOIN orders o ON o.user_id = u.id WHERE u.created_at > '2024-01-01' AND u.status IN ('active', 'trial') GROUP BY u.id, u.name HAVING COUNT(o.id) > 2 ORDER BY spent DESC LIMIT 50", "", `{"version":1,"node_type":"AST","Statements":[{"node_type":"SelectStatement","Columns":[{"node_type":"Identifier","Name":"id","Table":"u","Pos":{"Line":1,"Column":8}},{"node_type":"Identifier","Name":"name","Table":"u","Pos":{"Line":1,"Column":14}},{"node_type":"AliasedExpression","Expr":{"node_type":"FunctionCall","Name":"COUNT","Arguments":[{"node_type":"Identifier","Name":"id","Table":"o","Pos":{"Line":1,"Column":28}}],"Pos":{"Line":1,"Column":22}},"Alias":"orders"},{"node_type":"AliasedExpression","Expr":{"node_type":"FunctionCall","Name":"SUM","Arguments":[{"node_type":"Identifier","Name":"total","Table":"o","Pos":{"Line":1,"Column":49}}],"Pos":{"Line":1,"Column":45}},"Alias":"spent"}],"From":[{"node_type":"TableReference","Name":"users","Alias":"u"}],"TableName":"users","Joins":[{"node_type":"JoinClause","Type":"LEFT","Left":{"node_type":"TableReference","Name":"users","Alias":"u"},"Right":{"node_type":"TableReference","Name":"orders","Alias":"o"},"Condition":{"node_type":"BinaryExpression","Left":{"node_type":"Identifier","Name":"user_id","Table":"o","Pos":{"Line":1,"Column":102}},"Operator":"=","Right":{"node_type":"Identifier","Name":"id","Table":"u","Pos":{"Line":1,"Column":114}},"Pos":{"Line":1,"Column":112}},"Pos":{"Line":1,"Column":80}}],"Where":{"node_type":"BinaryExpression","Left":{"node_type":"BinaryExpression","Left":{"node_type":"Identifier","Name":"created_at","Table":"u","Pos":{"Line":1,"Column":125}},"Operator":">","Right":{"node_type":"LiteralValue","Value":"2024-01-01","Type":"string"},"Pos":{"Line":1,"Column":138}},"Operator":"AND","Right":{"node_type":"InExpression","Expr":{"node_type":"Identifier","Name":"status","Table":"u","Pos":{"Line":1,"Column":157}},"List":[{"node_type":"LiteralValue","Value":"active","Type":"string"},{"node_type":"LiteralValue","Value":"trial","Type":"string"}],"Pos":{"Line":1,"Column":166}},"Pos":{"Line":1,"Column":153}},"GroupBy":[{"node_type":"Identifier","Name":"id","Table":"u","Pos":{"Line":1,"Column":198}},{"node_type":"Identifier","Name":"name","Table":"u","Pos":{"Line":1,"Column":204}}],"Having":{"node_type":"BinaryExpression","Left":{"node_type":"FunctionCall","Name":"COUNT","Arguments":[{"node_type":"Identifier","Name":"id","Table":"o","Pos":{"Line":1,"Column":224}}],"Pos":{"Line":1,"Column":218}},"Operator":">","Right":{"node_type":"LiteralValue","Value":"2","Type":"int"},"Pos":{"Line":1,"Column":230}},"OrderBy":[{"node_type":"OrderByExpression","Expression":{"node_type":"Identifier","Name":"spent","Pos":{"Line":1,"Column":243}}}],"Limit":50,"Pos":{"Line":1,"Column":1}}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":1,"Column":262}]}`},
	{"cte_window", "WITH x AS (SELECT id FROM t) SELECT id, ROW_NUMBER() OVER (ORDER BY id) FROM x", "", `{"version":1,"node_type":"AST","Statements":[{"node_type":"SelectStatement","With":{"node_type":"WithClause","CTEs":[{"node_type":"CommonTableExpr","Name":"x","Statement":{"node_type":"SelectStatement","Columns":[{"node_type":"Identifier","Name":"id","Pos":{"Line":1,"Column":19}}],"From":[{"node_type":"TableReference","Name":"t"}],"TableName":"t"},"Pos":{"Line":1,"Column":6}}],"Pos":{"Line":1,"Column":1}},"Columns":[{"node_type":"Identifier","Name":"id","Pos":{"Line":1,"Column":37}},{"node_type":"FunctionCall","Name":"ROW_NUMBER","Over":{"node_type":"WindowSpec","OrderBy":[{"node_type":"OrderByExpression","Expression":{"node_type":"Identifier","Name":"id","Pos":{"Line":1,"Column":69}},"Ascending":true}]},"Pos":{"Line":1,"Column":41}}],"From":[{"node_type":"TableReference","Name":"x"}],"TableName":"x"}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":1,"Column":79}]}`},
	{"literals", "INSERT INTO t VALUES (NULL, TRUE, FALSE, '')", "", `{"version":1,"node_type":"AST","Statements":[{"node_type":"InsertStatement","TableName":"t","Values":[[{"node_type":"LiteralValue","Type":"null"},{"node_type":"LiteralValue","Value":"TRUE","Type":"bool"},{"node_type":"LiteralValue","Value":"FALSE","Type":"bool"},{"node_type":"LiteralValue","Value":"","Type":"string"}]],"Pos":{"Line":1,"Column":1}}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":1,"Column":45}]}`},
	{"mysql", "SELECT `a` FROM `t`", "mysql", `{"version":1,"node_type":"AST","Statements":[{"node_type":"SelectStatement","Columns":[{"node_type":"Identifier","Name":"a","Pos":{"Line":1,"Column":8},"QuoteStyle":96}],"From":[{"node_type":"TableReference","Name":"t"}],"TableName":"t","Pos":{"Line":1,"Column":1}}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":1,"Column":20}]}`},
	{"cast", "SELECT a::int FROM t", "postgresql", `{"version":1,"node_type":"AST","Statements":[{"node_type":"SelectStatement","Columns":[{"node_type":"CastExpression","Expr":{"node_type":"Identifier","Name":"a","Pos":{"Line":1,"Column":8}},"Type":"int"}],"From":[{"node_type":"TableReference","Name":"t"}],"TableName":"t","Pos":{"Line":1,"Column":1}}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":1,"Column":21}]}`},
	{"create", "CREATE TEMP TABLE t (id INT PRIMARY KEY, name VARCHAR(20))", "postgresql", `{"version":1,"node_type":"AST","Statements":[{"node_type":"CreateTableStatement","Temporary":true,"Name":"t","Columns":[{"node_type":"ColumnDef","Name":"id","Type":"INT","Constraints":[{"node_type":"ColumnConstraint","Type":"PRIMARY KEY"}]},{"node_type":"ColumnDef","Name":"name","Type":"VARCHAR(20)"}],"Kind":"TEMP"}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":1,"Column":59}]}`},
	{"escaping", "SELECT '\"\\\\\n<>&\u2028\xff'", "", `{"version":1,"node_type":"AST","Statements":[{"node_type":"SelectStatement","Columns":[{"node_type":"LiteralValue","Value":"\"\\\n<>&\u2028�","Type":"string"}],"Pos":{"Line":1,"Column":1}}],"StatementStarts":[{"Line":1,"Column":1}],"StatementEnds":[{"Line":2,"Column":9}]}`},
}

func parseTest(sql, d string) (*ast.AST, error) {
	if d == "" || d == "generic" {
		return gosqlx.Parse(sql)
	}
	return gosqlx.ParseWithDialect(sql, keywords.SQLDialect(d))
}
func TestAppend_Golden(t *testing.T) {
	for _, q := range goldenQueries {
		t.Run(q.name, func(t *testing.T) {
			tree, err := parseTest(q.sql, q.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			got, err := Marshal(tree)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != q.want {
				t.Fatalf("golden mismatch\ngot: %s\nwant: %s", got, q.want)
			}
			twice, err := Append([]byte("prefix:"), tree)
			if err != nil || string(twice) != "prefix:"+q.want {
				t.Fatalf("Append prefix: %s, %v", twice, err)
			}
		})
	}
}
func FuzzAppend(f *testing.F) {
	for _, q := range goldenQueries {
		f.Add(q.sql)
	}
	corpus := goldens.Corpus(f)
	for i := 0; i < len(corpus) && i < 20; i++ {
		f.Add(corpus[i].SQL)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		tree, err := gosqlx.Parse(sql)
		if err != nil {
			return
		}
		defer ast.ReleaseAST(tree)
		out, err := Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		compareJSON(t, tree, out)
	})
}
func BenchmarkAppend(b *testing.B) {
	queries := []struct{ name, sql string }{{"small", goldenQueries[0].sql}, {"medium", goldenQueries[1].sql}, {"large", "SELECT " + strings.TrimSuffix(strings.Repeat("c, ", 120), ", ") + " FROM t WHERE " + strings.TrimSuffix(strings.Repeat("a = 1 AND ", 80), " AND ")}}
	for _, q := range queries {
		b.Run(q.name, func(b *testing.B) {
			tree, err := gosqlx.Parse(q.sql)
			if err != nil {
				b.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			buf, err := Append(nil, tree)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf, err = Append(buf[:0], tree)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Empty indentation keeps the legacy MarshalIndent depth check without
// allocating quadratic whitespace for these deliberately deep trees.
func TestAppend_LegacyChainDepth(t *testing.T) {
	for _, chain := range []struct{ name, prefix, term, separator string }{
		{"select", "SELECT ", "a", " + "},
		{"where", "SELECT a FROM t WHERE ", "a = a", " AND "},
	} {
		for _, terms := range []int{1000, 3500, 5000, 20000} {
			t.Run(fmt.Sprintf("%s/%d", chain.name, terms), func(t *testing.T) {
				sql := chain.prefix + strings.Repeat(chain.term+chain.separator, terms-1) + chain.term
				tree, err := parseTest(sql, "")
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				_, legacyErr := json.MarshalIndent(tree, "", "")
				out, err := Marshal(tree)
				if (err == nil) != (legacyErr == nil) {
					t.Fatalf("v1 error = %v; legacy error = %v", err, legacyErr)
				}
				if terms == 20000 {
					if legacyErr == nil || !strings.Contains(legacyErr.Error(), "exceeded max depth") {
						t.Fatalf("expected legacy max depth rejection, got %v", legacyErr)
					}
					if len(err.Error()) >= 1024 {
						t.Fatalf("depth error has %d bytes, want < 1024", len(err.Error()))
					}
				} else if err != nil {
					t.Fatal(err)
				} else if !json.Valid(out) {
					t.Fatal("v1 returned invalid JSON")
				}
			})
		}
	}
}
