package parser_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func dialectConstructTreeShape(t *testing.T, tree *ast.AST) any {
	t.Helper()
	data, err := json.Marshal(tree.Statements)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	var clearPositions func(any)
	clearPositions = func(v any) {
		switch n := v.(type) {
		case map[string]any:
			delete(n, "Pos")
			// Unquoted function names are case-insensitive, and lower-case
			// formatting writes them in lower case (SUM -> sum).
			if name, ok := n["Name"].(string); ok && n["NameQuote"] == float64(0) {
				if _, call := n["Arguments"]; call {
					n["Name"] = strings.ToUpper(name)
				}
			}
			for _, child := range n {
				clearPositions(child)
			}
		case []any:
			for _, child := range n {
				clearPositions(child)
			}
		}
	}
	clearPositions(value)
	return value
}

func TestDialectConstructsInsertArrayGroupingRoundTrip(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectSQLServer, `INSERT TOP (10) INTO t (a) SELECT a FROM s`},
		{keywords.DialectSQLServer, `INSERT TOP (10) PERCENT INTO t (a) SELECT a FROM s`},
		{keywords.DialectSQLServer, `INSERT TOP (@n) t (a) SELECT a FROM s`},
		{keywords.DialectPostgreSQL, `SELECT (ARRAY[1,2,3])[2]`},
		{keywords.DialectPostgreSQL, `SELECT ARRAY[1,2,3][2]`},
		{keywords.DialectPostgreSQL, `SELECT ARRAY[[1,2],[3,4]][1][2]`},
		{keywords.DialectPostgreSQL, `SELECT ARRAY[1,2,3][1:2]`},
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectSnowflake, keywords.DialectSQLServer, keywords.DialectOracle} {
		cases = append(cases, struct {
			dialect keywords.SQLDialect
			sql     string
		}{d, `SELECT a, b, SUM(c) FROM t GROUP BY GROUPING SETS ((a), ROLLUP(b), CUBE(a, b), ())`})
	}
	for _, tc := range cases {
		t.Run(string(tc.dialect)+tc.sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			want := dialectConstructTreeShape(t, tree)
			formatted, err := gosqlx.FormatWithDialect(tc.sql, gosqlx.DefaultFormatOptions(), tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			outputs := append(formatterOutputs(tree), formatted)
			for _, output := range outputs {
				again, err := gosqlx.ParseWithDialect(output, tc.dialect)
				if err != nil {
					t.Fatalf("reparse %q: %v", output, err)
				}
				defer ast.ReleaseAST(again)
				if got := dialectConstructTreeShape(t, again); !reflect.DeepEqual(got, want) {
					t.Fatalf("tree changed after rendering %q\nwant %#v\ngot %#v", output, want, got)
				}
			}
		})
	}
}

func TestDialectConstructsInsertTopInspection(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect(`INSERT TOP (@n) PERCENT t (a) SELECT a FROM s`, keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected INSERT, got %T", tree.Statements[0])
	}
	top := stmt.DialectExtras().Top
	if top == nil || !top.IsPercent {
		t.Fatal("missing TOP PERCENT")
	}
	seenTop, seenCount := false, false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if n == top {
			seenTop = true
		}
		if n == top.Count {
			seenCount = true
		}
		return true
	})
	if !seenTop || !seenCount {
		t.Fatal("TOP and count must be inspectable")
	}
}

func TestDialectConstructsArrayGroupingInspection(t *testing.T) {
	cases := []struct {
		sql                                                        string
		constructors, subscripts, slices, rollups, cubes, literals int
	}{
		{`SELECT ARRAY[[1,2],[3,4]][1][2]`, 3, 2, 0, 0, 0, 6},
		{`SELECT (ARRAY[1,2,3])[1:2]`, 1, 0, 1, 0, 0, 5},
		{`SELECT a FROM t GROUP BY GROUPING SETS ((a), ROLLUP(b), CUBE(a,b), ())`, 0, 0, 0, 1, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			var constructors, subscripts, slices, rollups, cubes, literals int
			ast.Inspect(tree.Statements[0], func(n ast.Node) bool {
				switch n.(type) {
				case *ast.ArrayConstructorExpression:
					constructors++
				case *ast.ArraySubscriptExpression:
					subscripts++
				case *ast.ArraySliceExpression:
					slices++
				case *ast.RollupExpression:
					rollups++
				case *ast.CubeExpression:
					cubes++
				case *ast.LiteralValue:
					literals++
				}
				return true
			})
			got := []int{constructors, subscripts, slices, rollups, cubes, literals}
			want := []int{tc.constructors, tc.subscripts, tc.slices, tc.rollups, tc.cubes, tc.literals}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("inspection counts got %v, want %v", got, want)
			}
		})
	}
}

func TestDialectConstructsInsertTopRejectsUnsupportedForms(t *testing.T) {
	for _, sql := range []string{
		`INSERT TOP 10 INTO t VALUES (1)`,
		`INSERT TOP (10) WITH TIES INTO t VALUES (1)`,
	} {
		if tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectSQLServer); err == nil {
			defer ast.ReleaseAST(tree)
			t.Errorf("accepted invalid INSERT syntax: %s", sql)
		}
	}
}
