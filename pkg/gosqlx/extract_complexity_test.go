// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func nestedExtractCTE(depth int) string {
	sql := "SELECT 1 FROM t0"
	for i := 1; i <= depth; i++ {
		sql = fmt.Sprintf("WITH c%d AS (%s) SELECT * FROM c%d", i, sql, i)
	}
	return sql
}

func extractVisitCount(t *testing.T, sql string) int {
	t.Helper()
	tree, err := Parse(sql)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	c := metadataCollector{want: extractTables, tables: make(map[string]struct{})}
	c.collect(tree)
	assertMetadataMatchesExtractors(t, tree)
	return c.visits
}

func TestExtractTraversalLinear(t *testing.T) {
	t.Run("nested CTE", func(t *testing.T) {
		for _, depth := range []int{3, 12, 50} {
			visits := extractVisitCount(t, nestedExtractCTE(depth))
			if visits > 6*depth+3 {
				t.Fatalf("depth %d: %d visits exceed linear bound %d", depth, visits, 6*depth+3)
			}
			tree, err := Parse(nestedExtractCTE(depth))
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			want := []string{"t0"}
			for i := 1; i <= depth; i++ {
				want = append(want, fmt.Sprintf("c%d", i))
			}
			sort.Strings(want)
			got := ExtractTables(tree)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("tables = %v, want %v", got, want)
			}
			t.Logf("depth %d: %d visits", depth, visits)
		}
	})
	t.Run("UNION ALL", func(t *testing.T) {
		var small int
		for _, n := range []int{4, 250, 1000} {
			visits := extractVisitCount(t, strings.Repeat("SELECT a FROM t UNION ALL ", n)+"SELECT a FROM t")
			if visits > 4*n+3 {
				t.Fatalf("%d unions: %d visits exceed linear bound %d", n, visits, 4*n+3)
			}
			if n == 250 {
				small = visits
			}
			if n == 1000 && visits*2 > small*9 {
				t.Fatalf("visit ratio exceeds 4.5: %d / %d", visits, small)
			}
			t.Logf("%d unions: %d visits", n, visits)
		}
	})
}

func TestExtractTraversalPreservesMetadata(t *testing.T) {
	// Expected sets were captured at adc88380 before removing duplicate visits.
	tests := []struct {
		name, sql                         string
		tables, columns, functions        []string
		qualifiedTables, qualifiedColumns []QualifiedName
	}{
		{"CTE UNION", "WITH c AS (SELECT a FROM public.t UNION ALL SELECT a FROM public.u) SELECT MAX(a) AS m FROM c HAVING MAX(a) > 0 ORDER BY m",
			[]string{"c", "public.t", "public.u"}, []string{"a"}, []string{"MAX"},
			[]QualifiedName{{Name: "c"}, {Schema: "public", Name: "t"}, {Schema: "public", Name: "u"}}, []QualifiedName{{Name: "a"}}},
		{"INSERT WITH", "INSERT INTO dst (a) WITH c AS (SELECT LOWER(a) AS a FROM public.src) SELECT a FROM c",
			[]string{"c", "dst", "public.src"}, []string{"a"}, []string{"LOWER"},
			[]QualifiedName{{Name: "c"}, {Name: "dst"}, {Schema: "public", Name: "src"}}, []QualifiedName{{Name: "a"}}},
		{"UPDATE WITH", "WITH c AS (SELECT id FROM public.src) UPDATE dst SET a = LOWER(c.id) FROM c WHERE dst.id = c.id",
			[]string{"c", "dst", "public.src"}, []string{"a", "id"}, []string{"LOWER"},
			[]QualifiedName{{Name: "c"}, {Name: "dst"}, {Schema: "public", Name: "src"}}, []QualifiedName{{Name: "a"}, {Name: "id"}, {Table: "c", Name: "id"}, {Table: "dst", Name: "id"}}},
		{"DELETE WITH", "WITH c AS (SELECT id FROM public.src) DELETE FROM dst USING c WHERE dst.id = c.id",
			[]string{"c", "dst", "public.src"}, []string{"id"}, []string{},
			[]QualifiedName{{Name: "c"}, {Name: "dst"}, {Schema: "public", Name: "src"}}, []QualifiedName{{Name: "id"}, {Table: "c", Name: "id"}, {Table: "dst", Name: "id"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := Parse(tt.sql)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			assertMetadataMatchesExtractors(t, tree)
			md := ExtractMetadata(tree)
			if !reflect.DeepEqual(md.Tables, tt.tables) || !reflect.DeepEqual(md.Columns, tt.columns) || !reflect.DeepEqual(md.Functions, tt.functions) || !reflect.DeepEqual(md.TablesQualified, tt.qualifiedTables) || !reflect.DeepEqual(md.ColumnsQualified, tt.qualifiedColumns) {
				t.Fatalf("metadata = %#v", md)
			}
		})
	}
}
