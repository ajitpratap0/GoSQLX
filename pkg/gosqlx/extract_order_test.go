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
	"reflect"
	"slices"
	"testing"
)

type orderCase struct {
	name             string
	sql              string
	tables           []string
	tablesQualified  []QualifiedName
	columns          []string
	columnsQualified []QualifiedName
	functions        []string
}

// TestExtract_DeterministicOrder_Issue619 pins the documented sort order and
// checks that repeated calls return identical slices (map iteration order is
// random, so unsorted results differ from call to call).
func TestExtract_DeterministicOrder_Issue619(t *testing.T) {
	cases := []orderCase{
		{
			name:            "issue SQL",
			sql:             "SELECT a, b, c, d, e, f, g, h FROM t1 JOIN t2 ON t1.x = t2.y JOIN t3 ON t3.z = t1.x",
			tables:          []string{"t1", "t2", "t3"},
			tablesQualified: []QualifiedName{{Name: "t1"}, {Name: "t2"}, {Name: "t3"}},
			columns:         []string{"a", "b", "c", "d", "e", "f", "g", "h", "x", "y", "z"},
			columnsQualified: []QualifiedName{
				{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"}, {Name: "f"}, {Name: "g"}, {Name: "h"},
				{Table: "t1", Name: "x"}, {Table: "t2", Name: "y"}, {Table: "t3", Name: "z"},
			},
		},
		{
			name:            "schema alias and functions",
			sql:             "SELECT s1.a, s2.b, s1.c, COUNT(*), SUM(d), MAX(e) FROM sch1.t1 AS s1 JOIN sch2.t2 s2 ON s1.x = s2.y JOIN t3 ON t3.z = s1.x GROUP BY s1.a, s2.b, s1.c, d, e",
			tables:          []string{"sch1.t1", "sch2.t2", "t3"},
			tablesQualified: []QualifiedName{{Name: "t3"}, {Schema: "sch1", Name: "t1"}, {Schema: "sch2", Name: "t2"}},
			columns:         []string{"a", "b", "c", "d", "e", "x", "y", "z"},
			columnsQualified: []QualifiedName{
				{Name: "d"}, {Name: "e"},
				{Table: "s1", Name: "a"}, {Table: "s1", Name: "c"}, {Table: "s1", Name: "x"},
				{Table: "s2", Name: "b"}, {Table: "s2", Name: "y"}, {Table: "t3", Name: "z"},
			},
			functions: []string{"COUNT", "MAX", "SUM"},
		},
		{
			name:            "godoc join example",
			sql:             "SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
			tables:          []string{"orders", "users"},
			tablesQualified: []QualifiedName{{Name: "orders"}, {Name: "users"}},
			columns:         []string{"id", "user_id"},
			columnsQualified: []QualifiedName{
				{Table: "o", Name: "user_id"}, {Table: "u", Name: "id"},
			},
		},
		{
			name:            "godoc columns example",
			sql:             "SELECT u.name, u.email FROM users u WHERE u.active = true ORDER BY u.created_at",
			tables:          []string{"users"},
			tablesQualified: []QualifiedName{{Name: "users"}},
			columns:         []string{"active", "created_at", "email", "name"},
			columnsQualified: []QualifiedName{
				{Table: "u", Name: "active"}, {Table: "u", Name: "created_at"},
				{Table: "u", Name: "email"}, {Table: "u", Name: "name"},
			},
		},
	}

	const runs = 50
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := Parse(tc.sql)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.sql, err)
			}

			for i := 0; i < runs; i++ {
				m := ExtractMetadata(tree)
				if !slices.Equal(m.Tables, tc.tables) {
					t.Fatalf("run %d: ExtractMetadata Tables = %v, want %v", i, m.Tables, tc.tables)
				}
				if !slices.Equal(m.TablesQualified, tc.tablesQualified) {
					t.Fatalf("run %d: ExtractMetadata TablesQualified = %v, want %v", i, m.TablesQualified, tc.tablesQualified)
				}
				if !slices.Equal(m.Columns, tc.columns) {
					t.Fatalf("run %d: ExtractMetadata Columns = %v, want %v", i, m.Columns, tc.columns)
				}
				if !slices.Equal(m.ColumnsQualified, tc.columnsQualified) {
					t.Fatalf("run %d: ExtractMetadata ColumnsQualified = %v, want %v", i, m.ColumnsQualified, tc.columnsQualified)
				}
				if len(m.Functions) != len(tc.functions) || (len(tc.functions) > 0 && !slices.Equal(m.Functions, tc.functions)) {
					t.Fatalf("run %d: ExtractMetadata Functions = %v, want %v", i, m.Functions, tc.functions)
				}

				if got := ExtractTables(tree); !slices.Equal(got, tc.tables) {
					t.Fatalf("run %d: ExtractTables = %v, want %v", i, got, tc.tables)
				}
				if got := ExtractTablesQualified(tree); !slices.Equal(got, tc.tablesQualified) {
					t.Fatalf("run %d: ExtractTablesQualified = %v, want %v", i, got, tc.tablesQualified)
				}
				if got := ExtractColumns(tree); !slices.Equal(got, tc.columns) {
					t.Fatalf("run %d: ExtractColumns = %v, want %v", i, got, tc.columns)
				}
				if got := ExtractColumnsQualified(tree); !slices.Equal(got, tc.columnsQualified) {
					t.Fatalf("run %d: ExtractColumnsQualified = %v, want %v", i, got, tc.columnsQualified)
				}
				if got := ExtractFunctions(tree); len(got) != len(tc.functions) || (len(tc.functions) > 0 && !slices.Equal(got, tc.functions)) {
					t.Fatalf("run %d: ExtractFunctions = %v, want %v", i, got, tc.functions)
				}
			}
		})
	}
}

// TestExtract_SortedInvariant checks that every result slice is sorted and
// that ExtractMetadata agrees with the individual extractors element by
// element, not just as sets.
func TestExtract_SortedInvariant(t *testing.T) {
	queries := []string{
		"WITH c AS (SELECT z, y FROM tz) SELECT ROW_NUMBER() OVER (ORDER BY b), UPPER(a) FROM c UNION SELECT q, LOWER(p) FROM ta",
		"SELECT m.k, (SELECT MAX(v) FROM inner_t WHERE inner_t.id = m.id) FROM main_t m WHERE m.k IN (SELECT k FROM other_t)",
		"SELECT s.t.c1, s.t.c2, COALESCE(x, y) FROM s.t JOIN u ON u.id = s.t.id",
	}

	for _, sql := range queries {
		t.Run(sql, func(t *testing.T) {
			tree, err := Parse(sql)
			if err != nil {
				t.Fatalf("Parse(%q): %v", sql, err)
			}
			m := ExtractMetadata(tree)

			if !slices.IsSorted(m.Tables) || !slices.IsSorted(m.Columns) || !slices.IsSorted(m.Functions) {
				t.Errorf("ExtractMetadata string slices not sorted: %v %v %v", m.Tables, m.Columns, m.Functions)
			}
			if !slices.IsSortedFunc(m.TablesQualified, compareQualifiedName) || !slices.IsSortedFunc(m.ColumnsQualified, compareQualifiedName) {
				t.Errorf("ExtractMetadata qualified slices not sorted: %v %v", m.TablesQualified, m.ColumnsQualified)
			}

			tables, columns, functions := ExtractTables(tree), ExtractColumns(tree), ExtractFunctions(tree)
			tq, cq := ExtractTablesQualified(tree), ExtractColumnsQualified(tree)
			if !slices.IsSorted(tables) || !slices.IsSorted(columns) || !slices.IsSorted(functions) {
				t.Errorf("extractor string slices not sorted: %v %v %v", tables, columns, functions)
			}
			if !slices.IsSortedFunc(tq, compareQualifiedName) || !slices.IsSortedFunc(cq, compareQualifiedName) {
				t.Errorf("extractor qualified slices not sorted: %v %v", tq, cq)
			}

			if !reflect.DeepEqual(m.Tables, tables) || !reflect.DeepEqual(m.Columns, columns) ||
				!reflect.DeepEqual(m.Functions, functions) || !reflect.DeepEqual(m.TablesQualified, tq) ||
				!reflect.DeepEqual(m.ColumnsQualified, cq) {
				t.Errorf("ExtractMetadata disagrees with individual extractors:\n%+v\ntables=%v columns=%v functions=%v tq=%v cq=%v", m, tables, columns, functions, tq, cq)
			}
		})
	}
}
