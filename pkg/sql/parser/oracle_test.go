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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func parseOracle(t *testing.T, sql string) *ast.AST {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectOracle)
	if err != nil {
		t.Fatalf("ParseWithDialect(Oracle) error: %v\n  SQL: %s", err, sql)
	}
	return tree
}

// --- ROWNUM pseudo-column ---

func TestOracle_Rownum_SimpleWhere(t *testing.T) {
	tree := parseOracle(t, "SELECT * FROM users WHERE ROWNUM <= 10")
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.Where == nil {
		t.Error("expected WHERE clause")
	}
}

func TestOracle_Rownum_Pagination(t *testing.T) {
	sql := `SELECT * FROM (
		SELECT a.*, ROWNUM rnum FROM (
			SELECT * FROM users ORDER BY created_at DESC
		) a WHERE ROWNUM <= 30
	) WHERE rnum > 20`
	parseOracle(t, sql)
}

func TestOracle_Level_InSelect(t *testing.T) {
	parseOracle(t, "SELECT LEVEL, id FROM categories START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id")
}

func TestOracle_Sysdate(t *testing.T) {
	parseOracle(t, "SELECT SYSDATE FROM DUAL")
}

// --- CONNECT BY ---

func TestOracle_ConnectBy_WithIsNull(t *testing.T) {
	sql := `SELECT employee_id, manager_id, name
	        FROM employees
	        START WITH manager_id IS NULL
	        CONNECT BY PRIOR employee_id = manager_id`
	tree := parseOracle(t, sql)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if sel.StartWith == nil {
		t.Error("expected StartWith clause")
	}
	if sel.ConnectBy == nil {
		t.Error("expected ConnectBy clause")
	}
}

func TestOracle_ConnectBy_NoCycle(t *testing.T) {
	sql := `SELECT id, parent_id FROM categories
	        START WITH parent_id IS NULL
	        CONNECT BY NOCYCLE PRIOR id = parent_id`
	tree := parseOracle(t, sql)
	sel := tree.Statements[0].(*ast.SelectStatement)
	if sel.ConnectBy == nil || !sel.ConnectBy.NoCycle {
		t.Error("expected NOCYCLE modifier on ConnectBy")
	}
}

func TestOracle_ConnectBy_SysConnectByPath(t *testing.T) {
	parseOracle(t, `SELECT SYS_CONNECT_BY_PATH(name, '/') AS path FROM employees START WITH manager_id IS NULL CONNECT BY PRIOR id = manager_id`)
}

// --- PIVOT / UNPIVOT ---

func TestOracle_Pivot(t *testing.T) {
	sql := `SELECT * FROM (
		SELECT product, region, sales FROM sales_data
	) PIVOT (
		SUM(sales) FOR region IN ('North' AS north, 'South' AS south, 'East' AS east, 'West' AS west)
	)`
	tree := parseOracle(t, sql)
	sel := tree.Statements[0].(*ast.SelectStatement)
	if len(sel.From) == 0 {
		t.Fatal("expected FROM clause")
	}
	if sel.From[0].Pivot == nil {
		t.Error("expected PIVOT clause on first table reference")
	}
}

func TestOracle_Unpivot(t *testing.T) {
	sql := `SELECT product, region, sales FROM regional_sales
	UNPIVOT (
		sales FOR region IN (north_sales AS 'North', south_sales AS 'South', east_sales AS 'East', west_sales AS 'West')
	)`
	tree := parseOracle(t, sql)
	sel := tree.Statements[0].(*ast.SelectStatement)
	if len(sel.From) == 0 {
		t.Fatal("expected FROM clause")
	}
	if sel.From[0].Unpivot == nil {
		t.Error("expected UNPIVOT clause on first table reference")
	}
}

// --- Backslash in string literals ---

func TestOracle_RegexpBackslash(t *testing.T) {
	parseOracle(t, `SELECT name, email FROM users WHERE REGEXP_LIKE(email, '^\w+@[\w.]+\.\w+$')`)
}

// --- Standard Oracle features ---

func TestOracle_Merge(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id
	        WHEN MATCHED THEN UPDATE SET t.name = s.name
	        WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, s.name)`
	parseOracle(t, sql)
}

func TestOracle_OffsetFetch(t *testing.T) {
	parseOracle(t, "SELECT * FROM users ORDER BY id OFFSET 10 ROWS FETCH NEXT 20 ROWS ONLY")
}

func TestOracle_NVL(t *testing.T) {
	parseOracle(t, "SELECT NVL(name, 'Unknown') FROM users")
}

func TestOracle_Decode(t *testing.T) {
	parseOracle(t, "SELECT DECODE(status, 'A', 'Active', 'I', 'Inactive', 'Unknown') FROM users")
}
