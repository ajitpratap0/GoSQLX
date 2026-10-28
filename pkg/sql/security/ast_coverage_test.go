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

package security

import (
	"reflect"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

type astCoverageCase struct {
	name     string
	sql      string
	dialect  keywords.SQLDialect
	patterns []PatternType
	exact    map[PatternType]int
}

func astCoverageCases() []astCoverageCase {
	const pg = keywords.DialectPostgreSQL
	tb := []PatternType{PatternTimeBased}
	taut := []PatternType{PatternTautology}
	oob := []PatternType{PatternOutOfBand}
	oneTB := map[PatternType]int{PatternTimeBased: 1}
	oneOOB := map[PatternType]int{PatternOutOfBand: 1}
	return []astCoverageCase{
		{"01 CTE function", "WITH c AS (SELECT pg_sleep(5)) SELECT * FROM c", pg, tb, oneTB},
		{"02 CTE condition", "WITH c AS (SELECT * FROM t WHERE 1=1 OR 2=2) SELECT * FROM c", pg, taut, nil},
		{"03 derived table", "SELECT * FROM (SELECT pg_sleep(5)) s", pg, tb, oneTB},
		{"04 IN subquery", "SELECT * FROM t WHERE id IN (SELECT pg_sleep(5))", pg, tb, oneTB},
		{"05 EXISTS", "SELECT * FROM t WHERE EXISTS (SELECT pg_sleep(5))", pg, tb, nil},
		{"06 scalar subquery", "SELECT * FROM t WHERE x = (SELECT pg_sleep(5))", pg, tb, oneTB},
		{"07 CASE", "SELECT CASE WHEN 1=1 THEN pg_sleep(5) END FROM t", pg, []PatternType{PatternTimeBased, PatternTautology}, oneTB},
		{"08 CAST", "SELECT CAST(pg_sleep(5) AS text) FROM t", pg, tb, nil},
		{"09 BETWEEN", "SELECT * FROM t WHERE x BETWEEN pg_sleep(1) AND 2", pg, tb, nil},
		{"10 IN list", "SELECT * FROM t WHERE x IN (pg_sleep(1), 2)", pg, tb, nil},
		{"11 ORDER BY", "SELECT * FROM t ORDER BY pg_sleep(5)", pg, tb, nil},
		{"12 GROUP BY", "SELECT * FROM t GROUP BY pg_sleep(5)", pg, tb, nil},
		{"13 JOIN condition", "SELECT * FROM a JOIN b ON a.id = b.id OR 1=1", pg, taut, nil},
		{"14 JOIN function", "SELECT * FROM a JOIN b ON pg_sleep(5) IS NULL", pg, tb, oneTB},
		{"15 window", "SELECT count(*) OVER (ORDER BY pg_sleep(5)) FROM t", pg, tb, nil},
		{"16 INSERT SELECT", "INSERT INTO t SELECT pg_sleep(5)", pg, tb, nil},
		{"17 ON CONFLICT", "INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET x = pg_sleep(5)", pg, tb, nil},
		{"18 INSERT RETURNING", "INSERT INTO t VALUES (1) RETURNING pg_sleep(5)", pg, tb, nil},
		{"19 UPDATE RETURNING", "UPDATE t SET x = 1 RETURNING pg_sleep(5)", pg, tb, nil},
		{"20 DELETE subquery", "DELETE FROM t WHERE id IN (SELECT id FROM u WHERE 1=1 OR 2=2)", pg, taut, nil},
		{"21 MERGE UPDATE", "MERGE INTO t USING s ON t.id = s.id OR 1=1 WHEN MATCHED THEN UPDATE SET x = pg_sleep(5)", pg, []PatternType{PatternTautology, PatternTimeBased}, nil},
		{"22 MERGE INSERT", "MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED THEN INSERT (a) VALUES (pg_sleep(5))", pg, tb, nil},
		{"23 CREATE TABLE AS", "CREATE TABLE x AS SELECT pg_sleep(5)", pg, tb, nil},
		{"24 CREATE VIEW", "CREATE VIEW v AS SELECT pg_sleep(5)", pg, tb, nil},
		{"25 CREATE MATERIALIZED VIEW", "CREATE MATERIALIZED VIEW v AS SELECT pg_sleep(5)", pg, tb, nil},
		{"26 EXPLAIN", "EXPLAIN SELECT pg_sleep(5)", pg, tb, nil},
		{"27 UNION derived table", "SELECT 1 UNION SELECT * FROM (SELECT pg_sleep(5)) s", pg, tb, oneTB},
		{"28 ANY", "SELECT * FROM t WHERE x = ANY (SELECT pg_sleep(5))", pg, tb, nil},
		{"29 ARRAY", "SELECT ARRAY[pg_sleep(5)]", pg, tb, nil},
		{"30 tuple", "SELECT (pg_sleep(5), 1)", pg, tb, nil},
		{"31 FILTER", "SELECT coalesce(x, 1) FILTER (WHERE pg_sleep(5) IS NULL) FROM t", pg, tb, nil},
		{"32 LIMIT", "SELECT * FROM t LIMIT (SELECT pg_sleep(5))", pg, tb, nil},
		{"33 LATERAL", "SELECT * FROM t, LATERAL (SELECT pg_sleep(5)) s", pg, tb, nil},
		{"34 cast operator", "SELECT x::text FROM t WHERE pg_sleep(5)::text = ''", pg, tb, nil},
		{"35 EXTRACT", "SELECT EXTRACT(YEAR FROM pg_sleep(5))", pg, tb, nil},
		{"36 nested VALUES", "SELECT * FROM (VALUES (pg_sleep(5))) v", pg, tb, oneTB},
		{"37 CTE UNION", "WITH c AS (SELECT id FROM t UNION SELECT table_name FROM information_schema.tables) SELECT * FROM c", pg, []PatternType{PatternUnionBased}, nil},
		{"38 WHERE function", "SELECT * FROM t WHERE pg_sleep(5) IS NULL", pg, tb, oneTB},
		{"39a function", "SELECT pg_sleep(5)", pg, tb, oneTB},
		{"39b qualified function", "SELECT pg_catalog.pg_sleep(5)", pg, tb, oneTB},
		{"40 CONNECT BY", "SELECT * FROM t START WITH id = 1 CONNECT BY PRIOR id = pid AND DBMS_LOCK.SLEEP(5) = 1", keywords.DialectOracle, tb, nil},
		{"41 PREWHERE", "SELECT * FROM t PREWHERE sleep(3) = 0", keywords.DialectClickHouse, tb, nil},
		{"42 table function", "SELECT * FROM url('http://x/a.csv', CSV, 'a String')", keywords.DialectClickHouse, oob, oneOOB},
		{"43 JOIN table function", "SELECT * FROM t JOIN url('http://x/a.csv', CSV, 'a String') u ON 1 = 1", keywords.DialectClickHouse, oob, oneOOB},
		{"44 APPLY", "SELECT TOP (1) * FROM t CROSS APPLY (SELECT xp_cmdshell('dir')) s", keywords.DialectSQLServer, oob, nil},
		{"45 IF WAITFOR", "IF 1=1 WAITFOR DELAY '0:0:5'", keywords.DialectSQLServer, []PatternType{PatternTimeBased, PatternTautology}, nil},
		{"46 IF subquery WAITFOR", "IF (SELECT COUNT(*) FROM users) > 0 WAITFOR DELAY '0:0:5'", keywords.DialectSQLServer, tb, nil},
		{"47 IF BEGIN WAITFOR", "IF 1=1 BEGIN WAITFOR DELAY '0:0:5' END", keywords.DialectSQLServer, tb, nil},
		{"48 AND function", "SELECT * FROM t WHERE id = 1 AND SLEEP(5)", keywords.DialectMySQL, tb, oneTB},
		{"49 LIKE function", "SELECT * FROM t WHERE x LIKE SLEEP(5)", keywords.DialectMySQL, tb, oneTB},
		{"50 QUALIFY", "SELECT * FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY pg_sleep(5)) = 1", keywords.DialectSnowflake, tb, nil},
		{"FILTER condition", "SELECT count(*) FILTER (WHERE 1=1) FROM t", pg, taut, nil},
		{"ON CONFLICT target condition", "INSERT INTO t VALUES (1) ON CONFLICT (id) WHERE 1=1 DO NOTHING", pg, taut, nil},
		{"ON CONFLICT action condition", "INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET x = 1 WHERE 1=1", pg, taut, nil},
		{"QUALIFY condition", "SELECT * FROM t QUALIFY 1=1", keywords.DialectSnowflake, taut, nil},
		{"PREWHERE condition", "SELECT * FROM t PREWHERE 1=1", keywords.DialectClickHouse, taut, nil},
		{"START WITH condition", "SELECT * FROM t START WITH 1=1 CONNECT BY PRIOR id = pid", keywords.DialectOracle, taut, nil},
		{"CONNECT BY condition", "SELECT * FROM t START WITH id = 1 CONNECT BY 1=1", keywords.DialectOracle, taut, nil},
		{"MERGE WHEN condition", "MERGE INTO t USING s ON t.id = s.other_id WHEN MATCHED AND 1=1 THEN UPDATE SET x = s.x", pg, taut, nil},
		{"JOIN MATCH_CONDITION", "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION (1=1) ON t1.sym = t2.other_sym", keywords.DialectSnowflake, taut, nil},
		{"boolean parentheses and NOT", "SELECT * FROM t WHERE NOT (x = 1 OR (1=1))", pg, taut, nil},
		{"nested dangerous function", "WITH c AS (SELECT CASE WHEN x > 1 THEN xp_cmdshell('dir') END FROM t) SELECT * FROM c", keywords.DialectSQLServer, oob, oneOOB},
		{"standalone WAITFOR", "WAITFOR DELAY '0:0:5'", keywords.DialectSQLServer, tb, nil},
		{"EXEC utility", "EXEC xp_cmdshell 'dir'", keywords.DialectSQLServer, oob, nil},
		{"standalone VALUES", "VALUES (pg_sleep(5))", pg, tb, oneTB},
		{"standalone VALUES CASE", "VALUES (CASE WHEN 1=1 THEN pg_sleep(5) END)", pg, []PatternType{PatternTimeBased, PatternTautology}, oneTB},
	}
}

func astCoveragePatternCount(result *ScanResult, pattern PatternType) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Pattern == pattern {
			count++
		}
	}
	return count
}

func TestScan_ASTCoverage(t *testing.T) {
	scanner := NewScanner()
	for _, tt := range astCoverageCases() {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)
			result := scanner.Scan(tree)
			for _, pattern := range tt.patterns {
				if astCoveragePatternCount(result, pattern) == 0 {
					t.Errorf("Scan missing %s: %+v", pattern, result.Findings)
				}
			}
			for pattern, want := range tt.exact {
				if got := astCoveragePatternCount(result, pattern); got != want {
					t.Errorf("Scan %s count = %d, want %d; findings: %+v", pattern, got, want, result.Findings)
				}
			}
			textResult := scanner.ScanSQL(tt.sql)
			for _, pattern := range []PatternType{PatternTimeBased, PatternOutOfBand, PatternTautology} {
				if hasPattern(textResult, pattern) && !hasPattern(result, pattern) {
					t.Errorf("ScanSQL reports %s but Scan does not; text: %+v; AST: %+v", pattern, textResult.Findings, result.Findings)
				}
			}
		})
	}
}

func TestScan_ASTCoverageClean(t *testing.T) {
	tests := []string{
		"SELECT 1=1 FROM t ORDER BY 2=2",
		"SELECT f(1=1) FROM t",
		"WITH c AS (SELECT id FROM t WHERE id = 1) SELECT * FROM c",
		"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET x = s.x WHEN NOT MATCHED THEN INSERT (id, x) VALUES (s.id, s.x)",
		"SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END FROM t ORDER BY a",
		"SELECT * FROM a JOIN b ON a.id = b.id WHERE b.x IN (SELECT x FROM c WHERE c.y = 2)",
		"CREATE VIEW v AS SELECT id, name FROM users WHERE active = true",
	}
	for _, sql := range tests {
		t.Run(sql, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if result := NewScanner().Scan(tree); !result.IsClean() {
				t.Errorf("expected clean Scan, got %+v", result.Findings)
			}
		})
	}
}

func TestScan_ASTCoverageUnion(t *testing.T) {
	scanner := NewScanner()
	const unionSQL = "SELECT id FROM t UNION SELECT table_name FROM information_schema.tables"
	baselineTree, err := parser.ParseWithDialect(unionSQL, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(baselineTree)
	baseline := scanner.Scan(baselineTree)
	if countUnionSystemTableFindings(baseline) == 0 {
		t.Fatalf("top-level UNION missing CRITICAL finding: %+v", baseline.Findings)
	}
	for _, sql := range []string{
		"WITH c AS (" + unionSQL + ") SELECT * FROM c",
		"SELECT * FROM (" + unionSQL + ") s",
	} {
		tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		result := scanner.Scan(tree)
		ast.ReleaseAST(tree)
		if !reflect.DeepEqual(result.Findings, baseline.Findings) {
			t.Errorf("nested UNION findings = %+v, want top-level findings %+v", result.Findings, baseline.Findings)
		}
	}
	tree, err := parser.ParseWithDialect("SELECT * FROM t1 UNION ALL SELECT * FROM t2", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	result := scanner.Scan(tree)
	for _, pattern := range []PatternType{PatternTimeBased, PatternOutOfBand, PatternTautology} {
		if hasPattern(result, pattern) {
			t.Errorf("benign UNION has unexpected %s: %+v", pattern, result.Findings)
		}
	}
	// The existing AST path produces no generic UNION finding.
	if !result.IsClean() {
		t.Errorf("benign UNION findings changed: %+v", result.Findings)
	}
}

func TestScan_ASTCoverageConcurrent(t *testing.T) {
	scanner := NewScanner()
	sqls := []string{
		"WITH c AS (SELECT pg_sleep(5)) SELECT * FROM c",
		"SELECT CASE WHEN 1=1 THEN pg_sleep(5) END FROM t",
		"SELECT * FROM (VALUES (pg_sleep(5))) v",
		"SELECT id FROM t UNION SELECT table_name FROM information_schema.tables",
	}
	trees := make([]*ast.AST, 0, len(sqls))
	expected := make([]*ScanResult, 0, len(sqls))
	for _, sql := range sqls {
		tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		defer ast.ReleaseAST(tree)
		trees = append(trees, tree)
		expected = append(expected, scanner.Scan(tree))
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				for i, tree := range trees {
					if result := scanner.Scan(tree); !reflect.DeepEqual(result, expected[i]) {
						t.Errorf("concurrent Scan changed result for %q: %+v", sqls[i], result)
					}
				}
			}
		}()
	}
	wg.Wait()
}
