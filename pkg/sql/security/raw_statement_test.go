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
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// The supplied review matrix contains 91 payloads (the brief calls it 93).
// Expected findings were frozen from the unchanged origin/main ScanSQL rules.
func TestScanSQL_ReviewPayloadMatrix(t *testing.T) {
	data, err := os.ReadFile("testdata/review_payload_findings.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected [][]Finding
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(reviewPayloads) {
		t.Fatalf("golden payload count %d, want %d", len(expected), len(reviewPayloads))
	}
	scanner := NewScanner()
	for i, sql := range reviewPayloads {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if got := scanner.ScanSQL(sql).Findings; !reflect.DeepEqual(got, expected[i]) {
				t.Errorf("ScanSQL(%q) = %+v, want %+v", sql, got, expected[i])
			}
		})
	}
}

func TestScan_ReviewPayloadMatrixRawStatements(t *testing.T) {
	scanner := NewScanner()
	for _, dialect := range []keywords.SQLDialect{
		"", keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB,
		keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSQLite,
		keywords.DialectSnowflake, keywords.DialectClickHouse,
	} {
		for i, sql := range reviewPayloads {
			t.Run(fmt.Sprintf("%s/%d", dialect, i), func(t *testing.T) {
				tree, err := parser.ParseWithDialect(sql, dialect)
				if err != nil {
					return // Only statements parseable in this dialect have an AST to scan.
				}
				defer ast.ReleaseAST(tree)
				if len(tree.Statements) != 1 {
					return
				}
				switch tree.Statements[0].(type) {
				case *ast.Values, *ast.UtilityStatement, *ast.SetStatement,
					*ast.TransactionStatement, *ast.UseStatement, *ast.UnsupportedStatement:
				default:
					return
				}
				got, want := scanner.Scan(tree), scanner.ScanSQL(sql)
				if !reflect.DeepEqual(findingSignatures(got), findingSignatures(want)) {
					t.Errorf("Scan(%q) = %+v, ScanSQL = %+v", sql, got.Findings, want.Findings)
				}
			})
		}
	}
}

func TestScan_RawStatementsMatchScanSQL(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "VALUES (SLEEP(5))"},
		{keywords.DialectPostgreSQL, "VALUES (pg_sleep(5))"},
		{keywords.DialectMySQL, "VALUES ROW(SLEEP(5))"},
		{keywords.DialectMySQL, "VALUES ROW(pg_sleep(5))"},
		{keywords.DialectPostgreSQL, "VALUES (SLEEP(LOAD_FILE('/x')))"},
		{keywords.DialectPostgreSQL, "VALUES (CAST(SLEEP(5) AS INTEGER))"},
		{keywords.DialectPostgreSQL, "VALUES (CASE WHEN id = 1 THEN SLEEP(5) ELSE 0 END)"},
		{keywords.DialectPostgreSQL, "VALUES ((SELECT pg_sleep(5)))"},
		{keywords.DialectPostgreSQL, "VALUES ('OR 1=1')"},
		{keywords.DialectSQLServer, "IF 1=1 WAITFOR DELAY '0:0:5'"},
		{keywords.DialectSQLServer, "WHILE 1=1 BEGIN WAITFOR DELAY '0:0:5' END"},
		{keywords.DialectSQLServer, "BEGIN WAITFOR DELAY '0:0:5' END"},
		{keywords.DialectMySQL, "SET @a = SLEEP(5)"},
		{keywords.DialectMySQL, "PREPARE stmt FROM 'SELECT SLEEP(5)'"},
		{keywords.DialectSQLServer, "EXEC sp_executesql N'SELECT SLEEP(5)'"},
		{keywords.DialectSnowflake, "EXECUTE IMMEDIATE 'SELECT SLEEP(5)'"},
		{keywords.DialectPostgreSQL, "CREATE POLICY p ON t USING (pg_sleep(5) IS NULL)"},
		{keywords.DialectPostgreSQL, "CREATE TRIGGER trg BEFORE UPDATE ON t FOR EACH ROW WHEN (pg_sleep(5) IS NULL) EXECUTE FUNCTION f()"},
	}
	scanner := NewScanner()
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			want, got := scanner.ScanSQL(tt.sql), scanner.Scan(tree)
			if want.IsClean() {
				t.Fatal("payload must produce findings")
			}
			if !reflect.DeepEqual(findingSignatures(got), findingSignatures(want)) {
				t.Errorf("Scan = %+v, ScanSQL = %+v", got.Findings, want.Findings)
			}
			if got.TotalCount != len(got.Findings) {
				t.Errorf("incorrect count: %+v", got)
			}
		})
	}
}

func findingSignatures(result *ScanResult) []string {
	signatures := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		signatures = append(signatures, string(finding.Pattern)+"/"+string(finding.Severity))
	}
	sort.Strings(signatures)
	return signatures
}

func TestScan_RetainedStatementText(t *testing.T) {
	// Exercise every raw-text statement type with all raw scanner rules, including
	// comments that may be absent from a parser's token-rebuilt statement text.
	text := "SELECT * FROM t WHERE id = 1 OR 1=1 --\n; DROP TABLE t; SELECT SLEEP(5), LOAD_FILE('/x') UNION SELECT NULL, NULL FROM information_schema.tables; EXEC('x');"
	statements := []ast.Statement{
		&ast.UtilityStatement{Text: text}, &ast.SetStatement{Text: text},
		&ast.TransactionStatement{Text: text}, &ast.UseStatement{Text: text},
		&ast.UnsupportedStatement{RawSQL: text},
	}
	scanner := NewScanner()
	for _, stmt := range statements {
		t.Run(fmt.Sprintf("%T", stmt), func(t *testing.T) {
			tree := &ast.AST{Statements: []ast.Statement{stmt}}
			if got, want := scanner.Scan(tree), scanner.ScanSQL(text); !reflect.DeepEqual(got, want) {
				t.Errorf("Scan = %+v, ScanSQL = %+v", got, want)
			}
		})
	}
}
