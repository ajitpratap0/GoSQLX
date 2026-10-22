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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestPrimaryForms_RoundTrip checks that primary expressions and special
// function-call forms survive format → parse → format unchanged and that the
// formatted text keeps their meaning (want is a substring of the output).
func TestPrimaryForms_RoundTrip(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		// Keyword-named and qualified function calls are written bare.
		{keywords.DialectMySQL, "SELECT LEFT(name, 2), RIGHT(name, 2) FROM t", "LEFT(name, 2), RIGHT(name, 2)"},
		{keywords.DialectPostgreSQL, "SELECT GROUPING(a) FROM t GROUP BY a", "GROUPING(a)"},
		{keywords.DialectMySQL, "SELECT TRUNCATE(x, 1), DEFAULT(c) FROM t", "TRUNCATE(x, 1), DEFAULT(c)"},
		{keywords.DialectClickHouse, "SELECT any(a), range(1, 2) FROM t", "any(a), range(1, 2)"},
		{keywords.DialectSnowflake, "SELECT HASH(a) FROM t", "HASH(a)"},
		{keywords.DialectPostgreSQL, "SELECT ROW(1, 2) = ROW(1, 2)", "ROW(1, 2) = ROW(1, 2)"},
		{keywords.DialectPostgreSQL, "SELECT pg_catalog.now(), auth.uid()", "pg_catalog.now(), auth.uid()"},
		{keywords.DialectOracle, "SELECT DBMS_RANDOM.VALUE(1, 100) FROM dual", "DBMS_RANDOM.VALUE(1, 100)"},
		// Literals.
		{keywords.DialectPostgreSQL, "SELECT DATE '2024-01-01', inet '10.0.0.1'", "DATE '2024-01-01', inet '10.0.0.1'"},
		{keywords.DialectOracle, "SELECT a FROM t WHERE d >= DATE '2024-01-01'", "d >= DATE '2024-01-01'"},
		{keywords.DialectSQLServer, "SELECT a FROM t WHERE b = N'x''y' AND c IN (N'a', N'b')", "b = N'x''y' AND c IN (N'a', N'b')"},
		{keywords.DialectMySQL, "SELECT 'a' 'b'", "'ab'"},
		// Special forms keep their keywords.
		{keywords.DialectPostgreSQL, "SELECT substring(name FROM 2 FOR 3), position('a' IN b) FROM t", "substring(name FROM 2 FOR 3), position('a' IN b)"},
		{keywords.DialectPostgreSQL, "SELECT trim(BOTH ' ' FROM x), trim(LEADING FROM y) FROM t", "trim(BOTH ' ' FROM x), trim(LEADING FROM y)"},
		{keywords.DialectPostgreSQL, "SELECT overlay(s PLACING 'ab' FROM 2 FOR 3) FROM t", "overlay(s PLACING 'ab' FROM 2 FOR 3)"},
		{keywords.DialectMySQL, "SELECT CONVERT(x USING utf8mb4) FROM t", "CONVERT(x USING utf8mb4)"},
		{keywords.DialectSQLServer, "SELECT TRY_PARSE(N'1' AS INT)", "TRY_PARSE(N'1' AS INT)"},
		{keywords.DialectMariaDB, "SELECT COLUMN_GET(d, 'k' AS CHAR) FROM t", "COLUMN_GET(d, 'k' AS CHAR)"},
		{keywords.DialectOracle, "SELECT LISTAGG(a, ',' ON OVERFLOW TRUNCATE '...' WITH COUNT) WITHIN GROUP (ORDER BY a) FROM t",
			"LISTAGG(a, ',' ON OVERFLOW TRUNCATE '...' WITH COUNT) WITHIN GROUP (ORDER BY a)"},
		{keywords.DialectOracle, "SELECT MAX(a) KEEP (DENSE_RANK LAST ORDER BY b) FROM t", "MAX(a) KEEP (DENSE_RANK LAST ORDER BY b)"},
		// GROUP_CONCAT SEPARATOR is not an extra argument.
		{keywords.DialectMySQL, "SELECT GROUP_CONCAT(a SEPARATOR '|') FROM t", "GROUP_CONCAT(a SEPARATOR '|')"},
		{keywords.DialectMariaDB, "SELECT GROUP_CONCAT(DISTINCT a ORDER BY a DESC SEPARATOR ',') FROM t",
			"GROUP_CONCAT(DISTINCT a ORDER BY a DESC SEPARATOR ',')"},
		// INTERVAL keeps an unquoted value unquoted.
		{keywords.DialectMySQL, "SELECT NOW() - INTERVAL 1 DAY", "NOW() - INTERVAL 1 DAY"},
		{keywords.DialectMySQL, "SELECT DATE_ADD(d, INTERVAL 1 MONTH) FROM t", "DATE_ADD(d, INTERVAL 1 MONTH)"},
		{keywords.DialectClickHouse, "SELECT now() - INTERVAL x DAY", "now() - INTERVAL x DAY"},
		{keywords.DialectMySQL, "SELECT INTERVAL(5, 1, 10)", "INTERVAL(5, 1, 10)"},
		{keywords.DialectPostgreSQL, "SELECT INTERVAL '1 day'", "INTERVAL '1 day'"},
		// MATCH ... AGAINST.
		{keywords.DialectMySQL, "SELECT * FROM t WHERE MATCH(a) AGAINST ('x' IN BOOLEAN MODE)", "MATCH(a) AGAINST('x' IN BOOLEAN MODE)"},
		// Oracle.
		{keywords.DialectOracle, "SELECT * FROM a, b WHERE a.id = b.id(+)", "a.id = b.id(+)"},
		{keywords.DialectOracle, "SELECT CONNECT_BY_ROOT name, PRIOR name AS m FROM e", "CONNECT_BY_ROOT name, PRIOR name AS m"},
		// Sequences and variables.
		{keywords.DialectSQLServer, "SELECT NEXT VALUE FOR dbo.s", "NEXT VALUE FOR dbo.s"},
		{keywords.DialectMySQL, "SELECT @@version, @@session.sql_mode", "@@version, @@session.sql_mode"},
		{keywords.DialectMySQL, "SELECT @rn := @rn + 1 AS rn FROM t", "@rn := @rn + 1 AS rn"},
		// Arrays.
		{keywords.DialectPostgreSQL, "SELECT ARRAY[[1, 2], [3, 4]]", "ARRAY[[1, 2], [3, 4]]"},
		{keywords.DialectPostgreSQL, "SELECT ARRAY(SELECT 1 UNION SELECT 2)", "ARRAY(SELECT 1 UNION SELECT 2)"},
		{keywords.DialectSnowflake, "SELECT [1, 2, 3] AS ar", "[1, 2, 3] AS ar"},
		{keywords.DialectClickHouse, "SELECT [1, 2, 3][2], (1, 'a').1", "[1, 2, 3][2], (1, 'a').1"},
		// CAST forms.
		{keywords.DialectClickHouse, "SELECT CAST(x, 'UInt32')", "CAST(x, 'UInt32')"},
		{keywords.DialectSnowflake, "SELECT TRY_CAST(x AS INT)", "TRY_CAST(x AS INT)"},
		{keywords.DialectPostgreSQL, "SELECT CAST(a AS int[]), CAST(b AS double precision)", "CAST(a AS int[]), CAST(b AS double precision)"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			f1 := FormatAST(tree)
			if !strings.Contains(strings.Join(strings.Fields(f1), " "), tt.want) {
				t.Errorf("formatted output\n  %s\ndoes not contain\n  %s", f1, tt.want)
			}
			tree2, err := ParseWithDialect(f1, tt.dialect)
			if err != nil {
				t.Fatalf("reparse of %q: %v", f1, err)
			}
			if f2 := FormatAST(tree2); f2 != f1 {
				t.Errorf("not idempotent:\n  %s\n  %s", f1, f2)
			}
		})
	}
}

// TestPrimaryForms_ExtractColumns checks that column extraction descends into
// the new primary-expression nodes.
func TestPrimaryForms_ExtractColumns(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    []string
	}{
		{keywords.DialectMySQL, "SELECT id FROM t WHERE MATCH(title, body) AGAINST ('x' IN BOOLEAN MODE)", []string{"body", "id", "title"}},
		{keywords.DialectPostgreSQL, "SELECT substring(name FROM pos FOR len) FROM t", []string{"len", "name", "pos"}},
		{keywords.DialectOracle, "SELECT a.x FROM a, b WHERE a.id = b.id(+)", []string{"id", "x"}},
		{keywords.DialectMySQL, "SELECT d + INTERVAL n DAY FROM t", []string{"d", "n"}},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := ExtractColumns(tree)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("ExtractColumns = %v, want %v", got, tt.want)
			}
		})
	}
}
