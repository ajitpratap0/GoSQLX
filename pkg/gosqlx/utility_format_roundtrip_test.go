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
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/dropcheck"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Utility statements, keyword aliases and delimited identifiers format to
// SQL that re-parses and re-formats to itself, without losing or changing
// any word of the input.
func TestFormatRoundTrip_UtilityAndIdentifiers(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string // formatted output
	}{
		{keywords.DialectPostgreSQL, "BEGIN", "BEGIN"},
		{keywords.DialectPostgreSQL, "SET search_path TO public, analytics", "SET search_path TO public, analytics"},
		{keywords.DialectPostgreSQL, "GRANT SELECT, INSERT ON users TO app_rw", "GRANT SELECT, INSERT ON users TO app_rw"},
		{keywords.DialectPostgreSQL, "COMMENT ON COLUMN users.email IS 'Login email'", "COMMENT ON COLUMN users.email IS 'Login email'"},
		{keywords.DialectMySQL, "START TRANSACTION", "START TRANSACTION"},
		{keywords.DialectMySQL, "USE app", "USE app"},
		{keywords.DialectMySQL, "SHOW VARIABLES LIKE 'max_%'", "SHOW VARIABLES LIKE 'max_%'"},
		{keywords.DialectMySQL, "CALL refresh_stats(2024, 'full')", "CALL refresh_stats(2024, 'full')"},
		{keywords.DialectMySQL, "DESC users", "DESC users"},
		{keywords.DialectSnowflake, "DESCRIBE STAGE my_stage", "DESCRIBE STAGE my_stage"},
		{keywords.DialectSnowflake, "USE WAREHOUSE compute_wh", "USE WAREHOUSE compute_wh"},
		{keywords.DialectSnowflake, "LIST @my_stage", "LIST @my_stage"},
		{keywords.DialectSQLServer, "DECLARE @i INT = 0", "DECLARE @i INT = 0"},
		{keywords.DialectSQLServer, "EXEC dbo.p @Id = 42", "EXEC dbo.p @Id = 42"},
		{keywords.DialectSQLServer, "SET NOCOUNT ON", "SET NOCOUNT ON"},
		{keywords.DialectClickHouse, "SET max_threads = 8", "SET max_threads = 8"},
		{keywords.DialectSQLite, "PRAGMA main.synchronous = NORMAL", "PRAGMA main.synchronous = NORMAL"},
		{keywords.DialectSQLite, "END TRANSACTION", "END TRANSACTION"},
		{keywords.DialectPostgreSQL, "SELECT a AS share FROM t", "SELECT a AS \"share\"\nFROM t"},
		{keywords.DialectPostgreSQL, "SELECT owner FROM t", "SELECT owner\nFROM t"},
		{keywords.DialectMySQL, "SELECT `from` FROM t", "SELECT `from`\nFROM t"},
		{keywords.DialectMySQL, "SELECT `key` FROM t", "SELECT `key`\nFROM t"},
		{keywords.DialectMySQL, "SELECT `my col` FROM t", "SELECT `my col`\nFROM t"},
		{keywords.DialectSQLServer, "SELECT [Group] FROM t", "SELECT [Group]\nFROM t"},
		{keywords.DialectSQLServer, "SELECT @@VERSION", "SELECT @@VERSION"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			f1 := FormatAST(tree)
			if f1 != tt.want {
				t.Errorf("format = %q, want %q", f1, tt.want)
			}
			tree2, err := ParseWithDialect(f1, tt.dialect)
			if err != nil {
				t.Fatalf("reparse %q: %v", f1, err)
			}
			if f2 := FormatAST(tree2); f2 != f1 {
				t.Errorf("not idempotent: %q != %q", f2, f1)
			}
			if lost := dropcheck.DroppedWords(tt.sql, f1); len(lost) > 0 {
				t.Errorf("formatter lost %v", lost)
			}
		})
	}
}
