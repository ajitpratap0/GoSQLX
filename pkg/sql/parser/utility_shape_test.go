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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Truncated utility statements are errors, not verbatim "valid" statements,
// so validation does not report them as correct.
func TestParser_UtilityShapeRejectsTruncated(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectMySQL, "SET GLOBAL"},
		{keywords.DialectMySQL, "SET SESSION"},
		{keywords.DialectMySQL, "SET @x"},
		{keywords.DialectMySQL, "SET @x ="},
		{keywords.DialectMySQL, "SET NAMES"},
		{keywords.DialectMySQL, "SET @@global.sql_mode"},
		{keywords.DialectMySQL, "SHOW"},
		{keywords.DialectMySQL, "SHOW FULL"},
		{keywords.DialectMySQL, "SHOW TABLES LIKE"},
		{keywords.DialectMySQL, "SHOW VARIABLES WHERE"},
		{keywords.DialectMySQL, "GRANT SELECT ON db.* TO"},
		{keywords.DialectPostgreSQL, "SET search_path"},
		{keywords.DialectPostgreSQL, "SET search_path TO"},
		{keywords.DialectPostgreSQL, "SHOW"},
		{keywords.DialectSQLServer, "SET NOCOUNT"},
		{keywords.DialectSQLServer, "SET @x ="},
		{keywords.DialectSnowflake, "SHOW TABLES IN"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			if tree, err := ParseWithDialect(tc.sql, tc.dialect); err == nil {
				t.Errorf("parse %q (%s) succeeded with %T, want an error", tc.sql, tc.dialect, tree.Statements[0])
			}
		})
	}
}

// The shape checks must not reject the complete forms next to them.
func TestParser_UtilityShapeAcceptsComplete(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectMySQL, "SET GLOBAL max_connections = 100"},
		{keywords.DialectMySQL, "SET SESSION sql_mode = ''"},
		{keywords.DialectMySQL, "SET @x = 1"},
		{keywords.DialectMySQL, "SET NAMES utf8mb4"},
		{keywords.DialectMySQL, "SET @@global.sql_mode = 'ANSI'"},
		{keywords.DialectMySQL, "SET GLOBAL = 1"},
		{keywords.DialectMySQL, "SHOW TABLES"},
		{keywords.DialectMySQL, "SHOW FULL PROCESSLIST"},
		{keywords.DialectMySQL, "SHOW GLOBAL STATUS LIKE 'Threads%'"},
		{keywords.DialectMySQL, "SHOW VARIABLES WHERE Variable_name = 'x'"},
		{keywords.DialectMySQL, "GRANT SELECT ON db.* TO 'u'@'h'"},
		{keywords.DialectMySQL, "FLUSH PRIVILEGES"},
		{keywords.DialectPostgreSQL, "SET search_path TO public"},
		{keywords.DialectPostgreSQL, "SET search_path TO DEFAULT"},
		{keywords.DialectPostgreSQL, "SET TIME ZONE 'UTC'"},
		{keywords.DialectPostgreSQL, "SET LOCAL statement_timeout = 0"},
		{keywords.DialectPostgreSQL, "SHOW ALL"},
		{keywords.DialectPostgreSQL, "SHOW search_path"},
		{keywords.DialectSQLServer, "SET NOCOUNT ON"},
		{keywords.DialectSQLServer, "SET XACT_ABORT OFF"},
		{keywords.DialectSQLServer, "SET @x = (SELECT 1)"},
		{keywords.DialectSQLServer, "SET TRANSACTION ISOLATION LEVEL SNAPSHOT"},
		{keywords.DialectSnowflake, "SET x = 1"},
		{keywords.DialectSnowflake, "SHOW TABLES IN SCHEMA s"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			if _, err := ParseWithDialect(tc.sql, tc.dialect); err != nil {
				t.Errorf("parse %q (%s): %v", tc.sql, tc.dialect, err)
			}
		})
	}
}
