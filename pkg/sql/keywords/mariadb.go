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

package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// MARIADB_SPECIFIC contains MariaDB-specific SQL keywords beyond the MySQL base.
// When DialectMariaDB is active, both MYSQL_SPECIFIC and MARIADB_SPECIFIC are loaded
// (MariaDB is a superset of MySQL).
//
// Features covered:
//   - SEQUENCE DDL (MariaDB 10.3+): CREATE/DROP/ALTER SEQUENCE, NEXTVAL, LASTVAL, SETVAL
//   - Temporal tables (MariaDB 10.3.4+): WITH SYSTEM VERSIONING, FOR SYSTEM_TIME, PERIOD FOR
//   - Hierarchical queries (MariaDB 10.2+): CONNECT BY, START WITH, PRIOR, NOCYCLE
//   - Index visibility (MariaDB 10.6+): INVISIBLE, VISIBLE modifiers
//
// Note: MAXVALUE is already in ADDITIONAL_KEYWORDS (base list, all dialects).
// Note: MINVALUE is already in ORACLE_SPECIFIC. Neither needs repeating here.
// Note: INCREMENT, RESTART, NOCACHE are already in ADDITIONAL_KEYWORDS.
var MARIADB_SPECIFIC = []Keyword{
	// ── SEQUENCE DDL (MariaDB 10.3+) ───────────────────────────────────────
	// CREATE SEQUENCE s START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 9999 CYCLE CACHE 100;
	// SELECT NEXT VALUE FOR s;  -- ANSI style
	// SELECT NEXTVAL(s);        -- MariaDB style
	// MINVALUE/MAXVALUE/INCREMENT/RESTART/NOCACHE covered by base or Oracle lists.
	{Word: "SEQUENCE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "NEXTVAL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "LASTVAL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "SETVAL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "NOCYCLE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// ── Temporal tables / System versioning (MariaDB 10.3.4+) ─────────────
	// CREATE TABLE t (...) WITH SYSTEM VERSIONING;
	// SELECT * FROM t FOR SYSTEM_TIME AS OF TIMESTAMP '2024-01-01';
	// PERIOD FOR app_time (start_col, end_col)
	{Word: "VERSIONING", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "PERIOD", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "OVERLAPS", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	// SYSTEM_TIME is reserved so it doesn't collide as a table alias
	{Word: "SYSTEM_TIME", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},

	// ── Hierarchical queries / CONNECT BY (MariaDB 10.2+) ──────────────────
	// SELECT id FROM t START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id;
	{Word: "PRIOR", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// ── Index visibility (MariaDB 10.6+) ────────────────────────────────────
	// CREATE INDEX idx ON t (col) INVISIBLE;
	// ALTER TABLE t ALTER INDEX idx VISIBLE;
	{Word: "INVISIBLE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "VISIBLE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
}
