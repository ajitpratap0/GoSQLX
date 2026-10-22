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
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseCreateTable parses sql and returns copies of the table's column
// definitions and constraints rendered as the AST writes them, plus the
// column definitions themselves (valid until the tree is released, so tests
// read what they need before returning).
type parsedTable struct {
	cols        []string
	colTypes    []string
	conTypes    [][]string // per column: constraint kinds
	constraints []string
	conKinds    []string
	stmtSQL     string
}

func parseTable(t *testing.T, d keywords.SQLDialect, sql string) (*parsedTable, error) {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, d)
	if err != nil {
		return nil, err
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 1 {
		t.Fatalf("%s: got %d statements, want 1", sql, len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
	if !ok {
		t.Fatalf("%s: got %T, want *ast.CreateTableStatement", sql, tree.Statements[0])
	}
	out := &parsedTable{stmtSQL: stmt.SQL()}
	for i := range stmt.Columns {
		col := &stmt.Columns[i]
		out.cols = append(out.cols, ast.ColumnDefSQL(col))
		out.colTypes = append(out.colTypes, col.Type)
		var kinds []string
		for _, c := range col.Constraints {
			kinds = append(kinds, c.Type)
		}
		out.conTypes = append(out.conTypes, kinds)
	}
	for i := range stmt.Constraints {
		out.constraints = append(out.constraints, ast.TableConstraintSQL(&stmt.Constraints[i]))
		out.conKinds = append(out.conKinds, stmt.Constraints[i].Type)
	}
	return out, nil
}

// TestColumnDef_TypesAndAttributes covers the column data types (multi-word,
// array, typeless) and the dialect column attributes. Each case parses one
// column, checks the type string and constraint kinds the parser stored, and
// that the AST writes the column back unchanged (want) and that the written
// text parses again to the same text.
func TestColumnDef_TypesAndAttributes(t *testing.T) {
	cases := []struct {
		name     string
		dialect  keywords.SQLDialect
		col      string
		wantType string
		wantKind []string
		want     string // rendered column; defaults to col
	}{
		// --- multi-word and array types
		{"pg double precision", keywords.DialectPostgreSQL, "d DOUBLE PRECISION", "DOUBLE PRECISION", nil, ""},
		{"pg timestamp with time zone", keywords.DialectPostgreSQL, "a timestamp with time zone", "timestamp with time zone", nil, ""},
		{"pg timestamp args without time zone", keywords.DialectPostgreSQL, "a timestamp(3) without time zone NOT NULL", "timestamp(3) without time zone", []string{"NOT NULL"}, ""},
		{"pg time with time zone", keywords.DialectPostgreSQL, "a time with time zone", "time with time zone", nil, ""},
		{"oracle timestamp with local time zone", keywords.DialectOracle, "a TIMESTAMP(6) WITH LOCAL TIME ZONE", "TIMESTAMP(6) WITH LOCAL TIME ZONE", nil, ""},
		{"pg character varying", keywords.DialectPostgreSQL, "a character varying(10)", "character varying(10)", nil, ""},
		{"pg national character varying", keywords.DialectPostgreSQL, "a national character varying(5)", "national character varying(5)", nil, ""},
		{"pg bit varying", keywords.DialectPostgreSQL, "a bit varying(4)", "bit varying(4)", nil, ""},
		{"pg interval day to second", keywords.DialectPostgreSQL, "a interval day to second", "interval day to second", nil, ""},
		{"oracle interval year to month", keywords.DialectOracle, "a INTERVAL YEAR(2) TO MONTH", "INTERVAL YEAR(2) TO MONTH", nil, ""},
		{"pg qualified type", keywords.DialectPostgreSQL, "a public.citext", "public.citext", nil, ""},
		{"pg array", keywords.DialectPostgreSQL, "tags text[]", "text[]", nil, ""},
		{"pg array of arrays", keywords.DialectPostgreSQL, "m int[][]", "int[][]", nil, ""},
		{"pg sized array", keywords.DialectPostgreSQL, "n varchar(10)[3]", "varchar(10)[3]", nil, ""},
		{"pg ARRAY keyword", keywords.DialectPostgreSQL, "o int ARRAY", "int ARRAY", nil, ""},
		{"pg ARRAY keyword sized", keywords.DialectPostgreSQL, "o int ARRAY[4]", "int ARRAY[4]", nil, ""},
		{"mysql unsigned", keywords.DialectMySQL, "id INT UNSIGNED", "INT UNSIGNED", nil, ""},
		{"mysql unsigned zerofill", keywords.DialectMySQL, "id INT(11) UNSIGNED ZEROFILL NOT NULL", "INT(11) UNSIGNED ZEROFILL", []string{"NOT NULL"}, ""},
		{"mysql double unsigned", keywords.DialectMySQL, "u DOUBLE UNSIGNED", "DOUBLE UNSIGNED", nil, ""},
		{"mariadb decimal unsigned", keywords.DialectMariaDB, "p DECIMAL(10, 2) UNSIGNED", "DECIMAL(10, 2) UNSIGNED", nil, ""},
		{"sqlite smallint unsigned", keywords.DialectSQLite, "a smallint unsigned NOT NULL", "smallint unsigned", []string{"NOT NULL"}, ""},
		{"sqlite unsigned big int", keywords.DialectSQLite, "b UNSIGNED BIG INT", "UNSIGNED BIG INT", nil, ""},
		{"sqlite varying character", keywords.DialectSQLite, "c VARYING CHARACTER(255)", "VARYING CHARACTER(255)", nil, ""},
		{"sqlite native character", keywords.DialectSQLite, "d NATIVE CHARACTER(70)", "NATIVE CHARACTER(70)", nil, ""},
		// --- typeless columns
		{"sqlite bare name", keywords.DialectSQLite, "a", "", nil, ""},
		{"sqlite typeless constraints", keywords.DialectSQLite, "b NOT NULL", "", []string{"NOT NULL"}, ""},
		{"sqlite typeless primary key", keywords.DialectSQLite, "c PRIMARY KEY", "", []string{"PRIMARY KEY"}, ""},
		{"sqlite typeless default", keywords.DialectSQLite, "d DEFAULT 1", "", []string{"DEFAULT"}, ""},
		{"sqlite typeless collate", keywords.DialectSQLite, "e COLLATE NOCASE", "", []string{"COLLATE"}, ""},
		{"sqlite typeless generated", keywords.DialectSQLite, "f AS (a + 1)", "", []string{"AS"}, ""},
		{"sqlite column named key", keywords.DialectSQLite, "key TEXT PRIMARY KEY", "TEXT", []string{"PRIMARY KEY"}, ""},
		{"clickhouse typeless default", keywords.DialectClickHouse, "x DEFAULT 1", "", []string{"DEFAULT"}, ""},
		{"clickhouse typeless materialized", keywords.DialectClickHouse, "y MATERIALIZED a", "", []string{"MATERIALIZED"}, ""},
		{"sqlserver computed column", keywords.DialectSQLServer, "total AS (a + b) PERSISTED", "", []string{"AS"}, ""},
		{"sqlserver computed column without parens", keywords.DialectSQLServer, "c AS a * 2", "", []string{"AS"}, "c AS (a * 2)"},
		// --- MySQL / MariaDB attributes
		{"mysql comment", keywords.DialectMySQL, "id INT COMMENT 'the id'", "INT", []string{"COMMENT"}, ""},
		{"mysql comment with quote", keywords.DialectMySQL, "id INT COMMENT 'it''s'", "INT", []string{"COMMENT"}, ""},
		{"mysql charset collate", keywords.DialectMySQL, "name VARCHAR(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL", "VARCHAR(10)", []string{"CHARACTER SET", "COLLATE", "NOT NULL"}, ""},
		{"mysql CHARSET spelling", keywords.DialectMySQL, "name VARCHAR(5) CHARSET latin1", "VARCHAR(5)", []string{"CHARACTER SET"}, ""},
		{"mysql on update", keywords.DialectMySQL, "ts DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP", "DATETIME", []string{"DEFAULT", "ON UPDATE"}, ""},
		{"mysql invisible", keywords.DialectMySQL, "d INT INVISIBLE", "INT", []string{"INVISIBLE"}, ""},
		{"mariadb invisible", keywords.DialectMariaDB, "d TEXT INVISIBLE", "TEXT", []string{"INVISIBLE"}, ""},
		{"mysql srid", keywords.DialectMySQL, "g POINT NOT NULL SRID 4326", "POINT", []string{"NOT NULL", "SRID"}, ""},
		{"mysql generated virtual", keywords.DialectMySQL, "c INT GENERATED ALWAYS AS (a * 2) VIRTUAL", "INT", []string{"GENERATED ALWAYS AS"}, ""},
		{"mysql generated stored shorthand", keywords.DialectMySQL, "b INT AS (a + 1) STORED", "INT", []string{"AS"}, ""},
		{"mariadb generated persistent", keywords.DialectMariaDB, "b INT AS (a + 1) PERSISTENT", "INT", []string{"AS"}, ""},
		{"mariadb row start", keywords.DialectMariaDB, "rs TIMESTAMP(6) GENERATED ALWAYS AS ROW START", "TIMESTAMP(6)", []string{"GENERATED ALWAYS AS ROW START"}, ""},
		// --- PostgreSQL / Oracle identity and generated columns
		{"pg identity always", keywords.DialectPostgreSQL, "id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY", "BIGINT", []string{"GENERATED ALWAYS AS IDENTITY", "PRIMARY KEY"}, ""},
		{"pg identity by default with options", keywords.DialectPostgreSQL, "id BIGINT GENERATED BY DEFAULT AS IDENTITY (START WITH 10 INCREMENT BY 2)", "BIGINT", []string{"GENERATED BY DEFAULT AS IDENTITY"}, ""},
		{"pg generated stored", keywords.DialectPostgreSQL, "b int GENERATED ALWAYS AS (a * 2) STORED", "int", []string{"GENERATED ALWAYS AS"}, ""},
		{"oracle identity on null", keywords.DialectOracle, "id NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY", "NUMBER", []string{"GENERATED BY DEFAULT ON NULL AS IDENTITY"}, ""},
		{"oracle virtual column", keywords.DialectOracle, "v NUMBER GENERATED ALWAYS AS (id * 2) VIRTUAL", "NUMBER", []string{"GENERATED ALWAYS AS"}, ""},
		{"oracle shorthand virtual", keywords.DialectOracle, "w NUMBER AS (id + 1)", "NUMBER", []string{"AS"}, ""},
		{"pg collate quoted", keywords.DialectPostgreSQL, `name text COLLATE "C" NOT NULL`, "text", []string{"COLLATE", "NOT NULL"}, ""},
		{"pg collate qualified", keywords.DialectPostgreSQL, `n text COLLATE pg_catalog."default"`, "text", []string{"COLLATE"}, ""},
		{"sqlite collate", keywords.DialectSQLite, "name TEXT COLLATE NOCASE", "TEXT", []string{"COLLATE"}, ""},
		{"pg named constraints", keywords.DialectPostgreSQL, "id int CONSTRAINT pk PRIMARY KEY CONSTRAINT nn NOT NULL", "int", []string{"PRIMARY KEY", "NOT NULL"}, ""},
		{"pg deferrable references", keywords.DialectPostgreSQL, "a int REFERENCES u (id) DEFERRABLE INITIALLY DEFERRED", "int", []string{"REFERENCES", "DEFERRABLE", "INITIALLY DEFERRED"}, ""},
		{"pg not deferrable", keywords.DialectPostgreSQL, "a int REFERENCES u (id) NOT DEFERRABLE INITIALLY IMMEDIATE", "int", []string{"REFERENCES", "NOT DEFERRABLE", "INITIALLY IMMEDIATE"}, ""},
		{"sqlite deferrable references", keywords.DialectSQLite, "a int REFERENCES u (id) DEFERRABLE INITIALLY DEFERRED", "int", []string{"REFERENCES", "DEFERRABLE", "INITIALLY DEFERRED"}, ""},
		// --- SQL Server / Snowflake identity
		{"sqlserver identity", keywords.DialectSQLServer, "id INT IDENTITY(1, 1) NOT NULL", "INT", []string{"IDENTITY", "NOT NULL"}, ""},
		{"sqlserver identity tight args", keywords.DialectSQLServer, "id INT IDENTITY(1,1) NOT NULL", "INT", []string{"IDENTITY", "NOT NULL"}, "id INT IDENTITY(1, 1) NOT NULL"},
		{"sqlserver bare identity", keywords.DialectSQLServer, "id INT IDENTITY NOT NULL", "INT", []string{"IDENTITY", "NOT NULL"}, ""},
		{"sqlserver not for replication", keywords.DialectSQLServer, "id INT IDENTITY(1, 1) NOT FOR REPLICATION", "INT", []string{"IDENTITY", "NOT FOR REPLICATION"}, ""},
		{"sqlserver clustered pk", keywords.DialectSQLServer, "id INT PRIMARY KEY CLUSTERED", "INT", []string{"PRIMARY KEY"}, ""},
		{"sqlserver nonclustered unique", keywords.DialectSQLServer, "n INT UNIQUE NONCLUSTERED", "INT", []string{"UNIQUE"}, ""},
		{"snowflake autoincrement start increment", keywords.DialectSnowflake, "id NUMBER AUTOINCREMENT START 1 INCREMENT 1", "NUMBER", []string{"AUTO_INCREMENT"}, ""},
		{"snowflake autoincrement args order", keywords.DialectSnowflake, "id NUMBER AUTOINCREMENT (5, 2) ORDER", "NUMBER", []string{"AUTO_INCREMENT"}, ""},
		{"snowflake identity negative", keywords.DialectSnowflake, "id NUMBER IDENTITY START 3 INCREMENT -1 NOORDER", "NUMBER", []string{"IDENTITY"}, ""},
		{"snowflake comment", keywords.DialectSnowflake, "v VARCHAR COMMENT 'x'", "VARCHAR", []string{"COMMENT"}, ""},
		// --- auto increment spelling
		{"sqlite autoincrement", keywords.DialectSQLite, "id INTEGER PRIMARY KEY AUTOINCREMENT", "INTEGER", []string{"PRIMARY KEY", "AUTO_INCREMENT"}, ""},
		{"sqlite lowercase autoincrement", keywords.DialectSQLite, "id integer not null primary key autoincrement", "integer", []string{"NOT NULL", "PRIMARY KEY", "AUTO_INCREMENT"}, "id integer NOT NULL PRIMARY KEY AUTOINCREMENT"},
		{"mysql auto_increment", keywords.DialectMySQL, "id INT NOT NULL AUTO_INCREMENT", "INT", []string{"NOT NULL", "AUTO_INCREMENT"}, ""},
		// --- ClickHouse column clauses
		{"clickhouse materialized", keywords.DialectClickHouse, "b UInt8 MATERIALIZED a + 1", "UInt8", []string{"MATERIALIZED"}, ""},
		{"clickhouse alias", keywords.DialectClickHouse, "b UInt8 ALIAS a + 1", "UInt8", []string{"ALIAS"}, ""},
		{"clickhouse ephemeral", keywords.DialectClickHouse, "f UInt8 EPHEMERAL", "UInt8", []string{"EPHEMERAL"}, ""},
		{"clickhouse ephemeral expr", keywords.DialectClickHouse, "g UInt8 EPHEMERAL 3", "UInt8", []string{"EPHEMERAL"}, ""},
		{"clickhouse default then codec", keywords.DialectClickHouse, "c UInt8 DEFAULT 1 CODEC(ZSTD)", "UInt8", []string{"DEFAULT", "CODEC"}, ""},
		{"clickhouse codec then default", keywords.DialectClickHouse, "a UInt8 CODEC(Delta, LZ4) DEFAULT 1", "UInt8 CODEC(Delta, LZ4)", []string{"DEFAULT"}, ""},
		{"clickhouse comment", keywords.DialectClickHouse, "d String COMMENT 'x'", "String", []string{"COMMENT"}, ""},
		{"clickhouse ttl", keywords.DialectClickHouse, "e DateTime TTL e + INTERVAL 1 DAY", "DateTime", []string{"TTL"}, ""},
		{"clickhouse nested type unchanged", keywords.DialectClickHouse, "m Map(String, Array(UInt32))", "Map(String, Array(UInt32))", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql := "CREATE TABLE t (" + tc.col + ")"
			got, err := parseTable(t, tc.dialect, sql)
			if err != nil {
				t.Fatalf("parse %q: %v", sql, err)
			}
			if len(got.cols) != 1 {
				t.Fatalf("got %d columns, want 1: %v", len(got.cols), got.cols)
			}
			if got.colTypes[0] != tc.wantType {
				t.Errorf("type = %q, want %q", got.colTypes[0], tc.wantType)
			}
			if !reflect.DeepEqual(got.conTypes[0], tc.wantKind) {
				t.Errorf("constraint kinds = %v, want %v", got.conTypes[0], tc.wantKind)
			}
			want := tc.want
			if want == "" {
				want = tc.col
			}
			if got.cols[0] != want {
				t.Errorf("rendered = %q, want %q", got.cols[0], want)
			}
			// The rendering parses again and renders the same.
			again, err := parseTable(t, tc.dialect, "CREATE TABLE t ("+got.cols[0]+")")
			if err != nil {
				t.Fatalf("reparse %q: %v", got.cols[0], err)
			}
			if again.cols[0] != got.cols[0] {
				t.Errorf("not idempotent: %q then %q", got.cols[0], again.cols[0])
			}
		})
	}
}

// TestColumnDef_AttributesAreDialectGated checks that dialect-specific column
// syntax is rejected where the dialect does not have it, instead of being
// accepted and written back for a dialect that cannot read it.
func TestColumnDef_AttributesAreDialectGated(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"pg has no ON UPDATE attribute", keywords.DialectPostgreSQL, "CREATE TABLE t (ts timestamp ON UPDATE now())"},
		{"pg has no IDENTITY(seed, incr)", keywords.DialectPostgreSQL, "CREATE TABLE t (id int IDENTITY(1,1))"},
		{"pg has no COMMENT attribute", keywords.DialectPostgreSQL, "CREATE TABLE t (id int COMMENT 'x')"},
		{"pg has no typeless columns", keywords.DialectPostgreSQL, "CREATE TABLE t (a, b)"},
		{"mysql has no typeless columns", keywords.DialectMySQL, "CREATE TABLE t (a, b)"},
		{"sqlserver has no CHARACTER SET attribute", keywords.DialectSQLServer, "CREATE TABLE t (c varchar(5) CHARACTER SET utf8)"},
		{"sqlite has no CLUSTERED", keywords.DialectSQLite, "CREATE TABLE t (id INT PRIMARY KEY CLUSTERED)"},
		{"mysql has no DEFERRABLE", keywords.DialectMySQL, "CREATE TABLE t (a int REFERENCES u (id) DEFERRABLE)"},
		{"pg has no MATERIALIZED column", keywords.DialectPostgreSQL, "CREATE TABLE t (a int, b int MATERIALIZED a + 1)"},
		{"mysql has no arrays", keywords.DialectMySQL, "CREATE TABLE t (a int[])"},
		{"generated needs ALWAYS before an expression", keywords.DialectPostgreSQL, "CREATE TABLE t (a int, b int GENERATED AS (a * 2) STORED)"},
		{"unterminated type arguments", keywords.DialectPostgreSQL, "CREATE TABLE t (a varchar(10)"},
		{"CONSTRAINT needs a constraint", keywords.DialectPostgreSQL, "CREATE TABLE t (a int CONSTRAINT c)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect); err == nil {
				ast.ReleaseAST(tree)
				t.Errorf("parse %q succeeded; want an error", tc.sql)
			}
		})
	}
}

// TestTableConstraints_AndIndexElements covers the table-level constraints and
// index elements of CREATE TABLE.
func TestTableConstraints_AndIndexElements(t *testing.T) {
	cases := []struct {
		name     string
		dialect  keywords.SQLDialect
		sql      string
		wantKind []string // Type of each table constraint
		want     []string // each rendered; defaults to the source constraints
	}{
		{"mysql unique key", keywords.DialectMySQL, "CREATE TABLE t (id INT, UNIQUE KEY uq (id))", []string{"UNIQUE"}, []string{"UNIQUE KEY uq (id)"}},
		{"mysql unique index", keywords.DialectMySQL, "CREATE TABLE t (id INT, UNIQUE INDEX uq (id))", []string{"UNIQUE"}, []string{"UNIQUE INDEX uq (id)"}},
		{"mysql unnamed unique key", keywords.DialectMySQL, "CREATE TABLE t (id INT, UNIQUE KEY (id))", []string{"UNIQUE"}, []string{"UNIQUE KEY (id)"}},
		{"plain unique", keywords.DialectPostgreSQL, "CREATE TABLE t (a INT, b INT, UNIQUE (a, b))", []string{"UNIQUE"}, []string{"UNIQUE (a, b)"}},
		{"mysql fulltext key", keywords.DialectMySQL, "CREATE TABLE t (a TEXT, FULLTEXT KEY ft (a))", []string{"FULLTEXT"}, []string{"FULLTEXT KEY ft (a)"}},
		{"mysql fulltext index", keywords.DialectMariaDB, "CREATE TABLE t (a TEXT, FULLTEXT INDEX ft (a))", []string{"FULLTEXT"}, []string{"FULLTEXT INDEX ft (a)"}},
		{"mysql spatial key", keywords.DialectMySQL, "CREATE TABLE t (g POINT NOT NULL, SPATIAL KEY sp (g))", []string{"SPATIAL"}, []string{"SPATIAL KEY sp (g)"}},
		{"mysql key", keywords.DialectMySQL, "CREATE TABLE t (a INT, b INT, KEY k1 (a, b))", []string{"KEY"}, []string{"KEY k1 (a, b)"}},
		{"mysql index using", keywords.DialectMySQL, "CREATE TABLE t (a INT, INDEX k USING BTREE (a))", []string{"INDEX"}, []string{"INDEX k USING BTREE (a)"}},
		{"mysql index using after parts", keywords.DialectMySQL, "CREATE TABLE t (a INT, INDEX k (a) USING HASH)", []string{"INDEX"}, []string{"INDEX k USING HASH (a)"}},
		{"mysql prefix length and order", keywords.DialectMySQL, "CREATE TABLE t (a TEXT, b INT, KEY k (a(191), b DESC))", []string{"KEY"}, []string{"KEY k (a(191), b DESC)"}},
		{"mysql unnamed key", keywords.DialectMySQL, "CREATE TABLE t (a INT, KEY (a))", []string{"KEY"}, []string{"KEY (a)"}},
		{"mysql functional key", keywords.DialectMySQL, "CREATE TABLE t (a INT, KEY k ((a + 1)))", []string{"KEY"}, []string{"KEY k ((a + 1))"}},
		{"mysql functional and plain parts", keywords.DialectMySQL, "CREATE TABLE t (a INT, KEY k (a, (a * 2)))", []string{"KEY"}, []string{"KEY k (a, (a * 2))"}},
		{"mysql named unique key", keywords.DialectMySQL, "CREATE TABLE t (a INT, CONSTRAINT c UNIQUE KEY k (a))", []string{"UNIQUE"}, []string{"CONSTRAINT c UNIQUE KEY k (a)"}},
		{"mysql like", keywords.DialectMySQL, "CREATE TABLE t (LIKE u)", []string{"LIKE"}, []string{"LIKE u"}},
		{"sqlserver clustered pk", keywords.DialectSQLServer, "CREATE TABLE t (id INT, CONSTRAINT pk PRIMARY KEY CLUSTERED (id))", []string{"PRIMARY KEY"}, []string{"CONSTRAINT pk PRIMARY KEY CLUSTERED (id)"}},
		{"sqlserver nonclustered pk with order", keywords.DialectSQLServer, "CREATE TABLE t (id INT, PRIMARY KEY NONCLUSTERED (id ASC))", []string{"PRIMARY KEY"}, []string{"PRIMARY KEY NONCLUSTERED (id ASC)"}},
		{"sqlserver unique nonclustered", keywords.DialectSQLServer, "CREATE TABLE t (id INT, UNIQUE NONCLUSTERED (id DESC))", []string{"UNIQUE"}, []string{"UNIQUE NONCLUSTERED (id DESC)"}},
		{"pg like including all", keywords.DialectPostgreSQL, "CREATE TABLE t (LIKE u INCLUDING ALL)", []string{"LIKE"}, []string{"LIKE u INCLUDING ALL"}},
		{"pg like options", keywords.DialectPostgreSQL, "CREATE TABLE t (a int, LIKE s.u INCLUDING DEFAULTS EXCLUDING INDEXES)", []string{"LIKE"}, []string{"LIKE s.u INCLUDING DEFAULTS EXCLUDING INDEXES"}},
		{"pg deferrable unique", keywords.DialectPostgreSQL, "CREATE TABLE t (a int, UNIQUE (a) DEFERRABLE INITIALLY DEFERRED)", []string{"UNIQUE"}, []string{"UNIQUE (a) DEFERRABLE INITIALLY DEFERRED"}},
		{"pg deferrable foreign key", keywords.DialectPostgreSQL, "CREATE TABLE t (a int, FOREIGN KEY (a) REFERENCES u (id) NOT DEFERRABLE)", []string{"FOREIGN KEY"}, []string{"FOREIGN KEY (a) REFERENCES u (id) NOT DEFERRABLE"}},
		{"pg deferrable primary key and check", keywords.DialectPostgreSQL, "CREATE TABLE t (a int, PRIMARY KEY (a) DEFERRABLE, CHECK (a > 0) NOT DEFERRABLE INITIALLY IMMEDIATE)", []string{"PRIMARY KEY", "CHECK"}, []string{"PRIMARY KEY (a) DEFERRABLE", "CHECK (a > 0) NOT DEFERRABLE INITIALLY IMMEDIATE"}},
		{"clickhouse index", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, INDEX i a TYPE minmax GRANULARITY 1) ENGINE = MergeTree ORDER BY a", []string{"INDEX"}, []string{"INDEX i a TYPE minmax GRANULARITY 1"}},
		{"clickhouse index args", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, b String, INDEX i1 (a, b) TYPE set(100) GRANULARITY 4, INDEX i2 lower(b) TYPE bloom_filter(0.01)) ENGINE = MergeTree ORDER BY a", []string{"INDEX", "INDEX"}, []string{"INDEX i1 (a, b) TYPE set(100) GRANULARITY 4", "INDEX i2 lower(b) TYPE bloom_filter(0.01)"}},
		{"clickhouse check without parens", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, CONSTRAINT c CHECK a > 0) ENGINE = MergeTree ORDER BY a", []string{"CHECK"}, []string{"CONSTRAINT c CHECK (a > 0)"}},
		{"clickhouse check with parens", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, CONSTRAINT c CHECK (a > 0)) ENGINE = MergeTree ORDER BY a", []string{"CHECK"}, []string{"CONSTRAINT c CHECK (a > 0)"}},
		{"clickhouse check parens then and", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, CONSTRAINT c CHECK (a > 0) AND a < 9) ENGINE = MergeTree ORDER BY a", []string{"CHECK"}, []string{"CONSTRAINT c CHECK ((a > 0) AND a < 9)"}},
		{"clickhouse assume", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, CONSTRAINT c2 ASSUME a < 10) ENGINE = MergeTree ORDER BY a", []string{"ASSUME"}, []string{"CONSTRAINT c2 ASSUME a < 10"}},
		{"clickhouse projection", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, b UInt8, PROJECTION p1 (SELECT a, sum(b) GROUP BY a)) ENGINE = MergeTree ORDER BY a", []string{"PROJECTION"}, []string{"PROJECTION p1 (SELECT a, sum(b) GROUP BY a)"}},
		{"clickhouse columns named index and key", keywords.DialectClickHouse, "CREATE TABLE t (index UInt8, key String) ENGINE = MergeTree ORDER BY index", nil, nil},
		{"sqlite column named key", keywords.DialectSQLite, "CREATE TABLE t (key TEXT, index_no INTEGER)", nil, nil},
		{"mysql column named key with a type", keywords.DialectMySQL, "CREATE TABLE t (key INT, b INT)", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTable(t, tc.dialect, tc.sql)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			if !reflect.DeepEqual(got.conKinds, tc.wantKind) {
				t.Errorf("constraint kinds = %v, want %v", got.conKinds, tc.wantKind)
			}
			if !reflect.DeepEqual(got.constraints, tc.want) {
				t.Errorf("rendered constraints = %q, want %q", got.constraints, tc.want)
			}
			// The whole statement written back parses to the same statement.
			again, err := parseTable(t, tc.dialect, got.stmtSQL)
			if err != nil {
				t.Fatalf("reparse %q: %v", got.stmtSQL, err)
			}
			if again.stmtSQL != got.stmtSQL {
				t.Errorf("not idempotent: %q then %q", got.stmtSQL, again.stmtSQL)
			}
		})
	}
}

// TestTableConstraints_Rejected covers index elements that are not accepted:
// outside their dialect, malformed, or that the renderer could not place
// without changing the table.
func TestTableConstraints_Rejected(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		wantErr string
	}{
		{"sqlserver has no FULLTEXT element", keywords.DialectSQLServer, "CREATE TABLE t (a int, FULLTEXT KEY k (a))", ""},
		{"column after LIKE would be reordered", keywords.DialectPostgreSQL, "CREATE TABLE t (LIKE u, x int)", "LIKE"},
		{"clickhouse index needs TYPE", keywords.DialectClickHouse, "CREATE TABLE t (a UInt8, INDEX i a GRANULARITY 1) ENGINE = MergeTree ORDER BY a", ""},
		{"functional key part with a prefix length", keywords.DialectMySQL, "CREATE TABLE t (a INT, KEY k (a(5), (a + 1)))", ""},
		{"empty key part list", keywords.DialectMySQL, "CREATE TABLE t (a INT, KEY k ())", ""},
		{"LIKE needs a table", keywords.DialectPostgreSQL, "CREATE TABLE t (LIKE )", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("parse %q succeeded; want an error", tc.sql)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestColumnConstraint_SpellingIsKept checks that AUTOINCREMENT (SQLite,
// Snowflake) and AUTO_INCREMENT (MySQL) are written as the source spelled
// them: SQLite rejects AUTO_INCREMENT.
func TestColumnConstraint_SpellingIsKept(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
		notWant string
	}{
		{keywords.DialectSQLite, "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT)", "AUTOINCREMENT", "AUTO_INCREMENT"},
		{keywords.DialectMySQL, "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)", "AUTO_INCREMENT", "AUTOINCREMENT"},
		{keywords.DialectSnowflake, "CREATE TABLE t (id NUMBER AUTOINCREMENT)", "AUTOINCREMENT", "AUTO_INCREMENT"},
	}
	for _, tc := range cases {
		t.Run(string(tc.dialect), func(t *testing.T) {
			got, err := parseTable(t, tc.dialect, tc.sql)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			if !strings.Contains(got.stmtSQL, tc.want) || strings.Contains(got.stmtSQL, tc.notWant) {
				t.Errorf("SQL() = %q; want %s, not %s", got.stmtSQL, tc.want, tc.notWant)
			}
		})
	}
}

// TestColumnDef_ConstraintPayloads checks the typed fields the parser fills,
// which the renderers read, for a few constraint kinds.
func TestColumnDef_ConstraintPayloads(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect(
		"CREATE TABLE t (c VARCHAR(5) CHARSET latin1 COLLATE latin1_bin COMMENT 'hi' DEFAULT 'x' ON UPDATE NOW(), "+
			"g INT GENERATED ALWAYS AS (c + 1) STORED, "+
			"id INT CONSTRAINT pk PRIMARY KEY)", keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
	if !ok {
		t.Fatalf("got %T, want *ast.CreateTableStatement", tree.Statements[0])
	}
	byType := func(col int, typ string) *ast.ColumnConstraint {
		for i := range stmt.Columns[col].Constraints {
			if stmt.Columns[col].Constraints[i].Type == typ {
				return &stmt.Columns[col].Constraints[i]
			}
		}
		t.Fatalf("column %d has no %s constraint", col, typ)
		return nil
	}
	if c := byType(0, "CHARACTER SET"); c.Value != "latin1" || c.Keyword != "CHARSET" {
		t.Errorf("CHARACTER SET = {Value: %q, Keyword: %q}, want latin1 / CHARSET", c.Value, c.Keyword)
	}
	if c := byType(0, "COLLATE"); c.Value != "latin1_bin" {
		t.Errorf("COLLATE value = %q, want latin1_bin", c.Value)
	}
	if c := byType(0, "COMMENT"); c.Expr == nil || ast.ColumnConstraintSQL(c) != "COMMENT 'hi'" {
		t.Errorf("COMMENT = %v, want COMMENT 'hi'", ast.ColumnConstraintSQL(c))
	}
	if c := byType(0, "ON UPDATE"); c.Expr == nil {
		t.Errorf("ON UPDATE has no expression")
	}
	if c := byType(1, "GENERATED ALWAYS AS"); c.Keyword != "STORED" || c.Expr == nil {
		t.Errorf("generated column = {Keyword: %q, Expr: %v}, want STORED and an expression", c.Keyword, c.Expr)
	} else if _, ok := c.Expr.(*ast.ParenthesizedExpression); !ok {
		t.Errorf("generation expression is %T, want *ast.ParenthesizedExpression", c.Expr)
	}
	if c := byType(2, "PRIMARY KEY"); c.Name != "pk" {
		t.Errorf("constraint name = %q, want pk", c.Name)
	}
}

// TestColumnDef_TruncatedInputDoesNotPanic parses every prefix of statements
// that use the new column and constraint syntax: a statement cut off in the
// middle of a clause must be an error (or a shorter valid statement), never a
// panic.
func TestColumnDef_TruncatedInputDoesNotPanic(t *testing.T) {
	stmts := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "CREATE TABLE t (a timestamp(3) with time zone, b int[3] ARRAY, c int GENERATED BY DEFAULT AS IDENTITY (START WITH 1), d text COLLATE pg_catalog.\"C\" REFERENCES u (id) NOT DEFERRABLE INITIALLY IMMEDIATE, LIKE v INCLUDING ALL)"},
		{keywords.DialectMySQL, "CREATE TABLE t (a INT(5) UNSIGNED ZEROFILL AS (b + 1) STORED COMMENT 'x' CHARSET utf8 ON UPDATE NOW() SRID 4326, UNIQUE KEY k USING BTREE (a(10) DESC, (a + 1)), FULLTEXT INDEX f (a))"},
		{keywords.DialectSQLServer, "CREATE TABLE t (a INT IDENTITY(1, 1) NOT FOR REPLICATION, b AS (a * 2) PERSISTED, CONSTRAINT pk PRIMARY KEY CLUSTERED (a ASC))"},
		{keywords.DialectSQLite, "CREATE TABLE t (a, b UNSIGNED BIG INT NOT NULL, c INTEGER PRIMARY KEY AUTOINCREMENT, d AS (a) STORED)"},
		{keywords.DialectSnowflake, "CREATE TABLE t (a NUMBER AUTOINCREMENT START 1 INCREMENT -1 ORDER, b NUMBER IDENTITY (1, 1))"},
		{keywords.DialectClickHouse, "CREATE TABLE t (a UInt8 DEFAULT 1 CODEC(ZSTD) TTL a + 1, x MATERIALIZED a, INDEX i lower(a) TYPE set(10) GRANULARITY 2, PROJECTION p (SELECT a GROUP BY a), CONSTRAINT c CHECK a > 0, CONSTRAINT d ASSUME a < 5)"},
	}
	for _, st := range stmts {
		toks := strings.Fields(st.sql)
		for n := 1; n <= len(toks); n++ {
			prefix := strings.Join(toks[:n], " ")
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s: parse of %q panicked: %v", st.dialect, prefix, r)
					}
				}()
				if tree, err := gosqlx.ParseWithDialect(prefix, st.dialect); err == nil {
					ast.ReleaseAST(tree)
				}
			}()
		}
	}
}
