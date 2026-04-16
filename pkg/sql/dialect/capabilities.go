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

// Package dialect provides typed SQL dialect identity and capability flags
// for GoSQLX. Use Capabilities() on a Dialect to feature-gate parser logic
// instead of string comparisons such as `p.dialect == "postgresql"`.
//
// The typed Dialect constants in this package are the long-term replacement
// for scattered `p.dialect == "..."` comparisons in the parser. Consumers
// should prefer Dialect / Capabilities over string comparison so that:
//
//   - typos are caught at compile time;
//   - adding a new dialect is a single-file change (adding a case to
//     Capabilities()) rather than a grep-audit of dozens of parser files;
//   - feature detection is intent-revealing ("supports QUALIFY") rather than
//     implementation-coupled ("is Snowflake or BigQuery").
//
// Backward compatibility:
//
//   - The parser.Parser struct keeps its string `dialect` field and its
//     string-returning Dialect() method for the v1.x series.
//   - Migration happens call-site by call-site as scheduled for v2.0.
package dialect

import "strings"

// Dialect is a typed SQL dialect identifier. The zero value is Unknown
// (empty string), which means "no dialect specified" and selects the
// permissive default capability set.
type Dialect string

// Dialect constants. String values match the keywords.SQLDialect values to
// allow round-tripping through the legacy string field on the parser.
const (
	// Unknown is the zero value; no dialect has been explicitly selected.
	// Matches the behaviour of an empty parser.dialect string field and
	// yields the permissive default capability set.
	Unknown Dialect = ""

	// PostgreSQL is the PostgreSQL dialect (https://www.postgresql.org/docs/).
	PostgreSQL Dialect = "postgresql"

	// MySQL is the MySQL / Percona dialect (https://dev.mysql.com/doc/).
	MySQL Dialect = "mysql"

	// MariaDB is the MariaDB dialect (https://mariadb.com/kb/en/).
	// Superset of MySQL 5.7 syntax plus SEQUENCE, system-versioned tables,
	// CONNECT BY, and index visibility controls.
	MariaDB Dialect = "mariadb"

	// SQLServer is Microsoft SQL Server / T-SQL
	// (https://learn.microsoft.com/sql/t-sql/).
	SQLServer Dialect = "sqlserver"

	// Oracle is Oracle Database / PL-SQL
	// (https://docs.oracle.com/en/database/oracle/oracle-database/).
	Oracle Dialect = "oracle"

	// SQLite is SQLite (https://www.sqlite.org/lang.html).
	SQLite Dialect = "sqlite"

	// Snowflake is Snowflake (https://docs.snowflake.com/).
	Snowflake Dialect = "snowflake"

	// ClickHouse is ClickHouse (https://clickhouse.com/docs/).
	ClickHouse Dialect = "clickhouse"

	// BigQuery is Google BigQuery
	// (https://cloud.google.com/bigquery/docs/reference/standard-sql/).
	BigQuery Dialect = "bigquery"

	// Redshift is Amazon Redshift
	// (https://docs.aws.amazon.com/redshift/latest/dg/).
	Redshift Dialect = "redshift"

	// Generic represents standard/ANSI SQL with no dialect-specific
	// features. It is distinct from Unknown: Generic explicitly means
	// "parse standard SQL only"; Unknown means "no choice has been made".
	Generic Dialect = "generic"
)

// Parse normalises a free-form dialect string to a typed Dialect. The match
// is case-insensitive and tolerates a short list of well-known aliases
// ("postgres" -> PostgreSQL, "mssql" -> SQLServer). Unknown strings map to
// Unknown.
//
// Empty input returns Unknown.
func Parse(s string) Dialect {
	if s == "" {
		return Unknown
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "postgresql", "postgres", "pg":
		return PostgreSQL
	case "mysql":
		return MySQL
	case "mariadb":
		return MariaDB
	case "sqlserver", "mssql", "tsql", "sql_server", "sql-server":
		return SQLServer
	case "oracle", "plsql", "pl/sql":
		return Oracle
	case "sqlite", "sqlite3":
		return SQLite
	case "snowflake":
		return Snowflake
	case "clickhouse", "ch":
		return ClickHouse
	case "bigquery", "bq":
		return BigQuery
	case "redshift":
		return Redshift
	case "generic", "ansi", "standard":
		return Generic
	default:
		return Unknown
	}
}

// String satisfies fmt.Stringer. Returns the canonical lowercase dialect
// identifier, or the empty string for Unknown.
func (d Dialect) String() string { return string(d) }

// IsValid reports whether d is a recognised dialect (not Unknown).
func (d Dialect) IsValid() bool {
	switch d {
	case PostgreSQL, MySQL, MariaDB, SQLServer, Oracle, SQLite,
		Snowflake, ClickHouse, BigQuery, Redshift, Generic:
		return true
	default:
		return false
	}
}

// Capabilities describes which optional SQL features a dialect supports.
// This is the long-term replacement for scattered `p.dialect == "..."`
// string comparisons in the parser.
//
// Fields are intentionally kept to genuine feature-gated capabilities:
// each flag should correspond to at least one existing parser branch that
// would otherwise require string comparison. If a feature is supported by
// every dialect (e.g. SELECT, basic WHERE), it does not belong here.
type Capabilities struct {
	// --- Query clauses ---

	// SupportsQualify indicates QUALIFY clause support
	// (Snowflake, BigQuery, Databricks, DuckDB).
	SupportsQualify bool

	// SupportsArrayJoin indicates ARRAY JOIN clause support (ClickHouse).
	SupportsArrayJoin bool

	// SupportsPrewhere indicates PREWHERE clause support (ClickHouse).
	SupportsPrewhere bool

	// SupportsSample indicates SAMPLE / TABLESAMPLE clause support
	// (ClickHouse SAMPLE, standard TABLESAMPLE in PostgreSQL, SQL Server,
	// Snowflake).
	SupportsSample bool

	// SupportsTimeTravel indicates AT/BEFORE time-travel clauses
	// (Snowflake AT/BEFORE, Oracle FLASHBACK).
	SupportsTimeTravel bool

	// SupportsMatchRecognize indicates MATCH_RECOGNIZE row-pattern
	// recognition (Oracle 12c+, Snowflake, Trino).
	SupportsMatchRecognize bool

	// SupportsPivotUnpivot indicates PIVOT / UNPIVOT support
	// (Oracle 11g+, SQL Server, Snowflake, Databricks).
	SupportsPivotUnpivot bool

	// SupportsWindowIgnoreNulls indicates IGNORE NULLS / RESPECT NULLS in
	// window functions (Oracle, Snowflake, SQL Server, Redshift, BigQuery).
	SupportsWindowIgnoreNulls bool

	// SupportsConnectBy indicates CONNECT BY / START WITH hierarchical
	// queries (Oracle, Snowflake, MariaDB 10.2+).
	SupportsConnectBy bool

	// --- Row limiting ---

	// SupportsTop indicates TOP N row limiting
	// (SQL Server, Snowflake, Sybase).
	SupportsTop bool

	// SupportsLimitOffset indicates LIMIT / OFFSET row limiting
	// (PostgreSQL, MySQL, MariaDB, SQLite, ClickHouse, Snowflake,
	// BigQuery, Redshift).
	SupportsLimitOffset bool

	// SupportsFetchFirst indicates standard SQL FETCH FIRST / OFFSET
	// (Oracle 12c+, SQL Server 2012+, PostgreSQL, DB2).
	SupportsFetchFirst bool

	// --- DML features ---

	// SupportsMerge indicates MERGE statement support
	// (SQL Server, Oracle, Snowflake, PostgreSQL 15+, BigQuery,
	// ClickHouse 23.3+, MariaDB; NOT SQLite or classic MySQL).
	SupportsMerge bool

	// SupportsReturning indicates RETURNING clause on DML
	// (PostgreSQL, Oracle, SQLite 3.35+, MariaDB, BigQuery).
	SupportsReturning bool

	// SupportsCompoundReturning indicates the SQL Server OUTPUT clause,
	// which is similar to RETURNING but has different syntax and can emit
	// into a result set or a table.
	SupportsCompoundReturning bool

	// SupportsDistinctOn indicates SELECT DISTINCT ON (...) syntax
	// (PostgreSQL-only, not standard SQL).
	SupportsDistinctOn bool

	// SupportsMaterializedView indicates MATERIALIZED VIEW DDL
	// (PostgreSQL, Oracle, Snowflake, ClickHouse, Redshift, BigQuery,
	// Databricks).
	SupportsMaterializedView bool

	// SupportsIndexHints indicates MySQL-style USE INDEX / FORCE INDEX /
	// IGNORE INDEX table hints (MySQL, MariaDB).
	SupportsIndexHints bool

	// --- Identifier quoting ---

	// SupportsBracketQuoting indicates [column] identifier quoting
	// (SQL Server, MS Access).
	SupportsBracketQuoting bool

	// SupportsBacktickQuoting indicates `column` identifier quoting
	// (MySQL, MariaDB, ClickHouse, BigQuery, Snowflake for some contexts).
	SupportsBacktickQuoting bool

	// SupportsDoubleQuoteIdentifier indicates "column" as identifier
	// (standard SQL; supported by PostgreSQL, Oracle, SQLite, DB2,
	// Snowflake, Redshift, and SQL Server with QUOTED_IDENTIFIER ON).
	SupportsDoubleQuoteIdentifier bool

	// --- String and pattern matching ---

	// SupportsILike indicates case-insensitive LIKE via the ILIKE operator
	// (PostgreSQL, Snowflake, DuckDB, Redshift).
	SupportsILike bool
}

// Capabilities returns the capability matrix for d.
//
// For Unknown, the returned Capabilities is the "permissive default": flags
// that correspond to widely-supported standard SQL features are enabled so
// that callers who never call WithDialect keep working. Dialect-specific
// extensions (QUALIFY, ARRAY JOIN, PREWHERE, etc.) are disabled in the
// permissive default.
func (d Dialect) Capabilities() Capabilities {
	switch d {

	case PostgreSQL:
		return Capabilities{
			SupportsSample:                true, // TABLESAMPLE
			SupportsPivotUnpivot:          false,
			SupportsLimitOffset:           true,
			SupportsFetchFirst:            true, // SQL:2008 fetch
			SupportsMerge:                 true, // PG 15+
			SupportsReturning:             true,
			SupportsDistinctOn:            true, // PG-only
			SupportsMaterializedView:      true,
			SupportsDoubleQuoteIdentifier: true,
			SupportsILike:                 true,
		}

	case MySQL:
		return Capabilities{
			SupportsLimitOffset:           true,
			SupportsMerge:                 false, // classic MySQL has no MERGE
			SupportsIndexHints:            true,
			SupportsBacktickQuoting:       true,
			SupportsDoubleQuoteIdentifier: true, // when ANSI_QUOTES is set
		}

	case MariaDB:
		return Capabilities{
			SupportsLimitOffset:           true,
			SupportsMerge:                 true, // MariaDB supports MERGE-like INSERT .. ON DUPLICATE
			SupportsReturning:             true, // MariaDB 10.5+
			SupportsIndexHints:            true,
			SupportsConnectBy:             true, // MariaDB 10.2+
			SupportsBacktickQuoting:       true,
			SupportsDoubleQuoteIdentifier: true,
		}

	case SQLServer:
		return Capabilities{
			SupportsSample:                true, // TABLESAMPLE
			SupportsPivotUnpivot:          true,
			SupportsTop:                   true,
			SupportsFetchFirst:            true, // 2012+
			SupportsMerge:                 true,
			SupportsCompoundReturning:     true, // OUTPUT clause
			SupportsBracketQuoting:        true,
			SupportsDoubleQuoteIdentifier: true, // with QUOTED_IDENTIFIER ON
		}

	case Oracle:
		return Capabilities{
			SupportsTimeTravel:            true, // FLASHBACK AS OF
			SupportsMatchRecognize:        true, // 12c+
			SupportsPivotUnpivot:          true, // 11g+
			SupportsWindowIgnoreNulls:     true,
			SupportsConnectBy:             true,
			SupportsFetchFirst:            true, // 12c+
			SupportsMerge:                 true,
			SupportsReturning:             true,
			SupportsMaterializedView:      true,
			SupportsDoubleQuoteIdentifier: true,
		}

	case SQLite:
		return Capabilities{
			SupportsLimitOffset:           true,
			SupportsMerge:                 false, // SQLite has no MERGE
			SupportsReturning:             true,  // 3.35+
			SupportsDoubleQuoteIdentifier: true,
			// SQLite also accepts bracket and backtick quoting for MySQL/
			// SQL Server compatibility, but that is a tokenizer-level detail
			// and not currently gated in the parser.
		}

	case Snowflake:
		return Capabilities{
			SupportsQualify:               true,
			SupportsSample:                true,
			SupportsTimeTravel:            true, // AT/BEFORE
			SupportsMatchRecognize:        true,
			SupportsPivotUnpivot:          true,
			SupportsWindowIgnoreNulls:     true,
			SupportsTop:                   true,
			SupportsLimitOffset:           true,
			SupportsFetchFirst:            true,
			SupportsMerge:                 true,
			SupportsMaterializedView:      true,
			SupportsDoubleQuoteIdentifier: true,
			SupportsILike:                 true,
		}

	case ClickHouse:
		return Capabilities{
			SupportsArrayJoin:             true,
			SupportsPrewhere:              true,
			SupportsSample:                true,
			SupportsLimitOffset:           true,
			SupportsMerge:                 true, // ClickHouse 23.3+
			SupportsMaterializedView:      true,
			SupportsBacktickQuoting:       true,
			SupportsDoubleQuoteIdentifier: true,
		}

	case BigQuery:
		return Capabilities{
			SupportsQualify:               true,
			SupportsPivotUnpivot:          true,
			SupportsWindowIgnoreNulls:     true,
			SupportsLimitOffset:           true,
			SupportsMerge:                 true,
			SupportsReturning:             true,
			SupportsMaterializedView:      true,
			SupportsBacktickQuoting:       true,
			SupportsDoubleQuoteIdentifier: true,
		}

	case Redshift:
		return Capabilities{
			SupportsSample:                true,
			SupportsWindowIgnoreNulls:     true,
			SupportsLimitOffset:           true,
			SupportsMerge:                 true,
			SupportsMaterializedView:      true,
			SupportsDoubleQuoteIdentifier: true,
			SupportsILike:                 true,
		}

	case Generic:
		// Standard / ANSI SQL: fetch-first, merge, returning are all
		// in the standard; LIMIT is NOT.
		return Capabilities{
			SupportsFetchFirst:            true,
			SupportsMerge:                 true,
			SupportsReturning:             false, // RETURNING is PG/Oracle, not ANSI
			SupportsDoubleQuoteIdentifier: true,
		}

	case Unknown:
		fallthrough
	default:
		// Permissive default: enable common features that most callers
		// will expect to "just work" when no dialect is set. This matches
		// the pre-typed-dialect behaviour where the parser defaulted to
		// PostgreSQL-ish leniency.
		return Capabilities{
			SupportsLimitOffset:           true,
			SupportsFetchFirst:            true,
			SupportsMerge:                 true,
			SupportsReturning:             true,
			SupportsDoubleQuoteIdentifier: true,
			SupportsILike:                 true,
		}
	}
}
