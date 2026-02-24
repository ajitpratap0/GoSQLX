# GoSQLX SQL Feature Compatibility Matrix

**Version**: v1.8.0 | **Last Updated**: 2026-02-24

## Overview

This matrix documents the comprehensive SQL feature support in GoSQLX across different SQL dialects and standards. The testing was conducted using the comprehensive integration test suite with 700+ test cases covering real-world SQL patterns.

### Recent Additions (v1.8.0)
- ✅ **Dialect Mode Engine**: First-class dialect support with `ParseWithDialect()` — thread dialect through tokenizer and parser
- ✅ **MySQL Syntax Support**:
  - **LIMIT offset, count** - MySQL-style `LIMIT 10, 20`
  - **ON DUPLICATE KEY UPDATE** - MySQL upsert syntax
  - **SHOW statements** - `SHOW TABLES`, `SHOW DATABASES`, `SHOW CREATE TABLE`
  - **DESCRIBE/EXPLAIN** - Table description commands
  - **REPLACE INTO** - MySQL insert-or-replace
  - **UPDATE/DELETE with LIMIT** - MySQL extension
  - **GROUP_CONCAT** - With ORDER BY and SEPARATOR clause
  - **MATCH AGAINST** - Full-text search expressions
  - **REGEXP/RLIKE** - Regular expression operators
  - **INTERVAL number unit** - MySQL-style `INTERVAL 30 DAY`
- ✅ **Query Transform API**: Programmatic SQL rewriting via `pkg/transform/`
- ✅ **Comment Preservation**: Comments survive parse-format round-trips
- ✅ **AST-to-SQL Serialization**: `SQL()` methods on all AST nodes
- ✅ **Dollar-Quoted Strings**: PostgreSQL `$$body$$` and `$tag$body$tag$`
- ✅ **Error Recovery**: Multi-error parsing with `ParseWithRecovery()`
- ✅ **~50% Faster Parsing**: Token type overhaul with O(1) integer comparison
- ✅ **Snowflake Dialect**: Keyword detection and weighted dialect scoring

### Previous Additions (v1.7.0)
- ✅ **Schema-Qualified Names**: Full support for `schema.table`, `db.schema.table` in all DML/DDL statements
- ✅ **PostgreSQL Enhancements**:
  - **Type Casting** - `::` operator for PostgreSQL-style casts (`SELECT 1::int`)
  - **UPSERT** - `INSERT ... ON CONFLICT DO UPDATE/NOTHING`
  - **Positional Parameters** - `$1`, `$2` style parameter placeholders
  - **JSONB Operators** - Additional `@?` and `@@` operators
  - **Regex Operators** - `~`, `~*`, `!~`, `!~*` for pattern matching
- ✅ **ARRAY Constructors**: `ARRAY[1, 2, 3]` expressions with subscript/slice operations
- ✅ **WITHIN GROUP** - Ordered-set aggregate functions
- ✅ **INTERVAL Expressions** - `INTERVAL '1 day'` temporal literals
- ✅ **FOR UPDATE/SHARE** - Row-level locking clauses
- ✅ **Multi-row INSERT** - `INSERT INTO t VALUES (1), (2), (3)` batch inserts

### Previous Additions (v1.6.0)
- ✅ **PostgreSQL Extensions**:
  - **LATERAL JOIN** - Correlated subqueries in FROM clause
  - **JSON/JSONB Operators** - Complete operator set (`->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`, `#-`)
  - **DISTINCT ON** - PostgreSQL-specific row selection
  - **FILTER Clause** - Conditional aggregation (SQL:2003)
  - **Aggregate ORDER BY** - Ordering within aggregate functions
  - **RETURNING Clause** - Return modified rows from INSERT/UPDATE/DELETE
- ✅ **SQL Standards**:
  - **FETCH FIRST n ROWS** - Standard row limiting (SQL-99 F861)
  - **FETCH WITH TIES** - Include tied rows (SQL-99 F862)
  - **OFFSET-FETCH** - Standard pagination
  - **TRUNCATE TABLE** - SQL:2008 table truncation
  - **Materialized CTE Hints** - CTE optimization

### Previous Additions (v1.4+)
- ✅ **MERGE Statements** (SQL:2003 F312)
- ✅ **GROUPING SETS, ROLLUP, CUBE** (SQL-99 T431)
- ✅ **Materialized Views** (CREATE, DROP, REFRESH)
- ✅ **Table Partitioning** (RANGE, LIST, HASH)
- ✅ **NULLS FIRST/LAST** (SQL-99 F851)
- ✅ **Advanced Operators** (BETWEEN, IN, LIKE, IS NULL)
- ✅ **Comprehensive Subqueries** (Scalar, Table, Correlated, EXISTS)
- ✅ **Window Functions** - Complete SQL-99 support (ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, etc.)
- ✅ **SQL Injection Detection** (`pkg/sql/security` package)

## Legend

- ✅ **Full Support**: Complete parsing and AST generation with validation
- ⚠️ **Partial Support**: Basic syntax recognition, limited semantic validation
- ❌ **Not Supported**: Feature not recognized or causes parsing errors
- 🔧 **Syntax Only**: Recognizes syntax but no semantic validation

## Core SQL Features Support Matrix

### Data Manipulation Language (DML)

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **SELECT** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Basic WHERE clauses | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Complex WHERE (nested) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| ORDER BY | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| GROUP BY | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| HAVING | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| DISTINCT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| LIMIT/TOP | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| FETCH FIRST (SQL-99 F861) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| FETCH WITH TIES (SQL-99 F862) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| OFFSET-FETCH pagination | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| **INSERT** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| INSERT VALUES | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| INSERT SELECT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Multi-row INSERT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **UPDATE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| UPDATE with JOIN | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| Multi-table UPDATE | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 80% |
| **DELETE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| DELETE with JOIN | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| **TRUNCATE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| TRUNCATE with CASCADE | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 90% |
| **MERGE** (SQL:2003 F312) | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| MERGE WHEN MATCHED | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| MERGE WHEN NOT MATCHED | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| **RETURNING Clause** (PostgreSQL) | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| INSERT...RETURNING | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| UPDATE...RETURNING | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| DELETE...RETURNING | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |

### Data Definition Language (DDL)

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **CREATE TABLE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Column definitions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Primary keys | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Foreign keys | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Unique constraints | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Check constraints | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| **ALTER TABLE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| ADD COLUMN | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| DROP COLUMN | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| MODIFY COLUMN | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| **DROP TABLE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **CREATE INDEX** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Unique indexes | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Partial indexes | ✅ | ❌ | ⚠️ | ❌ | ✅ | ⚠️ Partial | 40% |
| **CREATE VIEW** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **CREATE MATERIALIZED VIEW** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| REFRESH MATERIALIZED VIEW | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 95% |
| **TABLE PARTITIONING** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| PARTITION BY RANGE | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| PARTITION BY LIST | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| PARTITION BY HASH | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |

### JOIN Operations

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **INNER JOIN** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **LEFT JOIN** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **RIGHT JOIN** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 100% |
| **FULL OUTER JOIN** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 85% |
| **CROSS JOIN** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **NATURAL JOIN** | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ Full | 95% |
| Multiple table JOINs | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| Self JOINs | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **LATERAL JOIN** (PostgreSQL) | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 95% |
| LATERAL with LEFT JOIN | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 95% |
| LATERAL with INNER JOIN | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 95% |
| LATERAL with CROSS JOIN | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 95% |
| JOIN with USING clause | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ Full | 95% |

### Subqueries

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **Scalar subqueries** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **Table subqueries** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **Correlated subqueries** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **EXISTS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **NOT EXISTS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **IN (subquery)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **ANY/SOME** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| **ALL** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |

### Aggregate Functions

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **COUNT** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **SUM** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **AVG** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **MIN/MAX** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **FILTER Clause** (SQL:2003) | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 95% |
| COUNT(*) FILTER (WHERE...) | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 95% |
| Aggregate ORDER BY (PostgreSQL) | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 95% |
| **GROUP_CONCAT** | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ Full | 95% |
| **STRING_AGG** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| **ARRAY_AGG** | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 90% |

## Advanced SQL Features

### Common Table Expressions (CTEs)

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **Basic CTE** (WITH clause) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **Multiple CTEs** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **Recursive CTE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **Nested CTEs** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| **Materialized CTE Hints** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 90% |
| WITH...AS MATERIALIZED | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 90% |
| WITH...AS NOT MATERIALIZED | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Full | 90% |

### Window Functions

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **ROW_NUMBER()** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **RANK()** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **DENSE_RANK()** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **NTILE()** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **LAG/LEAD** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **FIRST_VALUE/LAST_VALUE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **NTH_VALUE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| **PARTITION BY** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **ORDER BY in window** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **ROWS frame** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| **RANGE frame** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 90% |
| Frame UNBOUNDED PRECEDING | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| Frame UNBOUNDED FOLLOWING | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| Frame CURRENT ROW | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 95% |
| Frame N PRECEDING/FOLLOWING | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 90% |

### Set Operations

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **UNION** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **UNION ALL** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **INTERSECT** | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ Full | 90% |
| **EXCEPT/MINUS** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ Full | 90% |

### Grouping Operations (SQL-99 T431)

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **GROUPING SETS** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| **ROLLUP** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| **CUBE** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 95% |
| Combined GROUPING SETS | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |
| GROUPING() function | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ Full | 90% |

### ORDER BY Extensions (SQL-99 F851)

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **NULLS FIRST** | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 95% |
| **NULLS LAST** | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 95% |
| Multiple columns with NULLS | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ Full | 90% |

### Expression Operators

| Feature | PostgreSQL | MySQL | SQL Server | Oracle | SQLite | GoSQLX Parser | Test Coverage |
|---------|------------|-------|------------|--------|--------|---------------|---------------|
| **BETWEEN...AND** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **NOT BETWEEN** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **IN (list)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **IN (subquery)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **NOT IN** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **LIKE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **NOT LIKE** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **IS NULL** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **IS NOT NULL** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Full | 100% |
| **IS TRUE/FALSE** | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ Full | 90% |

## Dialect-Specific Features

**Note**: This section documents dialect-specific features where "Support Level" refers to the native database's support, while "GoSQLX Parser" and "Test Coverage" indicate GoSQLX implementation status. Many features listed have keyword recognition only (🔧 Syntax) without full parsing logic.

### PostgreSQL-Specific Features

| Feature | Support Level | GoSQLX Parser | Test Coverage | Notes |
|---------|---------------|---------------|---------------|-------|
| **Arrays** | ✅ Full | 🔧 Syntax | 40% | Keyword recognition only |
| **JSON/JSONB Types** | ✅ Full | ✅ Full | 95% | Full type support |
| **JSON -> Operator** | ✅ Full | ✅ Full | 95% | Extract JSON field as JSON |
| **JSON ->> Operator** | ✅ Full | ✅ Full | 95% | Extract JSON field as text |
| **JSON #> Operator** | ✅ Full | ✅ Full | 95% | Extract nested JSON path as JSON |
| **JSON #>> Operator** | ✅ Full | ✅ Full | 95% | Extract nested JSON path as text |
| **JSON @> Operator** | ✅ Full | ✅ Full | 95% | Contains (left contains right) |
| **JSON <@ Operator** | ✅ Full | ✅ Full | 95% | Contained by (left contained by right) |
| **JSON ? Operator** | ✅ Full | ✅ Full | 95% | Key exists |
| **JSON ?| Operator** | ✅ Full | ✅ Full | 95% | Any key exists |
| **JSON ?& Operator** | ✅ Full | ✅ Full | 95% | All keys exist |
| **JSON #- Operator** | ✅ Full | ✅ Full | 95% | Delete path |
| **DISTINCT ON** | ✅ Full | ✅ Full | 95% | SELECT DISTINCT ON (columns) ORDER BY... |
| **FILTER Clause** | ✅ Full | ✅ Full | 95% | Aggregate FILTER (WHERE condition) |
| **Aggregate ORDER BY** | ✅ Full | ✅ Full | 95% | string_agg(col, ',' ORDER BY col) |
| **RETURNING Clause** | ✅ Full | ✅ Full | 95% | INSERT/UPDATE/DELETE RETURNING |
| **Full-text search** | ✅ Full | 🔧 Syntax | 30% | tsvector, tsquery types |
| **LATERAL Joins** | ✅ Full | ✅ Full | 95% | Full support with LEFT/INNER/CROSS variants |
| **Custom operators** | ✅ Full | ⚠️ Partial | 30% | Basic operator recognition |
| **Dollar quoting** | ✅ Full | ✅ Full | 90% | `$$body$$` and `$tag$body$tag$` (v1.8.0) |

### MySQL-Specific Features (Enhanced in v1.8.0)

| Feature | Support Level | GoSQLX Parser | Test Coverage | Notes |
|---------|---------------|---------------|---------------|-------|
| **SHOW statements** | ✅ Full | ✅ Full | 95% | SHOW TABLES, DATABASES, CREATE TABLE (v1.8.0) |
| **DESCRIBE/EXPLAIN** | ✅ Full | ✅ Full | 95% | Table description commands (v1.8.0) |
| **REPLACE INTO** | ✅ Full | ✅ Full | 95% | MySQL insert-or-replace (v1.8.0) |
| **ON DUPLICATE KEY UPDATE** | ✅ Full | ✅ Full | 95% | MySQL upsert syntax (v1.8.0) |
| **LIMIT offset, count** | ✅ Full | ✅ Full | 95% | MySQL-style `LIMIT 10, 20` (v1.8.0) |
| **UPDATE/DELETE with LIMIT** | ✅ Full | ✅ Full | 90% | MySQL extension (v1.8.0) |
| **GROUP_CONCAT** | ✅ Full | ✅ Full | 95% | With ORDER BY and SEPARATOR (v1.8.0) |
| **MATCH/AGAINST** | ✅ Full | ✅ Full | 95% | Full-text search (v1.8.0) |
| **REGEXP/RLIKE** | ✅ Full | ✅ Full | 90% | Regular expression operators (v1.8.0) |
| **INTERVAL number unit** | ✅ Full | ✅ Full | 90% | MySQL-style `INTERVAL 30 DAY` (v1.8.0) |
| **IF()/REPLACE() as functions** | ✅ Full | ✅ Full | 85% | Keywords usable as function names (v1.8.0) |
| **Storage engines** | ✅ Full | 🔧 Syntax | 80% | ENGINE=InnoDB syntax |
| **Index hints** | ✅ Full | ✅ Full | 75% | USE/IGNORE/FORCE INDEX |
| **Partitioning** | ✅ Full | 🔧 Syntax | 70% | PARTITION BY syntax |
| **AUTO_INCREMENT** | ✅ Full | ✅ Full | 95% | Column property |
| **Backtick identifiers** | ✅ Full | ✅ Full | 100% | `` `table`.`column` `` syntax |

### SQL Server-Specific Features

| Feature | Support Level | GoSQLX Parser | Test Coverage | Notes |
|---------|---------------|---------------|---------------|-------|
| **MERGE** | ✅ Full | ✅ Full | 95% | MERGE statements with WHEN clauses |
| **PIVOT/UNPIVOT** | ✅ Full | 🔧 Syntax | 10% | Keywords reserved, no parsing logic |
| **CROSS/OUTER APPLY** | ✅ Full | 🔧 Syntax | 10% | Keywords reserved, no parsing logic |
| **HierarchyID** | ✅ Full | 🔧 Syntax | 20% | Data type recognition |
| **T-SQL functions** | ✅ Full | ⚠️ Partial | 40% | Subset of T-SQL functions |

### Oracle-Specific Features

| Feature | Support Level | GoSQLX Parser | Test Coverage | Notes |
|---------|---------------|---------------|---------------|-------|
| **CONNECT BY** | ✅ Full | 🔧 Syntax | 10% | Keywords reserved, no parsing logic |
| **PRIOR operator** | ✅ Full | 🔧 Syntax | 10% | Keyword reserved, no parsing logic |
| **DECODE function** | ✅ Full | ⚠️ Partial | 40% | Recognized as function, no special handling |
| **NVL/NVL2** | ✅ Full | ⚠️ Partial | 40% | Recognized as function, no special handling |
| **Dual table** | ✅ Full | ✅ Full | 100% | Standard table reference |
| **Analytic functions** | ✅ Full | ⚠️ Partial | 60% | Subset via window functions |

### SQLite-Specific Features

| Feature | Support Level | GoSQLX Parser | Test Coverage | Notes |
|---------|---------------|---------------|---------------|-------|
| **PRAGMA** | ✅ Full | 🔧 Syntax | 10% | Keywords reserved, no parsing logic |
| **ATTACH/DETACH** | ✅ Full | 🔧 Syntax | 10% | Keywords reserved, no parsing logic |
| **Type affinity** | ✅ Full | ⚠️ Partial | 30% | Flexible typing |
| **WITHOUT ROWID** | ✅ Full | ⚠️ Partial | 40% | Table option |
| **Simplified syntax** | ✅ Full | ✅ Full | 85% | SQLite variations |

## SQL Standards Compliance

### SQL-92 (Entry Level)

| Feature Category | Support Level | Test Coverage | Notes |
|------------------|---------------|---------------|-------|
| **Basic data types** | ✅ Full | 100% | CHAR, VARCHAR, INTEGER, etc. |
| **Basic predicates** | ✅ Full | 100% | =, <>, <, >, <=, >= |
| **Basic expressions** | ✅ Full | 100% | Arithmetic, string operations |
| **Subqueries** | ✅ Full | 100% | WHERE and HAVING subqueries |
| **Aggregate functions** | ✅ Full | 100% | COUNT, SUM, AVG, MIN, MAX |
| **Joins** | ✅ Full | 95% | Inner and outer joins |
| **UNION** | ✅ Full | 100% | Set operations |

### SQL-99 (Core Features)

| Feature Category | Support Level | Test Coverage | Notes |
|------------------|---------------|---------------|-------|
| **Regular expressions** | ⚠️ Partial | 60% | SIMILAR TO operator |
| **Array types** | ⚠️ Partial | 40% | Limited array support |
| **Common Table Expressions** | ✅ Full | 100% | WITH clause |
| **Window functions** | ✅ Full | 95% | OVER clause |
| **CASE expressions** | ✅ Full | 100% | Simple and searched CASE |
| **Recursive queries** | ✅ Full | 100% | Recursive CTEs |

### SQL-2003 (XML Features)

| Feature Category | Support Level | Test Coverage | Notes |
|------------------|---------------|---------------|-------|
| **Window functions** | ✅ Full | 100% | Enhanced window support |
| **MERGE statement** | ✅ Full | 80% | UPSERT operations |
| **Object identifiers** | ✅ Full | 90% | Standardized identifiers |
| **XML data type** | 🔧 Syntax | 30% | Basic syntax recognition |
| **XML functions** | ❌ Not Supported | 0% | XMLQuery, XMLTable, etc. |

### SQL-2006 (Enhancement)

| Feature Category | Support Level | Test Coverage | Notes |
|------------------|---------------|---------------|-------|
| **Enhanced window functions** | ✅ Full | 95% | Additional frame options |
| **More built-in functions** | ⚠️ Partial | 70% | Subset of new functions |
| **IMPORT/EXPORT** | ❌ Not Applicable | 0% | Not relevant for parser |

### SQL-2008 (Enhancements)

| Feature Category | Support Level | Test Coverage | Notes |
|------------------|---------------|---------------|-------|
| **INSTEAD OF triggers** | 🔧 Syntax | 50% | Syntax recognition only |
| **Enhanced MERGE** | ✅ Full | 80% | Extended MERGE capabilities |
| **TRUNCATE statement** | ✅ Full | 95% | Full TRUNCATE support with CASCADE |
| **FETCH FIRST/NEXT** | ✅ Full | 95% | Standard row limiting (F861/F862) |

### SQL-2011 (Temporal Data)

| Feature Category | Support Level | Test Coverage | Notes |
|------------------|---------------|---------------|-------|
| **Temporal tables** | 🔧 Syntax | 30% | FOR SYSTEM_TIME syntax |
| **Window function enhancements** | ⚠️ Partial | 60% | Some new functions |

### SQL-2016 (JSON Support)

| Feature Category | Support Level | Test Coverage | Notes |
|------------------|---------------|---------------|-------|
| **JSON data type** | 🔧 Syntax | 40% | Type recognition |
| **JSON functions** | ⚠️ Partial | 20% | Limited function support |
| **Row pattern recognition** | ❌ Not Supported | 0% | MATCH_RECOGNIZE clause |

## v1.6.0 PostgreSQL Extension Summary

GoSQLX v1.6.0 introduces comprehensive PostgreSQL-specific feature support, making it one of the most PostgreSQL-compatible SQL parsers available.

### Complete PostgreSQL Feature Set

| Feature Category | Features Included | Support Level | Use Cases |
|------------------|-------------------|---------------|-----------|
| **JSON/JSONB** | All 10 operators (`->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`, `#-`) | ✅ Full | Modern web apps, document stores, API backends |
| **LATERAL Joins** | LEFT LATERAL, INNER LATERAL, CROSS LATERAL | ✅ Full | Correlated subqueries, row-level computations |
| **DISTINCT ON** | SELECT DISTINCT ON with ORDER BY | ✅ Full | Deduplication, first/last row selection |
| **FILTER Clause** | Conditional aggregation on all aggregates | ✅ Full | Multi-condition analytics in single query |
| **Aggregate ORDER BY** | Ordering within aggregate functions | ✅ Full | String concatenation, array aggregation |
| **RETURNING** | INSERT/UPDATE/DELETE RETURNING | ✅ Full | Audit trails, single-trip operations |

### JSON/JSONB Operator Examples

```sql
-- Extract field as JSON (->)
SELECT data->'user' FROM events;

-- Extract field as text (->>)
SELECT data->>'email' FROM users;

-- Extract nested path as JSON (#>)
SELECT data#>'{user,address,city}' FROM profiles;

-- Extract nested path as text (#>>)
SELECT data#>>'{user,name}' FROM profiles;

-- Contains (@>)
SELECT * FROM products WHERE attributes @> '{"color": "red"}';

-- Contained by (<@)
SELECT * FROM users WHERE tags <@ '["admin", "user"]';

-- Key exists (?)
SELECT * FROM profiles WHERE data ? 'email';

-- Any key exists (?|)
SELECT * FROM users WHERE profile ?| array['phone', 'mobile'];

-- All keys exist (?&)
SELECT * FROM users WHERE profile ?& array['name', 'email'];

-- Delete path (#-)
SELECT data #- '{user,temp}' FROM cache;
```

### LATERAL JOIN Examples

```sql
-- Correlated subquery in FROM clause
SELECT u.name, recent.order_date
FROM users u,
LATERAL (
    SELECT order_date FROM orders
    WHERE user_id = u.id
    ORDER BY order_date DESC
    LIMIT 3
) recent;

-- LEFT LATERAL JOIN
SELECT u.name, stats.total
FROM users u
LEFT JOIN LATERAL (
    SELECT SUM(amount) as total
    FROM transactions
    WHERE user_id = u.id
) stats ON true;
```

### DISTINCT ON Examples

```sql
-- Get first row per department
SELECT DISTINCT ON (dept_id) dept_id, name, salary
FROM employees
ORDER BY dept_id, salary DESC;

-- Latest status per user
SELECT DISTINCT ON (user_id) user_id, status, updated_at
FROM user_status_log
ORDER BY user_id, updated_at DESC;
```

### FILTER Clause Examples

```sql
-- Multi-condition aggregation
SELECT
    dept_id,
    COUNT(*) FILTER (WHERE status = 'active') AS active_count,
    COUNT(*) FILTER (WHERE status = 'inactive') AS inactive_count,
    SUM(salary) FILTER (WHERE bonus_eligible = true) AS bonus_pool
FROM employees
GROUP BY dept_id;
```

### RETURNING Clause Examples

```sql
-- INSERT with RETURNING
INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com')
RETURNING id, created_at;

-- UPDATE with RETURNING
UPDATE products
SET price = price * 1.1
WHERE category = 'Electronics'
RETURNING id, name, price;

-- DELETE with RETURNING
DELETE FROM sessions
WHERE expired_at < NOW()
RETURNING user_id, session_id;
```

## Dialect Mode Engine (v1.8.0)

GoSQLX v1.8.0 introduces a first-class dialect mode engine that threads the SQL dialect through the tokenizer and parser. This enables dialect-specific keyword recognition, syntax parsing, and validation.

### Supported Dialects

| Dialect | Dialect String | Keyword Set | Dialect-Specific Parsing | Status |
|---------|---------------|-------------|--------------------------|--------|
| **PostgreSQL** | `"postgresql"` | Full PG keywords | `::`, `ON CONFLICT`, `$$`, JSONB ops, LATERAL, DISTINCT ON | ✅ Default dialect |
| **MySQL** | `"mysql"` | MySQL keywords | SHOW, DESCRIBE, REPLACE INTO, ON DUPLICATE KEY, LIMIT n,m, GROUP_CONCAT, MATCH AGAINST, REGEXP | ✅ Full support |
| **SQL Server** | `"sqlserver"` | T-SQL keywords | MERGE, bracket identifiers `[col]` | ⚠️ Keywords + basic parsing |
| **Oracle** | `"oracle"` | Oracle keywords | DUAL table, basic PL/SQL keywords | ⚠️ Keywords + basic parsing |
| **SQLite** | `"sqlite"` | SQLite keywords | Flexible typing, simplified syntax | ⚠️ Keywords + basic parsing |
| **Snowflake** | `"snowflake"` | Snowflake keywords | Stage operations, VARIANT type | ⚠️ Keyword detection only |

### Usage

```go
// API
ast, err := parser.ParseWithDialect("SHOW TABLES", "mysql")
err = parser.ValidateWithDialect("DESCRIBE users", "mysql")

// CLI
gosqlx validate --dialect mysql "SHOW TABLES"
gosqlx format --dialect mysql query.sql
```

### Known Gaps by Dialect

#### PostgreSQL (default, best supported)
- PL/pgSQL procedural blocks not parsed
- Some advanced array operations limited
- Full-text search `tsvector`/`tsquery` syntax-only recognition

#### MySQL
- Stored procedures / functions not parsed
- HANDLER statements not supported
- XA transactions not supported
- CREATE EVENT not supported

#### SQL Server (T-SQL)
- PIVOT/UNPIVOT keywords reserved but no parsing logic
- CROSS/OUTER APPLY keywords reserved but no parsing logic
- TRY/CATCH blocks not supported
- OPENROWSET / OPENQUERY not supported

#### Oracle
- CONNECT BY / START WITH / PRIOR not parsed (keywords reserved)
- PL/SQL blocks not supported
- DECODE recognized as generic function only
- Pipelined table functions not supported

#### SQLite
- PRAGMA statements not parsed (keyword reserved)
- ATTACH/DETACH not parsed (keywords reserved)
- VACUUM not supported
- Virtual tables (FTS5, rtree) not supported

#### Snowflake
- Keyword detection and dialect scoring only
- No Snowflake-specific parsing (stages, COPY INTO, VARIANT operations)
- QUALIFY clause not supported

## SQL Standards Compliance Summary

### Overall Compliance (v1.8.0)

| Standard | Compliance % | Status | Notes |
|----------|--------------|--------|-------|
| **SQL-92 Entry** | ~95% | ✅ Excellent | All core features supported |
| **SQL-92 Intermediate** | ~85% | ✅ Strong | Most features supported |
| **SQL-99 Core** | ~85% | ✅ Strong | Window functions, CTEs, recursive queries |
| **SQL:2003** | ~75% | ✅ Good | MERGE, FILTER, enhanced window functions |
| **SQL:2008** | ~65% | ✅ Good | TRUNCATE, FETCH FIRST/NEXT |
| **SQL:2011** | ~40% | ⚠️ Partial | Some temporal features, limited support |
| **SQL:2016** | ~50% | ⚠️ Partial | JSON support via PostgreSQL extensions |

### Feature Category Compliance

| Category | Features Supported | Total Features | Compliance % |
|----------|-------------------|----------------|--------------|
| **Basic DML** | 18/18 | 18 | 100% |
| **Advanced DML** | 12/15 | 15 | 80% |
| **DDL Operations** | 22/25 | 25 | 88% |
| **JOIN Operations** | 10/10 | 10 | 100% |
| **Subqueries** | 8/8 | 8 | 100% |
| **Aggregate Functions** | 10/13 | 13 | 77% |
| **Window Functions** | 15/16 | 16 | 94% |
| **CTEs** | 7/7 | 7 | 100% |
| **Set Operations** | 4/4 | 4 | 100% |
| **Expression Operators** | 9/9 | 9 | 100% |
| **PostgreSQL Extensions** | 20/25 | 25 | 80% |

### Dialect-Specific Compliance

| Database | Core Features | Extensions | Overall Rating | Notes |
|----------|---------------|------------|----------------|-------|
| **PostgreSQL** | 95% | 85% | ⭐⭐⭐⭐⭐ Excellent | Default dialect, best supported |
| **MySQL** | 95% | 85% | ⭐⭐⭐⭐⭐ Excellent | Full dialect parsing (v1.8.0) |
| **SQL Server** | 85% | 65% | ⭐⭐⭐⭐ Very Good | Keywords + MERGE |
| **Oracle** | 80% | 60% | ⭐⭐⭐⭐ Good | Keywords + basic features |
| **SQLite** | 85% | 50% | ⭐⭐⭐⭐ Good | Keywords + basic features |
| **Snowflake** | 80% | 30% | ⭐⭐⭐ Good | Keyword detection only |

## Performance Characteristics by Feature

### High Performance Features (>1M ops/sec)

- Basic SELECT statements
- Simple INSERT/UPDATE/DELETE
- Basic WHERE clauses
- Simple JOINs (2-3 tables)
- Standard aggregate functions
- Basic subqueries

### Good Performance Features (100K-1M ops/sec)

- Complex WHERE clauses
- Multi-table JOINs (4-6 tables)
- Window functions
- Simple CTEs
- Set operations (UNION, etc.)
- Complex subqueries

### Moderate Performance Features (10K-100K ops/sec)

- Recursive CTEs
- Very complex JOINs (7+ tables)
- Deeply nested subqueries
- Complex window functions with frames
- Large CASE expressions

### Lower Performance Features (<10K ops/sec)

- Extremely complex queries (1000+ tokens)
- Deeply nested expressions (10+ levels)
- Very large DDL statements
- Queries with 100+ columns

## Edge Case Support

### Unicode and International Support

| Feature | Support Level | Test Coverage |
|---------|---------------|---------------|
| **Unicode identifiers** | ✅ Full | 95% |
| **Unicode string literals** | ✅ Full | 100% |
| **Multi-byte characters** | ✅ Full | 90% |
| **Right-to-left text** | ✅ Full | 80% |
| **Emoji in comments** | ✅ Full | 70% |

### Extreme Query Patterns

| Feature | Support Level | Test Coverage |
|---------|---------------|---------------|
| **Very long queries (50K+ chars)** | ✅ Full | 80% |
| **Deeply nested subqueries (10+ levels)** | ✅ Full | 85% |
| **Large column lists (100+ columns)** | ✅ Full | 75% |
| **Complex WHERE clauses (50+ conditions)** | ✅ Full | 80% |
| **Large IN lists (1000+ values)** | ✅ Full | 70% |

### Error Recovery

| Scenario | Support Level | Test Coverage |
|----------|---------------|---------------|
| **Syntax errors with context** | ✅ Full | 95% |
| **Incomplete queries** | ✅ Full | 90% |
| **Invalid token sequences** | ✅ Full | 85% |
| **Unmatched parentheses** | ✅ Full | 100% |
| **Invalid string literals** | ✅ Full | 95% |

## Production Readiness Summary

### Ready for Production (v1.7.0)

**Core DML/DDL**:
- **Core SQL operations** (SELECT, INSERT, UPDATE, DELETE, TRUNCATE)
- **Standard joins and subqueries** (all types including LATERAL)
- **Window functions and CTEs** (including recursive and materialized hints)
- **MERGE statements** (SQL:2003 F312)
- **GROUPING SETS, ROLLUP, CUBE** (SQL-99 T431)
- **Materialized views**
- **Table partitioning**

**PostgreSQL Extensions** (v1.6.0-v1.7.0):
- **JSON/JSONB operators** - All 10 operators (`->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`, `#-`)
- **LATERAL JOIN** - Full support with LEFT/INNER/CROSS variants
- **DISTINCT ON** - PostgreSQL-specific row selection
- **FILTER clause** - Conditional aggregation
- **Aggregate ORDER BY** - Ordering within aggregate functions
- **RETURNING clause** - INSERT/UPDATE/DELETE RETURNING

**Standards & Performance**:
- **FETCH FIRST/NEXT** - SQL-99 F861/F862 standard pagination
- **OFFSET-FETCH** - Standard row limiting
- **Multi-dialect basic syntax**
- **Unicode and international text**
- **High-performance scenarios** (1.25M ops/sec peak)

### Suitable with Considerations

- **Advanced dialect-specific features** (keyword recognition only for: PIVOT/UNPIVOT, CONNECT BY, PRAGMA, ATTACH/DETACH)
- **Complex XML operations** (syntax recognition only)
- **Dialect-specific functions** (DECODE, NVL, recognized as generic functions)
- **Newest SQL standard features (SQL-2011+)**
- **Very large query processing**

### Development Needed

- **PIVOT/UNPIVOT parsing logic** (keywords reserved)
- **CONNECT BY hierarchical queries** (keywords reserved)
- **Full XML function support**
- **Row pattern recognition (MATCH_RECOGNIZE)**
- **Complete temporal table support**
- **SQLite PRAGMA statements** (keywords reserved)
- **Advanced array operations**

## Recommendations

### For Web Applications
- ✅ **Excellent support** for typical web app queries
- ✅ **High performance** for user authentication, content management
- ✅ **Multi-dialect compatibility** for different backends
- ✅ **PostgreSQL JSON/JSONB support** for modern document storage
- ✅ **RETURNING clause** for efficient single-trip operations

### For Analytics Platforms
- ✅ **Strong support** for complex analytical queries
- ✅ **Full CTE and window function support**
- ✅ **GROUPING SETS, ROLLUP, CUBE** for OLAP operations
- ✅ **FILTER clause** for conditional aggregation
- ⚠️ **Consider dialect-specific features** for advanced analytics

### For PostgreSQL Applications
- ✅ **Industry-leading PostgreSQL support** with 95% core feature coverage
- ✅ **Complete JSON/JSONB operator support** (10 operators)
- ✅ **LATERAL JOIN** for advanced correlated subqueries
- ✅ **DISTINCT ON** for PostgreSQL-specific deduplication
- ✅ **Aggregate ORDER BY** for string aggregation
- ✅ **Best-in-class PostgreSQL compatibility**

### For Database Tools
- ✅ **Comprehensive DDL support**
- ✅ **Excellent error handling and recovery**
- ✅ **Multi-dialect parsing capabilities**
- ✅ **SQL injection detection** built-in

### For Migration Tools
- ✅ **Strong cross-dialect compatibility**
- ✅ **Robust error handling**
- ✅ **PostgreSQL extension awareness**
- ⚠️ **Manual handling needed** for dialect-specific features (PIVOT, CONNECT BY)

---

**Last Updated**: 2026-02-24
**GoSQLX Version**: 1.8.0
**Test Suite Version**: 1.8.0
**Total Test Cases**: 800+
**Coverage Percentage**: 95%+
**SQL-99 Compliance**: ~85%
**PostgreSQL Compliance**: ~95% (core features), ~85% (extensions)
**MySQL Compliance**: ~95% (core features), ~85% (extensions)

## Quick Reference: What's New in v1.8.0

### Dialect Engine
1. **ParseWithDialect()** - Parse SQL with dialect-specific syntax
2. **ValidateWithDialect()** - Validate with dialect awareness
3. **--dialect CLI flag** - Specify dialect for CLI commands
4. **6 Supported Dialects** - PostgreSQL, MySQL, SQL Server, Oracle, SQLite, Snowflake

### MySQL Syntax (11 Features)
1. **SHOW statements** - SHOW TABLES, DATABASES, CREATE TABLE
2. **DESCRIBE/EXPLAIN** - Table description
3. **REPLACE INTO** - Insert-or-replace
4. **ON DUPLICATE KEY UPDATE** - MySQL upsert
5. **LIMIT offset, count** - MySQL-style pagination
6. **UPDATE/DELETE with LIMIT** - Row limiting extension
7. **GROUP_CONCAT** - With ORDER BY and SEPARATOR
8. **MATCH AGAINST** - Full-text search
9. **REGEXP/RLIKE** - Regular expression operators
10. **INTERVAL number unit** - MySQL-style intervals
11. **IF()/REPLACE() as functions** - Keywords as function names

### New Capabilities
1. **Query Transform API** - `pkg/transform/` for programmatic SQL rewriting
2. **Comment Preservation** - Comments survive parse-format round-trips
3. **AST-to-SQL** - `SQL()` methods on all nodes for roundtrip serialization
4. **WASM Playground** - Browser-based SQL parsing and formatting
5. **Error Recovery** - `ParseWithRecovery()` for multi-error diagnostics
6. **Dollar-Quoted Strings** - PostgreSQL `$$body$$` support
7. **~50% Faster Parsing** - O(1) integer token comparison

### Migration Notes
- **From v1.7.0**: High-level API (`gosqlx.Parse()`, `gosqlx.Validate()`) is fully backward compatible
- **Breaking**: `token.Token.ModelType` renamed to `Type`; string-based `token.Type` removed. See [MIGRATION.md](MIGRATION.md)
- **MySQL Users**: Use `parser.ParseWithDialect(sql, "mysql")` for MySQL-specific syntax
- **Performance**: ~50% faster parsing from token type overhaul