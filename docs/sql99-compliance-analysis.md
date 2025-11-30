# SQL-99 Compliance Gap Analysis for GoSQLX

**Issue**: #67 (FEAT-001: SQL-99 Compliance to 95%)
**Current Compliance**: ~80-85% (estimated)
**Target Compliance**: 95%
**Analysis Date**: 2025-11-17
**Version**: v1.5.1

## Executive Summary

This document provides a comprehensive analysis of SQL-99 standard compliance gaps in GoSQLX. Based on detailed codebase analysis, the parser currently implements approximately 80-85% of SQL-99 core features, with strong support for DML operations, JOINs, CTEs, window functions, and set operations. To reach the target of 95% compliance, we need to implement 10-12 key missing features, which are prioritized below by importance and implementation effort.

**Key Findings:**
- **Strong Foundation**: Robust implementation of core SQL-99 features (SELECT, JOINs, subqueries, CTEs, window functions)
- **Missing Features**: 15 SQL-99 features identified, prioritized by importance and implementation complexity
- **Estimated Effort**: ~120-160 developer hours to reach 95% compliance
- **Recommended Approach**: 3-phase implementation over 3-4 months

---

## Table of Contents

1. [Currently Implemented SQL-99 Features](#currently-implemented-sql-99-features)
2. [Missing SQL-99 Features (Gap Analysis)](#missing-sql-99-features-gap-analysis)
3. [Priority Ranking and Implementation Roadmap](#priority-ranking-and-implementation-roadmap)
4. [Detailed Feature Analysis](#detailed-feature-analysis)
5. [Effort Estimates](#effort-estimates)
6. [Implementation Recommendations](#implementation-recommendations)
7. [Risk Assessment](#risk-assessment)

---

## Currently Implemented SQL-99 Features

### Core Data Manipulation (100% Coverage)

**SELECT Statement** - Fully implemented with comprehensive support:
- Basic SELECT with column projection
- WHERE clause with complex predicates (AND, OR, NOT, comparison operators)
- GROUP BY with multiple grouping columns
- HAVING clause for aggregate filtering
- ORDER BY with ASC/DESC modifiers
- DISTINCT for duplicate elimination
- LIMIT/OFFSET for pagination (dialect-specific)
- Subqueries (scalar, row, table subqueries)
- Correlated subqueries

**INSERT Statement** - Complete implementation:
- INSERT INTO with VALUES clause
- Multi-row INSERT
- INSERT SELECT (insert from query results)
- Column list specification

**UPDATE Statement** - Full support:
- Basic UPDATE with SET clause
- WHERE clause for conditional updates
- Multiple column updates

**DELETE Statement** - Complete:
- DELETE FROM with WHERE clause
- Conditional deletion

### JOIN Operations (100% Coverage)

Full support for all SQL-99 JOIN types:
- **INNER JOIN** - Fully implemented with ON and USING clauses
- **LEFT OUTER JOIN** - Complete support
- **RIGHT OUTER JOIN** - Complete support
- **FULL OUTER JOIN** - Complete support
- **CROSS JOIN** - Fully implemented
- **NATURAL JOIN** - Complete support
- **Multiple JOINs** - Proper left-associative parsing
- **Self JOINs** - Supported

### Subqueries (100% Coverage)

Comprehensive subquery support:
- Scalar subqueries (single value)
- Row subqueries (single row, multiple columns)
- Table subqueries (multiple rows and columns)
- Correlated subqueries (references to outer query)
- EXISTS and NOT EXISTS predicates
- IN (subquery) predicates
- ANY/SOME quantified comparisons
- ALL quantified comparisons

### Common Table Expressions (100% Coverage)

**Phase 2 Complete** - Full CTE implementation:
- Basic WITH clause
- Multiple CTEs in single query
- Recursive CTEs with RECURSIVE keyword
- Column specifications in CTEs
- CTE references in main query
- Nested CTEs

### Window Functions (95% Coverage)

**Phase 2.5 Complete** - Comprehensive window function support:

**Ranking Functions:**
- ROW_NUMBER() - Sequential row numbering
- RANK() - Ranking with gaps
- DENSE_RANK() - Ranking without gaps
- NTILE(n) - Distribution into buckets

**Analytic Functions:**
- LAG(expr, offset, default) - Access previous row
- LEAD(expr, offset, default) - Access next row
- FIRST_VALUE(expr) - First value in window
- LAST_VALUE(expr) - Last value in window

**Window Specification:**
- PARTITION BY clause - Data partitioning
- ORDER BY clause - Ordering within partitions
- ROWS frame clause - Physical row-based frames
- RANGE frame clause - Logical value-based frames
- Frame bounds:
  - UNBOUNDED PRECEDING
  - n PRECEDING
  - CURRENT ROW
  - n FOLLOWING
  - UNBOUNDED FOLLOWING

**Missing Window Features** (5% gap):
- EXCLUDE clause (EXCLUDE CURRENT ROW, EXCLUDE GROUP, EXCLUDE TIES, EXCLUDE NO OTHERS)
- GROUPS frame unit (SQL:2016, but commonly backported)
- Named window specifications (WINDOW clause)

### Set Operations (100% Coverage)

**Phase 2 Complete** - Full set operation support:
- UNION - Combines results with duplicate elimination
- UNION ALL - Combines results keeping duplicates
- EXCEPT - Set difference
- INTERSECT - Set intersection
- Left-associative parsing for chained operations
- Proper precedence handling

### Aggregate Functions (95% Coverage)

Standard SQL-99 aggregates:
- COUNT(*) and COUNT(column)
- SUM(expression)
- AVG(expression)
- MIN(expression)
- MAX(expression)
- COUNT(DISTINCT expression) - Supported in function call parsing

**Missing Aggregate Features** (5% gap):
- FILTER clause for conditional aggregation
- WITHIN GROUP (ORDER BY) for ordered-set aggregates

### Expression Support (90% Coverage)

**Fully Implemented:**
- Binary expressions (arithmetic, comparison, logical)
- Unary expressions (NOT, negation)
- BETWEEN expressions
- IN expressions (with lists and subqueries)
- EXISTS expressions
- CASE expressions (simple and searched)
- CAST expressions
- Function calls with arguments
- Literal values (string, integer, float, boolean, NULL)
- Identifiers (qualified and unqualified)
- Parenthesized expressions

**Partially Implemented:**
- EXTRACT expressions - Basic syntax
- SUBSTRING expressions - Basic syntax
- POSITION expressions - Basic syntax

**Missing Expression Features** (10% gap):
- COALESCE function
- NULLIF function
- Array expressions and constructors
- Row value constructors (multi-column comparisons)

### DDL Operations (80% Coverage)

**CREATE TABLE** - Comprehensive support:
- Column definitions with data types
- Primary key constraints
- Foreign key constraints
- Unique constraints
- Check constraints
- NOT NULL constraints
- DEFAULT values

**ALTER TABLE** - Good support:
- ADD COLUMN
- DROP COLUMN
- MODIFY/ALTER COLUMN
- ADD/DROP constraints
- RENAME TABLE/COLUMN

**Other DDL:**
- DROP TABLE
- CREATE INDEX (basic and unique)
- CREATE VIEW (basic)

**Missing DDL Features** (20% gap):
- TRUNCATE TABLE
- COMMENT ON statements
- More complex constraint types
- Temporary table support

---

## Missing SQL-99 Features (Gap Analysis)

Based on comprehensive codebase analysis, the following SQL-99 features are **NOT currently implemented**:

### High Priority Missing Features

#### 1. FETCH FIRST / OFFSET-FETCH Clause
**Status**: Not implemented (keyword recognized but no parsing)
**SQL-99 Feature**: F861, F862
**Importance**: HIGH
**Reason**: Standard pagination syntax (more portable than LIMIT/OFFSET)

**Examples:**
```sql
-- Standard SQL-99 syntax
SELECT * FROM users
ORDER BY created_at
OFFSET 20 ROWS
FETCH NEXT 10 ROWS ONLY;

-- Alternative form
SELECT * FROM products
ORDER BY price
FETCH FIRST 5 ROWS ONLY;
```

**Current Status**:
- Keywords FETCH and OFFSET are recognized
- No AST nodes for FETCH clause
- No parser methods for OFFSET...FETCH syntax
- LIMIT/OFFSET works but is non-standard

**Implementation Impact**: Medium (requires new AST nodes, parser extension to SELECT)

---

#### 2. NULLS FIRST / NULLS LAST in ORDER BY
**Status**: Not implemented (test data exists but no parsing support)
**SQL-99 Feature**: F851
**Importance**: HIGH
**Reason**: Critical for deterministic sorting with NULL values

**Examples:**
```sql
SELECT name, salary
FROM employees
ORDER BY salary DESC NULLS LAST;

SELECT product, rating
FROM reviews
ORDER BY rating NULLS FIRST, product;
```

**Current Status**:
- Test file exists: `testdata/real_world/19_geo_location_radius_search.sql:52`
- Keywords not recognized in ORDER BY context
- AST has OrderBy field but no NULL ordering support

**Implementation Impact**: Low (parser extension only, AST modification minimal)

---

#### 3. GROUPING SETS, ROLLUP, CUBE
**Status**: Not implemented
**SQL-99 Feature**: F441 (ROLLUP), F442 (CUBE), T431 (GROUPING SETS)
**Importance**: HIGH
**Reason**: Essential for OLAP and analytical queries

**Examples:**
```sql
-- ROLLUP - hierarchical aggregation
SELECT region, category, SUM(sales)
FROM sales_data
GROUP BY ROLLUP(region, category);

-- CUBE - all combinations
SELECT year, quarter, product, SUM(revenue)
FROM sales
GROUP BY CUBE(year, quarter, product);

-- GROUPING SETS - custom combinations
SELECT brand, category, SUM(quantity)
FROM inventory
GROUP BY GROUPING SETS ((brand), (category), (brand, category), ());
```

**Current Status**:
- No AST nodes for ROLLUP/CUBE/GROUPING SETS
- Error suggestions reference "grouping_sets" in `pkg/errors/suggestions.go:463`
- No parser support

**Implementation Impact**: High (complex AST changes, new parser logic for grouping specifications)

---

#### 4. FILTER Clause for Aggregates
**Status**: Syntax only (test data exists, no parsing)
**SQL-99 Feature**: T612
**Importance**: MEDIUM-HIGH
**Reason**: Cleaner syntax for conditional aggregation (PostgreSQL, SQL Server support)

**Examples:**
```sql
SELECT
    department,
    COUNT(*) FILTER (WHERE salary > 50000) as high_earners,
    COUNT(*) FILTER (WHERE salary <= 50000) as low_earners,
    AVG(salary) FILTER (WHERE active = true) as avg_active_salary
FROM employees
GROUP BY department;
```

**Current Status**:
- Test file: `testdata/postgresql/28_filter_clause.sql`
- Keyword FILTER recognized
- No AST support in FunctionCall structure
- No parser logic for FILTER (WHERE ...) syntax

**Implementation Impact**: Medium (requires FunctionCall AST extension, parser modification)

---

#### 5. LATERAL Joins
**Status**: Syntax recognition only (limited parsing support)
**SQL-99 Feature**: T491
**Importance**: MEDIUM-HIGH
**Reason**: Enables correlated table expressions (powerful for complex queries)

**Examples:**
```sql
SELECT u.name, recent_orders.order_date, recent_orders.total
FROM users u
CROSS JOIN LATERAL (
    SELECT order_date, total
    FROM orders
    WHERE user_id = u.id
    ORDER BY order_date DESC
    LIMIT 5
) recent_orders;
```

**Current Status**:
- Test file: `testdata/postgresql/25_lateral_join.sql`
- Keyword LATERAL is reserved: `pkg/sql/keywords/keywords.go:26`
- SQL_COMPATIBILITY.md shows "🔧 Syntax" support (20% coverage)
- No full semantic support for lateral subquery correlation

**Implementation Impact**: Medium-High (requires subquery correlation tracking, scope management)

---

#### 6. DISTINCT in Aggregate Functions
**Status**: Partially implemented
**SQL-99 Feature**: E071-05
**Importance**: MEDIUM
**Reason**: Common pattern for counting unique values

**Examples:**
```sql
SELECT
    COUNT(DISTINCT customer_id) as unique_customers,
    COUNT(DISTINCT product_id) as unique_products,
    SUM(DISTINCT category_id) as unique_categories
FROM orders;
```

**Current Status**:
- Parser recognizes DISTINCT in function calls: `pkg/sql/parser/parser.go:484-486`
- AST FunctionCall has Distinct field
- **Appears implemented** - needs verification in tests

**Implementation Impact**: Low (may only need comprehensive testing)

---

#### 7. MERGE Statement (UPSERT)
**Status**: IMPLEMENTED (v1.5.0+)
**SQL-99 Feature**: F312 (SQL:2003 but commonly needed)
**Importance**: MEDIUM (no longer a gap)
**Reason**: Efficient UPSERT operations (Oracle, SQL Server, PostgreSQL 15+)

**Examples:**
```sql
MERGE INTO target_table t
USING source_table s
ON (t.id = s.id)
WHEN MATCHED THEN
    UPDATE SET t.value = s.value, t.updated_at = CURRENT_TIMESTAMP
WHEN NOT MATCHED THEN
    INSERT (id, value, created_at) VALUES (s.id, s.value, CURRENT_TIMESTAMP);
```

**Current Status**:
- MERGE parsing implemented in parser.go parseMergeStatement()
- AST MergeStatement node exists and fully supported
- Test files: `testdata/oracle/06_merge_statement.sql`, `testdata/mssql/05_merge_statement.sql`
- SQL_COMPATIBILITY.md: Full support listed (80% coverage) - ACCURATE

**Note**: This feature was completed in v1.5.0 and is no longer part of the gap analysis. Consider removing from Phase 3 implementation roadmap.

---

### Medium Priority Missing Features

#### 8. TRUNCATE TABLE
**Status**: IMPLEMENTED (v1.5.0+)
**SQL-99 Feature**: F201 (SQL:2008)
**Importance**: MEDIUM (no longer a gap)
**Reason**: Efficient table clearing (faster than DELETE)

**Examples:**
```sql
TRUNCATE TABLE logs;
TRUNCATE TABLE temp_data CASCADE;
```

**Current Status**:
- TRUNCATE parsing implemented in parser.go parseTruncateStatement()
- AST TruncateStatement node exists and fully supported
- SQL_COMPATIBILITY.md: Full support listed (90% coverage) - ACCURATE

**Note**: This feature was completed in v1.5.0 and is no longer part of the gap analysis. Remove from Phase 1 implementation roadmap.

---

#### 9. COALESCE and NULLIF Functions
**Status**: Not implemented
**SQL-99 Feature**: E021-10, E021-11
**Importance**: MEDIUM
**Reason**: Common NULL handling patterns

**Examples:**
```sql
SELECT
    COALESCE(phone, email, 'No contact') as contact_method,
    NULLIF(status, 'unknown') as clean_status
FROM users;
```

**Current Status**:
- No special handling in parser (would parse as regular function calls)
- No type checking or validation

**Implementation Impact**: Low (can be treated as built-in functions)

---

#### 10. Frame Exclusion in Window Functions
**Status**: Not implemented
**SQL-99 Feature**: F855
**Importance**: MEDIUM
**Reason**: Fine-grained window frame control

**Examples:**
```sql
SELECT
    date, amount,
    AVG(amount) OVER (
        ORDER BY date
        ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING
        EXCLUDE CURRENT ROW
    ) as avg_excluding_current
FROM transactions;
```

**Current Status**:
- Window frame parsing exists (ROWS/RANGE)
- No EXCLUDE clause support in WindowFrame AST
- Keywords: EXCLUDE, CURRENT, ROW, GROUP, TIES, NO, OTHERS

**Implementation Impact**: Medium (AST extension, parser enhancement)

---

#### 11. Array Support (Basic)
**Status**: Partial (syntax recognition only)
**SQL-99 Feature**: S091, S094
**Importance**: MEDIUM
**Reason**: PostgreSQL compatibility, data structure support

**Examples:**
```sql
SELECT ARRAY[1, 2, 3, 4] as numbers;
SELECT name FROM users WHERE id = ANY(ARRAY[1,2,3]);
SELECT items[1] FROM orders;
```

**Current Status**:
- SQL_COMPATIBILITY.md: "⚠️ Partial" (40% coverage)
- No array literal parsing
- No array indexing support
- ANY/SOME operators exist but limited array support

**Implementation Impact**: Medium-High (requires array literal parsing, type system considerations)

---

### Lower Priority Missing Features

#### 12. INTERSECT ALL and EXCEPT ALL
**Status**: Not implemented
**SQL-99 Feature**: F302, F304
**Importance**: LOW-MEDIUM
**Reason**: Completeness for set operations (with duplicate preservation)

**Examples:**
```sql
SELECT product_id FROM inventory_a
INTERSECT ALL
SELECT product_id FROM inventory_b;

SELECT customer_id FROM all_customers
EXCEPT ALL
SELECT customer_id FROM inactive_customers;
```

**Current Status**:
- INTERSECT and EXCEPT supported
- ALL modifier exists for UNION ALL
- No ALL support for INTERSECT/EXCEPT

**Implementation Impact**: Low (extend existing set operation parsing)

---

#### 13. TABLE Value Constructor
**Status**: Not implemented
**SQL-99 Feature**: F641
**Importance**: LOW
**Reason**: Inline table creation (useful for testing, small datasets)

**Examples:**
```sql
SELECT * FROM (VALUES
    (1, 'Alice', 30),
    (2, 'Bob', 25),
    (3, 'Charlie', 35)
) AS people(id, name, age);
```

**Current Status**:
- No VALUES as standalone table constructor
- VALUES only in INSERT context

**Implementation Impact**: Medium (new table reference type)

---

#### 14. Transaction Control Statements
**Status**: Not implemented
**SQL-99 Feature**: F381, F382, F383
**Importance**: LOW (for parser - high for execution)
**Reason**: Parsing completeness (execution not in scope)

**Examples:**
```sql
BEGIN TRANSACTION;
COMMIT;
ROLLBACK;
SAVEPOINT sp1;
ROLLBACK TO SAVEPOINT sp1;
RELEASE SAVEPOINT sp1;
```

**Current Status**:
- No transaction control parsing
- Out of scope for SQL parser (execution layer concern)

**Implementation Impact**: Low for parsing (just statement recognition)

---

#### 15. GRANT/REVOKE Statements
**Status**: Not implemented
**SQL-99 Feature**: F261, F262
**Importance**: LOW (for parser)
**Reason**: DDL completeness (execution not in scope)

**Examples:**
```sql
GRANT SELECT, INSERT ON users TO app_user;
REVOKE UPDATE ON orders FROM readonly_user;
GRANT ALL PRIVILEGES ON DATABASE mydb TO admin_user;
```

**Current Status**:
- No privilege management parsing
- Out of scope for parsing use cases

**Implementation Impact**: Medium (complex privilege specifications)

---

## Priority Ranking and Implementation Roadmap

### Phase 1: High-Impact Quick Wins (4-6 weeks)
**Goal**: Reach 88-90% compliance with minimal effort

| Feature | Priority | Effort | Impact | Order | Status |
|---------|----------|--------|--------|-------|--------|
| **NULLS FIRST/LAST** | P0 | 8h | High | 1 | TODO |
| **FETCH FIRST / OFFSET-FETCH** | P0 | 16h | High | 2 | TODO |
| **COALESCE/NULLIF** | P1 | 8h | Medium | 3 | TODO |
| **DISTINCT in aggregates** (verification) | P1 | 4h | Medium | 4 | TODO |
| **INTERSECT/EXCEPT ALL** | P1 | 6h | Low | 5 | TODO |

Note: TRUNCATE TABLE (previously P1) has been COMPLETED in v1.5.0 and removed from this phase.

**Phase 1 Total**: ~42 hours (reduced from 50)
**Compliance Gain**: +8-10%
**New Compliance**: 88-90%

---

### Phase 2: Advanced Analytics Features (6-8 weeks)
**Goal**: Reach 93-94% compliance with analytical SQL support

| Feature | Priority | Effort | Impact | Order |
|---------|----------|--------|--------|-------|
| **FILTER Clause** | P0 | 16h | High | 1 |
| **GROUPING SETS** | P0 | 24h | High | 2 |
| **ROLLUP** | P0 | 16h | High | 3 |
| **CUBE** | P0 | 16h | High | 4 |
| **Frame EXCLUDE** | P1 | 12h | Medium | 5 |

**Phase 2 Total**: ~84 hours
**Compliance Gain**: +5-6%
**New Compliance**: 93-94%

---

### Phase 3: Advanced Features (Optional - 4-6 weeks)
**Goal**: Reach 95%+ compliance with advanced SQL-99 features

| Feature | Priority | Effort | Impact | Order | Status |
|---------|----------|--------|--------|-------|--------|
| **LATERAL Joins** | P1 | 24h | Medium-High | 1 | TODO |
| **Array Support (Basic)** | P2 | 20h | Medium | 2 | TODO |
| **TABLE Constructor** | P2 | 12h | Low | 3 | TODO |

Note: MERGE Statement (previously P1, 32h) has been COMPLETED in v1.5.0 and removed from this phase.

**Phase 3 Total**: ~56 hours (reduced from 88)
**Compliance Gain**: +3-4%
**New Compliance**: 95-96%

---

### Timeline Summary

| Phase | Duration | Effort | Compliance | Features | Status |
|-------|----------|--------|------------|----------|--------|
| **Current State** | - | - | 80-85% | Baseline | - |
| **Phase 1** | 4-6 weeks | 42h | 88-90% | 5 features | TODO |
| **Phase 2** | 6-8 weeks | 84h | 93-94% | 5 features | TODO |
| **Phase 3** | 4-6 weeks | 56h | 95-96% | 3 features | TODO |
| **Total** | 14-20 weeks | 182h | 95-96% | 13 features | Updated |

Note: Total effort reduced by 40 hours (18%) due to MERGE and TRUNCATE completion in v1.5.0.

**Recommended Path to 95%**: Complete Phase 1 + Phase 2 + Phase 3 (LATERAL, Array Support)

---

## Detailed Feature Analysis

### Feature 1: NULLS FIRST/LAST in ORDER BY

**SQL-99 Standard**: F851 - Null ordering
**Importance**: HIGH - Critical for deterministic sorting
**Effort**: 8 hours
**Complexity**: Low

**Implementation Details:**

1. **AST Changes** (`pkg/sql/ast/ast.go`):
```go
type OrderByExpression struct {
    Expression  Expression
    Ascending   bool     // true for ASC, false for DESC
    NullsFirst  *bool    // nil = default, true = NULLS FIRST, false = NULLS LAST
}
```

2. **Parser Changes** (`pkg/sql/parser/parser.go`):
```go
// In parseWindowSpec() and parseOrderBy()
if p.currentToken.Type == "ASC" || p.currentToken.Type == "DESC" {
    ascending := p.currentToken.Type == "ASC"
    p.advance()

    var nullsFirst *bool
    if p.currentToken.Type == "NULLS" {
        p.advance()
        if p.currentToken.Type == "FIRST" {
            t := true
            nullsFirst = &t
        } else if p.currentToken.Type == "LAST" {
            f := false
            nullsFirst = &f
        }
        p.advance()
    }
}
```

3. **Token/Keyword Changes**: Keywords already exist (NULLS in reserved list)

4. **Test Cases**:
   - Basic: `ORDER BY salary DESC NULLS LAST`
   - Multiple columns: `ORDER BY dept NULLS FIRST, salary DESC NULLS LAST`
   - Default behavior verification
   - Window function context: `OVER (ORDER BY date NULLS FIRST)`

**Dependencies**: None
**Risks**: Low
**Testing Effort**: 4 hours

---

### Feature 2: FETCH FIRST / OFFSET-FETCH Clause

**SQL-99 Standard**: F861, F862 - Result offset and row limits
**Importance**: HIGH - Standard pagination syntax
**Effort**: 16 hours
**Complexity**: Medium

**Implementation Details:**

1. **AST Changes**:
```go
type FetchClause struct {
    OffsetRows    *int64   // OFFSET n ROWS
    FetchRows     *int64   // FETCH NEXT/FIRST n ROWS ONLY
    WithTies      bool     // FETCH ... WITH TIES
    PercentRows   bool     // FETCH ... PERCENT
}

type SelectStatement struct {
    // ... existing fields
    Fetch *FetchClause  // New field (mutually exclusive with Limit/Offset)
}
```

2. **Parser Changes**:
```go
func (p *Parser) parseFetchClause() (*ast.FetchClause, error) {
    fetch := &ast.FetchClause{}

    // Parse OFFSET
    if p.currentToken.Type == "OFFSET" {
        p.advance()
        // parse integer
        p.expect("ROWS") or p.expect("ROW")
    }

    // Parse FETCH
    if p.currentToken.Type == "FETCH" {
        p.advance()
        p.expect("NEXT" or "FIRST")
        // parse integer or PERCENT
        p.expect("ROWS" or "ROW")
        p.expect("ONLY" or "WITH TIES")
    }
}
```

3. **Keywords**: FETCH, OFFSET, ROWS, ROW, ONLY, TIES already exist

4. **Test Cases**:
   - `OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY`
   - `FETCH FIRST 5 ROWS ONLY` (no OFFSET)
   - `OFFSET 10 ROWS` (no FETCH)
   - `FETCH FIRST 10 PERCENT ROWS ONLY`
   - `FETCH NEXT 20 ROWS WITH TIES`
   - Error cases: invalid syntax combinations

**Dependencies**: None
**Risks**: Medium (need to handle Limit/Offset deprecation path)
**Testing Effort**: 8 hours

---

### Feature 3: GROUPING SETS, ROLLUP, CUBE

**SQL-99 Standard**: F441 (ROLLUP), F442 (CUBE), T431 (GROUPING SETS)
**Importance**: HIGH - Essential for OLAP
**Effort**: ROLLUP 16h + CUBE 16h + GROUPING SETS 24h = 56 hours total
**Complexity**: High

**Implementation Details:**

1. **AST Changes**:
```go
type GroupByClause struct {
    Type       string        // "SIMPLE", "ROLLUP", "CUBE", "GROUPING_SETS"
    Expressions []Expression  // For simple GROUP BY
    Sets       [][]Expression // For GROUPING SETS
}

type SelectStatement struct {
    // Change from: GroupBy []Expression
    GroupBy *GroupByClause  // New structured field
}
```

2. **Parser Changes**:
```go
func (p *Parser) parseGroupByClause() (*ast.GroupByClause, error) {
    p.expect("GROUP")
    p.expect("BY")

    if p.currentToken.Type == "ROLLUP" {
        return p.parseRollup()
    } else if p.currentToken.Type == "CUBE" {
        return p.parseCube()
    } else if p.currentToken.Type == "GROUPING" {
        if p.peekToken().Type == "SETS" {
            return p.parseGroupingSets()
        }
    }

    // Standard GROUP BY
    return p.parseSimpleGroupBy()
}
```

3. **Keywords**: ROLLUP, CUBE, GROUPING, SETS need to be added

4. **Test Cases**:
   - ROLLUP with 2-3 columns
   - CUBE with 2-3 columns
   - GROUPING SETS with various combinations
   - Empty grouping set `()`
   - Nested expressions
   - GROUPING() function for identifying subtotal rows

**Dependencies**: None
**Risks**: High (complex AST restructuring, backward compatibility)
**Testing Effort**: 20 hours
**Migration Strategy**: Provide backward compatibility for old GroupBy []Expression field

---

### Feature 4: FILTER Clause for Aggregates

**SQL-99 Standard**: T612 - Advanced aggregate features
**Importance**: MEDIUM-HIGH
**Effort**: 16 hours
**Complexity**: Medium

**Implementation Details:**

1. **AST Changes**:
```go
type FunctionCall struct {
    Name       string
    Arguments  []Expression
    Distinct   bool
    Over       *WindowSpec
    Filter     Expression  // NEW: FILTER (WHERE condition)
}
```

2. **Parser Changes**:
```go
// In parseFunctionCall(), after OVER clause parsing:
if p.currentToken.Type == "FILTER" {
    p.advance()
    p.expect("(")
    p.expect("WHERE")
    filterExpr, err := p.parseExpression()
    funcCall.Filter = filterExpr
    p.expect(")")
}
```

3. **Keywords**: FILTER already reserved

4. **Test Cases**:
   - `COUNT(*) FILTER (WHERE active = true)`
   - `SUM(amount) FILTER (WHERE category = 'sales')`
   - `AVG(salary) FILTER (WHERE dept = 'engineering')`
   - Multiple aggregates with different filters
   - FILTER combined with DISTINCT
   - FILTER combined with OVER (window functions)

**Dependencies**: None
**Risks**: Low
**Testing Effort**: 6 hours

---

## Effort Estimates

### Breakdown by Category

| Category | Features | Total Effort | % of Total | Status |
|----------|----------|--------------|------------|--------|
| **ORDER BY Enhancements** | NULLS FIRST/LAST | 8h | 4.4% | TODO |
| **Pagination** | FETCH/OFFSET | 16h | 8.8% | TODO |
| **Analytical SQL** | ROLLUP, CUBE, GROUPING SETS, FILTER | 72h | 39.6% | TODO |
| **Window Function Enhancements** | Frame EXCLUDE | 12h | 6.6% | TODO |
| **JOIN Enhancements** | LATERAL | 24h | 13.2% | TODO |
| **Function Enhancements** | COALESCE, NULLIF | 8h | 4.4% | TODO |
| **Set Operations** | INTERSECT/EXCEPT ALL | 6h | 3.3% | TODO |
| **Data Types** | Array Support | 20h | 11.0% | TODO |
| **Value Constructors** | TABLE constructor | 12h | 6.6% | TODO |
| **Testing & Documentation** | All features | 18h | 9.9% | TODO |
| **TOTAL** | 13 features | **182h** | 100% | Updated |

Note: MERGE (32h) and TRUNCATE (8h) are COMPLETED in v1.5.0. Testing/Documentation effort reduced proportionally.

### Effort by Complexity Level

| Complexity | Features | Effort | Avg per Feature | Status |
|------------|----------|--------|-----------------|--------|
| **Low** | 4 | 26h | 6.5h | TODO |
| **Medium** | 6 | 88h | 14.7h | TODO |
| **High** | 3 | 68h | 22.7h | TODO |
| **TOTAL** | 13 | 182h | 14.0h | Updated |

Note: Reduced from 15 features/222h due to MERGE and TRUNCATE completion.

---

## Implementation Recommendations

### Recommended Approach: Phased Implementation

**Phase 1: Quick Wins (Weeks 1-6)**
- Focus on low-hanging fruit with high impact
- Build confidence and momentum
- Establish testing patterns
- Features: NULLS ordering, FETCH, COALESCE, TRUNCATE, DISTINCT verification, INTERSECT/EXCEPT ALL

**Phase 2: Analytics Core (Weeks 7-14)**
- Implement OLAP features critical for analytics
- High complexity but high value
- Features: FILTER clause, GROUPING SETS, ROLLUP, CUBE, Frame EXCLUDE

**Phase 3: Advanced Features (Weeks 15-20)**
- Complete to 95% target
- Advanced but less commonly used features
- Features: LATERAL joins, MERGE statement, basic Array support

### Development Best Practices

1. **API Usage**:
   - For pooled parser instances: `GetParser()` and `PutParser(p)`
   - For parsing with position tracking: `ParseWithPositions(ConversionResult)`
   - Token conversion utilities are test-only helpers in individual test files
   - Always use `ParseWithPositions()` for production code to get accurate error locations

2. **Test-Driven Development**:
   - Write tests first based on SQL-99 standard examples
   - Include test data files in testdata/ directories
   - Use existing test patterns (parser_test.go, integration_test.go)

3. **AST Design Principles**:
   - Minimize breaking changes to existing AST
   - Use optional fields (pointers) for new features
   - Maintain backward compatibility with object pools

3. **Parser Patterns**:
   - Follow existing recursive descent patterns
   - Use helper methods for complex clause parsing
   - Implement proper error recovery and helpful error messages

4. **Documentation**:
   - Update CLAUDE.md with new feature documentation
   - Update CHANGELOG.md for each feature
   - Add examples to docs/USAGE_GUIDE.md
   - Update SQL_COMPATIBILITY.md matrix

5. **Performance Considerations**:
   - Leverage object pooling for new AST nodes
   - Minimize allocations in hot paths
   - Run benchmarks for each feature
   - Maintain race-free code with `-race` testing

### Code Quality Gates

For each feature implementation:

1. **Tests Pass**: `go test -race ./...`
2. **Benchmarks**: Performance regression < 5%
3. **Coverage**: Feature coverage > 90%
4. **Documentation**: Updated CLAUDE.md, CHANGELOG.md
5. **Examples**: Real-world test cases in testdata/
6. **Race Detection**: Zero race conditions
7. **Code Review**: Peer review completed

---

## Risk Assessment

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Breaking Changes in AST** | Medium | High | Use optional fields, maintain backward compatibility |
| **Performance Regression** | Low | High | Benchmark each feature, optimize hot paths |
| **Complex Feature Interactions** | Medium | Medium | Comprehensive integration tests, real-world SQL corpus |
| **Memory Leaks** | Low | High | Strict pool management, race detection testing |
| **Parser Complexity Growth** | High | Medium | Modular parser methods, clear separation of concerns |

### Project Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Scope Creep** | Medium | Medium | Strict prioritization, phase-based approach |
| **Time Estimation Error** | High | Low | Conservative estimates, buffer time (20% added) |
| **Dialect Conflicts** | Medium | Medium | Clear dialect separation, feature flags if needed |
| **Incomplete Testing** | Low | High | TDD approach, comprehensive test suites |
| **Documentation Drift** | Medium | Medium | Update docs in same PR as code changes |

### Mitigation Strategies

1. **AST Stability**:
   - Create feature branches for each major change
   - Use beta tags for testing before release
   - Maintain comprehensive integration test suite

2. **Performance**:
   - Continuous benchmarking in CI/CD
   - Performance budget: max 5% regression per feature
   - Profile complex features before merge

3. **Quality**:
   - Mandatory code review for all PRs
   - Race detection in all tests
   - Coverage tracking with targets

4. **Project Management**:
   - Weekly progress reviews
   - Adjust priorities based on user feedback
   - Release early and often (semantic versioning)

---

## Appendix: SQL-99 Standard Reference

### Core SQL-99 Features by Category

**E: Enhanced Features**
- E021: Character string types (CHAR, VARCHAR)
- E071: Basic query specification (SELECT, FROM, WHERE)
- E091: Set functions (COUNT, SUM, AVG, MIN, MAX)
- E101: Basic data manipulation (INSERT, UPDATE, DELETE)

**F: Features**
- F031: Basic schema manipulation (CREATE TABLE, DROP TABLE)
- F051: Basic date and time (DATE, TIME, TIMESTAMP)
- F201: TRUNCATE TABLE (SQL:2008)
- F261: GRANT statement
- F262: REVOKE statement
- F302: INTERSECT table operator
- F304: EXCEPT table operator (with ALL variants)
- F312: MERGE statement (SQL:2003)
- F381: COMMIT statement
- F382: ROLLBACK statement
- F383: SAVEPOINT
- F441: Extended grouping (ROLLUP)
- F442: Extended grouping (CUBE)
- F641: Row and table constructors (VALUES)
- F851: Null ordering (NULLS FIRST/LAST)
- F855: Window frame exclusion (EXCLUDE clause)
- F861: Top-level fetch clause (FETCH FIRST)
- F862: Offset clause (OFFSET)

**S: SQL/Foundation Features**
- S091: Basic array support
- S094: Advanced array operations

**T: Common Features**
- T431: Extended grouping (GROUPING SETS)
- T491: LATERAL derived tables
- T612: Advanced aggregate features (FILTER clause)

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-17 | Analysis Bot | Initial comprehensive analysis for issue #67 |

---

## References

1. **SQL-99 Standard**: ISO/IEC 9075:1999 Information technology — Database languages — SQL
2. **GoSQLX Codebase**: Version 1.5.1 (commit 0531c33)
3. **SQL Compatibility Matrix**: `docs/SQL_COMPATIBILITY.md`
4. **Test Data**: `testdata/postgresql/`, `testdata/oracle/`, `testdata/mssql/`
5. **Parser Implementation**: `pkg/sql/parser/parser.go`
6. **AST Definitions**: `pkg/sql/ast/ast.go`, `pkg/sql/ast/dml.go`
7. **Keyword Definitions**: `pkg/sql/keywords/keywords.go`

---

**End of Analysis**
