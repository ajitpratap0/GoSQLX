# Changelog

All notable changes to GoSQLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Query Optimization Engine (PR #210, closes #81)
- New `pkg/advisor/` package with 12 optimization rules
- Rules OPT-001 through OPT-008: SELECT * detection, missing WHERE, Cartesian products, DISTINCT overuse, subquery in WHERE, OR in WHERE, leading wildcard LIKE, function on indexed column
- Rules OPT-009 through OPT-012: N+1 query detection, index recommendations, join order optimization, query cost estimation
- CLI command `gosqlx optimize` with text/JSON output
- Complexity scoring and query classification

### Added - Schema Validation Extensions (PR #209, closes #82)
- Constraint validation: NOT NULL checking for INSERT/UPDATE
- Type compatibility checking for INSERT values vs column types
- Foreign key integrity validation
- Object pooling for validation maps
- Case-insensitive table/column lookups

### Added - SQL Dialect Support (PR #211)
- Snowflake dialect keyword detection and support
- Multi-dialect detection engine with weighted scoring
- Dialect-specific keyword sets for Snowflake, PostgreSQL, MySQL, SQL Server, Oracle, SQLite

### Fixed
- Relaxed performance baselines for CI runner variability
- Standardized token types in Snowflake keywords
- Optimized dialect hint scanning with scan length limit

## [1.7.0] - 2026-02-12 - Parser Enhancements: Schema-Qualified Names, Array/Regex Operators & SQL Standards

This release delivers 9 commits with major parser enhancements across 4 feature batches, 2 critical bug fixes, and comprehensive test improvements. Schema-qualified table names (`schema.table`) now work across all statement types, and the parser gains support for ARRAY constructors, regex operators, INTERVAL expressions, FETCH/FOR UPDATE, multi-row INSERT, PostgreSQL UPSERT, type casting, and positional parameters.

### Highlights
- **Schema-Qualified Names**: `schema.table` and `db.schema.table` support in SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, TRUNCATE, JOIN (Fixes #202)
- **Double-Quoted Identifiers**: ANSI SQL quoted identifiers in all DML/DDL statements (#200, #201)
- **Parser Batches 5-8**: ARRAY constructors, WITHIN GROUP, JSONB operators, INTERVAL, FETCH, FOR UPDATE, multi-row INSERT, UPSERT, type casting (`::` operator), positional parameters (`$1`), array subscript/slice, regex operators, BETWEEN tests
- **Test Coverage**: 30+ new test cases for schema qualification, tuple IN expressions, quoted identifiers

---

### Added - Parser Enhancements Batch 5 (PR #187)

#### ARRAY Constructor Syntax (#182)
- `ARRAY[1, 2, 3]` constructor expression parsing
- Nested arrays: `ARRAY[ARRAY[1,2], ARRAY[3,4]]`
- Empty arrays: `ARRAY[]`

#### WITHIN GROUP Ordered-Set Aggregates (#183)
- `PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary)` syntax
- Supports PERCENTILE_DISC, MODE, and other ordered-set aggregates
- Added `WithinGroup` field to `FunctionCall` AST

#### JSONB Operators Enhancement
- Concatenation operator: `||` for JSONB
- Delete operators: `-` (key delete), `#-` (path delete)
- All 10 JSON/JSONB operators fully supported

---

### Added - Parser Enhancements Batch 6 (PR #196)

#### PostgreSQL UPSERT / ON CONFLICT (#193)
- `INSERT ... ON CONFLICT (columns) DO NOTHING` syntax
- `INSERT ... ON CONFLICT (columns) DO UPDATE SET ...` syntax
- `ON CONFLICT ON CONSTRAINT constraint_name` variant
- Added `OnConflict` AST node with target columns, constraint, and update actions

#### PostgreSQL Type Casting (#188)
- `expr::type` operator syntax (e.g., `'123'::INTEGER`, `column::TEXT`)
- Chained casts: `value::TEXT::VARCHAR(50)`
- Parameterized types: `name::VARCHAR(100)`
- Array types: `tags::TEXT[]`
- All standard data types supported

#### Positional Parameters (#195)
- `$1`, `$2`, `$N` parameter placeholders
- Works in all expression contexts (WHERE, SELECT, VALUES, etc.)

---

### Added - Parser Enhancements Batch 7 (PR #197)

#### INTERVAL Expressions
- `INTERVAL '1 year'`, `INTERVAL '30 days'` syntax
- Time intervals: `INTERVAL '2 hours 30 minutes'`
- Added `IntervalExpression` AST node

#### FETCH FIRST/NEXT Enhancements
- Extended FETCH clause with additional syntax variants
- Better SQL-99 compliance for OFFSET-FETCH patterns

#### FOR UPDATE / FOR SHARE (SQL:2003)
- `SELECT ... FOR UPDATE` row-level locking
- `SELECT ... FOR SHARE` shared locking
- `FOR UPDATE OF table_name` targeted locking
- `FOR UPDATE NOWAIT` / `FOR UPDATE SKIP LOCKED`
- Added `ForClause` AST node

#### Multi-row INSERT (#179)
- `INSERT INTO t VALUES (1, 'a'), (2, 'b'), (3, 'c')` syntax
- Updated `InsertStatement.Values` to `[][]Expression` for multi-row support

---

### Added - Parser Enhancements Batch 8 (PR #198)

#### Array Subscript and Slice (#180, #190)
- `array[1]` subscript access
- `array[1:3]` slice syntax
- Chained access: `matrix[1][2]`
- Added `ArraySubscriptExpression` AST node

#### Regex Operators (#191)
- `~` case-sensitive match
- `~*` case-insensitive match
- `!~` case-sensitive not match
- `!~*` case-insensitive not match

#### BETWEEN Expression Tests
- Comprehensive test suite for BETWEEN with complex expression bounds

---

### Fixed

#### Schema-Qualified Table Names (#202, PR #204)
- `SELECT * FROM schema.table_name` now parses correctly (was: E2002 error)
- Added `parseQualifiedName()` helper supporting up to 3-part names (`db.schema.table`)
- Applied to: SELECT FROM, JOIN, INSERT INTO, UPDATE, DELETE FROM, CREATE TABLE/VIEW/INDEX, DROP, TRUNCATE, REFRESH MATERIALIZED VIEW
- Removed "Schema-Qualified Table Names" from known parser limitations
- Enabled `TestExtractTablesQualified_WithSchema` with 6 test cases
- 24 new parser tests in `schema_qualified_test.go`

#### Double-Quoted Identifiers in DML/DDL (#200, PR #201)
- `isIdentifier()` now used instead of `isType(TokenTypeIdentifier)` across all parsers
- Fixed in: INSERT, UPDATE, DELETE, MERGE, CREATE, DROP, TRUNCATE, REFRESH, CTE, constraints
- 527 lines of new tests in `double_quoted_identifier_test.go`

---

### Improved

#### Documentation (PRs #185, #186)
- Comprehensive godoc documentation update across all packages
- Updated docs to reflect v1.6.0 features as available

#### Test Coverage
- Tuple expressions in IN clause: comprehensive tests (PR #199)
- Safe type assertions pattern applied across test files
- Performance regression test baselines updated for CI variability

---

### Known Issues (Resolved from v1.6.0)

The following issues from v1.6.0 Known Issues have been resolved:
- ~~**#179**: Multi-row INSERT VALUES syntax~~ → Fixed in PR #197
- ~~**#180**: BETWEEN with complex expression bounds~~ → Fixed in PR #198
- ~~**#181**: Tuple expressions in IN clause~~ → Tests added in PR #199
- ~~**#182**: PostgreSQL ARRAY constructor syntax~~ → Fixed in PR #187
- ~~**#183**: WITHIN GROUP ordered set aggregates~~ → Fixed in PR #187

### Remaining Known Issues
- **#178**: PostgreSQL JSONB existence operators (?, ?|, ?&) in parser (partial - tokenizer supports them)
- Oracle PL/SQL `CREATE OR REPLACE FUNCTION` not supported (part of #202 report)

## [1.6.0] - 2025-12-09 - Major Feature Release: PostgreSQL Extensions, LSP Server & Developer Tools

This release represents a major milestone with 20+ PRs merged, adding comprehensive PostgreSQL support, a full Language Server Protocol implementation, VSCode extension, and significant performance optimizations.

### Highlights
- **PostgreSQL Extensions**: LATERAL JOIN, JSON/JSONB operators, DISTINCT ON, FILTER clause, aggregate ORDER BY
- **Language Server Protocol**: Full LSP server for IDE integration with real-time diagnostics
- **VSCode Extension**: Official extension with syntax highlighting, formatting, and autocomplete
- **Performance**: 14x faster token type checking, 575x faster keyword suggestions with caching
- **Developer Experience**: go-task build system, 10 linter rules, structured error codes

---

### Added - PostgreSQL Features (PRs #173-#177)

#### LATERAL JOIN Support (#173)
- Added `Lateral bool` field to `TableReference` AST node
- Parser recognizes LATERAL in FROM and JOIN clauses
- Supports: `LEFT JOIN LATERAL`, `INNER JOIN LATERAL`, `CROSS JOIN LATERAL`
- CLI formatter properly outputs LATERAL keyword

#### ORDER BY inside Aggregates (#174)
- Added `OrderBy []OrderByExpression` field to `FunctionCall` AST
- Supports: STRING_AGG, ARRAY_AGG, JSON_AGG, JSONB_AGG, XMLAGG, GROUP_CONCAT
- Full modifier support: ASC/DESC, NULLS FIRST/LAST
- Works with window functions and complex expressions

#### JSON/JSONB Operators (#175)
- Arrow operators: `->`, `->>` (field access)
- Path operators: `#>`, `#>>` (path access)
- Containment: `@>`, `<@` (contains/contained by)
- Existence: `?`, `?|`, `?&` (key existence checks)
- Delete: `#-` (delete at path)
- Proper operator precedence in expression parsing
- Supports chained operators: `data -> 'a' -> 'b' ->> 'c'`

#### PostgreSQL DISTINCT ON (#171, PR #176)
- `SELECT DISTINCT ON (column1, column2) ...` syntax
- Multi-column expression support
- 8 comprehensive test cases

#### FILTER Clause (SQL:2003 T612, PR #176)
- `COUNT(*) FILTER (WHERE condition)` syntax
- Works with all aggregate functions
- 13 test cases covering edge cases

#### RETURNING Clause (#159, PR #164)
- PostgreSQL-style RETURNING for INSERT, UPDATE, DELETE
- Supports: column names, `*`, qualified names, expressions
- Added `TokenTypeReturning` (379) for RETURNING keyword

---

### Added - Language Server Protocol (PRs #128-#129)

#### LSP Server Implementation (CLI-009)
- JSON-RPC 2.0 protocol handler over stdio
- `textDocument/didOpen`, `textDocument/didChange`, `textDocument/didClose` - Document sync
- `textDocument/publishDiagnostics` - Real-time SQL syntax error reporting
- `textDocument/hover` - Keyword/function documentation (60+ keywords)
- `textDocument/completion` - SQL autocomplete (100+ keywords, 22 snippets)
- `textDocument/formatting` - SQL code formatting
- `textDocument/documentSymbol` - SQL statement outline navigation
- `textDocument/signatureHelp` - Function signatures (20+ SQL functions)
- `textDocument/codeAction` - Quick fixes (add semicolon, uppercase keywords)
- Rate limiting (100 req/sec), content size limits (10MB), document limits (5MB)
- Incremental document sync for better performance with large files
- Error position extraction from parser messages

#### Usage
```bash
gosqlx lsp              # Start LSP server on stdio
gosqlx lsp --log /tmp/lsp.log  # With debug logging
```

---

### Added - VSCode Extension (PRs #132, #135)

#### Official GoSQLX Extension
- Real-time SQL validation via LSP
- SQL syntax highlighting with comprehensive TextMate grammar
- SQL formatting with customizable options
- Intelligent autocomplete for SQL keywords and functions
- Hover documentation for SQL keywords
- Multi-dialect support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)

#### Commands
- GoSQLX: Validate SQL
- GoSQLX: Format SQL
- GoSQLX: Analyze SQL
- GoSQLX: Restart Language Server

#### Settings
- `gosqlx.enable`: Enable/disable language server
- `gosqlx.executablePath`: Path to gosqlx binary
- `gosqlx.format.indentSize`: Formatting indent size
- `gosqlx.format.uppercaseKeywords`: Uppercase SQL keywords
- `gosqlx.dialect`: SQL dialect selection

---

### Added - SQL Standards Compliance (PRs #124-#126)

#### Token Type Unification (ARCH-002, PR #124)
- **120+ new SQL token types** with proper categorization
- Helper methods: `IsKeyword()`, `IsOperator()`, `IsLiteral()`, `IsDMLKeyword()`, `IsDDLKeyword()`, `IsJoinKeyword()`, `IsWindowKeyword()`, `IsAggregateFunction()`, `IsDataType()`, `IsConstraint()`, `IsSetOperation()`
- ModelType field for O(1) int-based comparisons
- **14x faster** token type checking (0.28ns vs 4.9ns)
- Token range constants for category boundaries

#### FETCH FIRST / OFFSET-FETCH (SQL-99 F861, F862, PR #125)
- `FETCH FIRST n ROWS ONLY` / `FETCH NEXT n ROWS ONLY`
- `FETCH FIRST n ROWS WITH TIES` (preserves ties in sort order)
- `FETCH FIRST n PERCENT ROWS ONLY` (percentage-based limiting)
- `OFFSET n ROWS` combined with FETCH clause
- Added `FetchClause` AST node

#### TRUNCATE TABLE (SQL:2008, PR #126)
- Basic syntax: `TRUNCATE [TABLE] table_name`
- Multiple tables: `TRUNCATE TABLE t1, t2, t3`
- Identity behavior: `RESTART IDENTITY` / `CONTINUE IDENTITY`
- Cascade behavior: `CASCADE` / `RESTRICT`
- Added `TruncateStatement` AST node

#### MATERIALIZED CTE Support (PR #129)
- `WITH cte AS MATERIALIZED (...)` syntax
- `WITH cte AS NOT MATERIALIZED (...)` syntax
- PostgreSQL-compatible optimization hints

---

### Added - Parser Enhancements (PRs #162-#164, #176)

#### Column Constraints (PR #163, #146)
- Column constraints: PRIMARY KEY, NOT NULL, NULL, UNIQUE, DEFAULT, CHECK, REFERENCES, AUTO_INCREMENT
- Table-level constraints: PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK with CONSTRAINT name
- Parameterized types: VARCHAR(100), DECIMAL(10,2), CHAR(50)
- Referential actions: ON DELETE/UPDATE CASCADE, SET NULL, SET DEFAULT, RESTRICT, NO ACTION

#### Derived Tables / Subqueries in FROM (#148, PR #163)
- `(SELECT ...) AS alias` in FROM clause
- Support in JOIN clauses
- Full nested subquery support

#### Column Aliases with AS Keyword (#160, PR #163)
- Added `AliasedExpression` AST type
- Preserves `AS` keyword in formatted output

#### Function Calls in INSERT VALUES (#158, PR #163)
- NOW(), UUID(), CONCAT(), arithmetic expressions in VALUES
- Expression-based VALUES parsing

#### Parser Bug Fixes (PR #162)
- **#142** DISTINCT/ALL keyword support in SELECT
- **#143** Arithmetic expression operator precedence (+, -, *, /, %)
- **#144** SQL comments: line (`--`) and block (`/* */`)
- **#145** Double-quoted identifiers: `"column_name"`
- **#147** NATURAL JOIN, NATURAL LEFT/RIGHT JOIN
- **#150** String literal quoting with single quotes
- **#151** IS NULL / IS NOT NULL formatting
- **#152** BETWEEN expression formatting
- **#153** IN expression formatting
- **#157** Qualified asterisk: `table.*` syntax

---

### Added - Linter Rules (PRs #164, #176)

#### 10 Complete Lint Rules
| Rule | Name | Description | Auto-Fix |
|------|------|-------------|----------|
| L001 | Trailing Whitespace | Detects trailing whitespace | Yes |
| L002 | Mixed Tabs/Spaces | Detects mixed indentation | No |
| L003 | Consecutive Blank Lines | Detects multiple blank lines | Yes |
| L004 | Indentation Depth | Warns on excessive nesting (>4 levels) | No |
| L005 | Line Length | Warns on long lines | No |
| L006 | Column Alignment | Checks SELECT column alignment | No |
| L007 | Keyword Case | Enforces uppercase/lowercase keywords | Yes |
| L008 | Comma Placement | Trailing vs leading comma style | No |
| L009 | Aliasing Consistency | Detects mixed table aliasing | No |
| L010 | Redundant Whitespace | Finds multiple consecutive spaces | Yes |

---

### Added - Security Scanner (PRs #164, #176)

#### CLI Integration (#154)
- Integrated `pkg/sql/security` scanner into CLI analyzer
- Security score adjustments based on finding severity
- 100% detection rate on injection patterns

#### Detection Patterns
- Tautology patterns (`'1'='1'`, `OR 1=1`)
- UNION-based injection
- Time-based blind injection (SLEEP, WAITFOR DELAY)
- Comment bypass (`--`, `/**/`)
- Stacked queries
- Dangerous functions (xp_cmdshell, LOAD_FILE)

---

### Added - Developer Tools (PRs #131, #133, #136)

#### go-task Build System (PR #131)
- Replaced Makefile with comprehensive Taskfile.yml (420+ lines)
- 45+ tasks vs original 10 Makefile targets
- Task namespacing: `build:cli`, `test:race`, `lint:fix`
- Cross-platform builds (linux, darwin, windows / amd64, arm64)
- CPU and memory profiling support
- Fuzz testing integration
- Security scanning (govulncheck)
- Development watch mode

#### Structured Error Codes (PR #133)
- Tokenizer errors: E1001-E1005
- Parser errors: E2001-E2012
- Semantic errors: E3001-E3004 (UndefinedTable, UndefinedColumn, TypeMismatch, AmbiguousColumn)
- All errors include: error codes, location info, helpful hints, doc links
- CLI JSON output includes `Code` field

#### Unified Configuration Package (PR #133)
- `pkg/config/` with Config struct
- File and environment loaders
- LSP integration
- 78.6% test coverage

#### Caching System (PR #136)
- Keyword suggestion cache: **575x speedup** (12.87ns vs 7402ns)
- Config file cache: **22.5x speedup** (1302ns vs 29379ns)
- Thread-safe with RWMutex
- Automatic invalidation on file modification

---

### Added - Metrics & Monitoring (PR #129)

#### Comprehensive Metrics System
- Parser operation metrics (duration, errors, statement counts)
- AST pool metrics (gets/puts/balance)
- Statement pool metrics
- Expression pool metrics
- Tokenizer pool metrics with hit rate tracking
- Thread-safe atomic counters

---

### Added - Test Coverage (PRs #137, #138)

#### AST Test Coverage to 80%+ (PR #138)
- DateTimeField.String() covering 44+ cases
- Parser position tracking infrastructure
- `ParseWithPositions()` method for position-aware parsing
- `currentLocation()` helper for accurate error locations

#### AST Interface Tests (PR #137)
- statementNode() marker methods for all statements
- expressionNode() marker methods for all expressions
- TokenLiteral() for 60+ node types
- Children() with comprehensive branch coverage
- Coverage improved from 60.7% to 70.1%

---

### Improved

#### Performance Optimizations (PR #127)
- O(1) switch dispatch on ModelType instead of O(n) isAnyType() calls
- isComparisonOperator() helper with O(1) ModelType switch
- Buffer pooling for keyword conversion (sync.Pool)
- ASCII fast-path in skipWhitespace for >99% of cases
- Parser pooling: GetParser/PutParser via sync.Pool
- CPU-scaled sustained load tests

#### AST Pool Architecture (PR #129)
- Iterative cleanup with work queue pattern to prevent stack overflow
- Added 8 new expression pools (Exists, Any, All, List, Unary, Extract, Position, Substring)
- MaxCleanupDepth and MaxWorkQueueSize limits

#### Type Assertion Safety (PR #129)
- Added proper `ok` pattern checking in `alter.go` and `value.go`

#### Race Condition Fixes (PR #129)
- Fixed data races in metrics.go using atomic operations
- Fixed race condition in LSP documents.go with defensive copy
- Fixed race condition in watch.go with RWMutex protection

#### Documentation Cleanup (PR #141)
- Deleted 4 LLM-generated files (~1,725 lines)
- Fixed API_REFERENCE.md return types
- Added 10 missing error codes to ERROR_CODES.md
- Fixed 50+ broken links and inaccurate references

---

### Changed

#### Go Version Update (PR #140)
- Minimum requirement: Go 1.21+ (was 1.19)
- Toolchain: Go 1.21+
- Updated all CI/CD workflows to test against Go 1.21+
- golangci-lint upgraded to v2.6.2

#### CLI Output Improvements (PR #163)
- Output file flag (`-o`) now functional for lint and analyze commands
- MERGE statement formatter with full clause support

---

### Fixed

- Critical type assertion panics in ALTER and VALUE parsing (PR #129)
- Race conditions in concurrent document management (PR #129)
- LSP hover returning nil instead of empty response (PR #129)
- Tokenizer negative column numbers in toSQLPosition (PR #129)
- L004 indentation depth display for depth > 9 (PR #164)
- CAST keyword missing from tokenizer keywordTokenTypes map (PR #176)
- || operator test with correct TokenTypeSingleQuotedString (PR #176)

---

### Known Issues (Future Enhancements)

The following features were identified during real-world testing and are tracked for future releases:
- **#178**: PostgreSQL JSONB existence operators (?, ?|, ?&) in parser
- **#179**: Multi-row INSERT VALUES syntax
- **#180**: BETWEEN with complex expression bounds
- **#181**: Tuple expressions in IN clause
- **#182**: PostgreSQL ARRAY constructor syntax
- **#183**: WITHIN GROUP ordered set aggregates

## [1.5.1] - 2025-11-15 - Phases 2-3 Test Coverage Completion

### Phase 3 Complete: Token and Tokenizer Coverage Enhancement

**Released - PR #88**

#### Test Coverage Enhancement - Phase 3 (Token, Tokenizer)
- **Comprehensive Test Suite**: Added 2 new test files with 378 lines of test code
- **Perfect Token Coverage Achieved**: Token package reaches 100% coverage ⭐
- **Coverage Achievements**:
  - Token Package: 59.1% → **100.0%** (+40.9%) - **Perfect Coverage!**
  - Tokenizer Package: 69.1% → **76.1%** (+7.0%) - **Target Exceeded!**
- **Zero Race Conditions**: All tests pass with race detection enabled

#### New Test Files Created - Phase 3
- **pkg/sql/token/coverage_enhancement_test.go** (332 lines)
  - IsKeyword(), IsOperator(), IsLiteral() - all classification methods
  - 95+ subtests covering all token types (25 keywords, 7 operators, 6 literals)
  - Edge cases: empty types, custom tokens, case sensitivity
  - Token alias testing: EQ/EQUAL, NEQ/NOT_EQ
  - Method combinations: TRUE/FALSE as both keywords and literals
- **pkg/sql/tokenizer/coverage_enhancement_test.go** (310 lines)
  - Buffer pool operations (NewBufferPool, Get, Put, Grow)
  - Error handling (7 error creation and formatting functions)
  - Position tracking (Location, AdvanceN)
  - Tokenizer operations (NewWithKeywords, Reset)
  - 25+ subtests with comprehensive edge case coverage

#### Combined Phase 1 + Phase 2 + Phase 3 Impact
- **8 packages** with comprehensive coverage improvements
- **4,823 lines** of production-grade test code
- **3 packages at perfect 100% coverage**: Models, Keywords, Token
- **Zero race conditions** across entire codebase
- **Production-ready** reliability validated

---

### Phase 2 Complete: Keywords, Errors, and AST Coverage Enhancement

**Released - PR #87**

#### Test Coverage Enhancement - Phase 2 (Keywords, Errors, AST)
- **Comprehensive Test Suite**: Added 3 new test files with 1,351 lines of test code
- **Perfect Coverage Achieved**: Keywords package reaches 100% coverage
- **Coverage Achievements**:
  - Keywords Package: 92.8% → **100.0%** (+7.2%) - Perfect Coverage
  - Errors Package: 83.8% → **95.6%** (+11.8%) - Exceeded Target
  - AST Package: 73.7% → **74.4%** (+0.7%) - Marker functions covered
- **Documentation Cleanup**: Removed 2,538 lines of obsolete/redundant documentation
- **Archived Historical Docs**: Moved outdated architecture docs to archive with explanation

#### New Test Files Created - Phase 2
- **pkg/sql/keywords/coverage_enhancement_test.go** (405 lines)
  - All 5 SQL dialects tested (Generic, MySQL, PostgreSQL, SQLite, Unknown)
  - Case-sensitive and case-insensitive mode coverage
  - Edge cases: empty strings, whitespace, special characters
  - 9 comprehensive test functions
- **pkg/sql/ast/marker_functions_test.go** (387 lines)
  - 14 statement types + 16 expression types + 4 ALTER operations
  - Interface compliance validation
  - Edge cases with zero-value structs
  - 5 test functions with 50+ subtests
- **pkg/errors/coverage_enhancement_test.go** (559 lines)
  - 9 advanced error builder functions
  - 5 suggestion helper functions
  - Integration and edge case validation
  - 4 test suites with 50+ subtests

#### Documentation Improvements
- Removed 5 obsolete LLM-generated session summaries (2,538 lines)
- Archived 2 outdated architecture/performance docs
- Created `PHASE2_COVERAGE_SUMMARY.md` with comprehensive documentation
- Added `archive/historical-architecture-docs/README.md` to explain historical context

#### Combined Phase 1 + Phase 2 Impact
- **6 packages** with comprehensive coverage improvements
- **4,445 lines** of production-grade test code
- **Zero race conditions** across entire codebase
- **Production-ready** reliability validated

## [1.5.0] - 2025-11-15 - Phase 1 Test Coverage Achievement

### Phase 1 Complete: Comprehensive Test Coverage Across CLI, Parser, and Tokenizer

**This release marks a major milestone** in GoSQLX quality assurance with comprehensive test coverage improvements across three critical packages. All Phase 1 coverage targets have been met or exceeded, establishing GoSQLX as production-grade software with extensive test validation.

### Test Coverage Enhancement - Phase 1 Complete (CLI, Parser, Tokenizer)
- **Comprehensive Test Suite**: Added 7 new test files with 3,094 lines of test code
- **Triple Coverage Achievement**: Met or exceeded all three coverage targets
  - CLI Package: 63.3% coverage (exceeded 60% target by 3.3%)
  - Parser Package: 75.0% coverage (met 75% target exactly)
  - Tokenizer Package: 76.5% coverage (exceeded 70% target by 6.5%)
- **CLI Code Refactoring**: Improved maintainability with net reduction of 529 lines
- **Real-World Integration Testing**: 115+ production SQL queries validated across multiple dialects
- **Quality Assurance**: All tests pass with race detection enabled, zero race conditions detected

### New Test Files Created - Parser Package
- **parser_additional_coverage_test.go** (420 lines): Additional statement coverage (CTEs, window functions)
- **parser_edge_cases_test.go** (450 lines): Edge cases and boundary conditions
- **parser_error_recovery_test.go** (380 lines): Error recovery and handling
- **parser_final_coverage_test.go** (350 lines): Final coverage gap filling
- **parser_targeted_coverage_test.go** (410 lines): Targeted function coverage improvements
- **error_recovery_test.go** (61 lines): Error recovery integration tests
- **integration_test.go** (311 lines): Real-world SQL query validation framework

### New Test Files Created - Tokenizer Package
- **tokenizer_coverage_test.go** (712 lines): Comprehensive tokenizer feature testing
  - Backtick identifiers (MySQL-style)
  - Triple-quoted strings (Python-style)
  - Escape sequences (\n, \t, \r, \\, \', \")
  - Scientific notation (1.23e4, 1.23E+4)
  - UTF-8 multi-byte characters (Chinese, Japanese, Korean, Arabic, emoji)
  - Operators and punctuation
  - Custom keyword support
  - Debug logger functionality

### Enhanced CLI Testing
- **sql_analyzer_test.go** (318 lines): Comprehensive CLI command testing
  - Analyze, validate, format, parse command coverage
  - Edge case testing: empty files, large files, invalid SQL, UTF-8
  - Error handling validation across all commands
  - Input detection testing (file vs SQL string)

### Integration Test Infrastructure
- **testdata/postgresql/queries.sql**: PostgreSQL-specific queries
- **testdata/mysql/queries.sql**: MySQL-specific queries
- **testdata/real_world/ecommerce.sql**: Complex e-commerce queries
- 115+ real-world SQL queries from production workloads
- Multi-dialect support validation
- Success rate tracking and failure analysis

### Coverage Progression
| Component | Initial | Target | Achieved | Status |
|-----------|---------|--------|----------|--------|
| CLI | ~50% | 60% | **63.3%** | ✅ Exceeded by 3.3% |
| Parser | 57.4% | 75% | **75.0%** | ✅ Met exactly |
| Tokenizer | 60.0% | 70% | **76.5%** | ✅ Exceeded by 6.5% |

### Function-Level Improvements - Tokenizer
| Function | Initial | Final | Improvement |
|----------|---------|-------|-------------|
| handleEscapeSequence | 0.0% | **85.7%** | +85.7% |
| readTripleQuotedString | 0.0% | **96.4%** | +96.4% |
| readBacktickIdentifier | 0.0% | **100%** | +100% (full coverage!) |
| SetDebugLogger | 0.0% | **100%** | +100% (full coverage!) |
| readPunctuation | 70.2% | **92.3%** | +22.1% |
| readQuotedIdentifier | 77.8% | **96.3%** | +18.5% |
| readNumber | 77.6% | **85.7%** | +8.1% |
| TokenizeContext | 81.1% | **84.9%** | +3.8% |

### CLI Code Refactoring
- **analyze.go**: Improved error handling consistency
- **config.go**: Enhanced configuration management
- **format.go**: Better error messages and UTF-8 handling
- **input_utils.go**: Consolidated input reading logic
- **parse.go**: Improved output formatting
- **validate.go**: Enhanced validation error reporting
- **Net Impact**: -529 lines with improved maintainability

### Testing Approach
- Table-driven test design with comprehensive subtests
- Short mode support for fast pre-commit hooks
- Integration tests document parser limitations for future improvements
- UTF-8 internationalization testing (8 languages tested)
- Edge case validation across all components
- Race detection validated confirming thread safety

### Quality Metrics
- ✅ All tests pass with race detection enabled (go test -race)
- ✅ Pre-commit hook integration with short mode support
- ✅ Code formatted with go fmt
- ✅ No issues reported by go vet
- ✅ Thread-safe operation confirmed across all test scenarios
- ✅ Real-world SQL validation: 95%+ success rate on production queries

### Impact

**Production Confidence**: This Phase 1 test coverage enhancement establishes GoSQLX as enterprise-grade software with:
- **Comprehensive Validation**: 3,094 lines of new tests covering real-world usage patterns
- **International Compliance**: Full UTF-8 support validated across 8 languages
- **Thread-Safe Operation**: Zero race conditions detected in 20,000+ concurrent operations
- **Real-World Readiness**: 95%+ success rate on production SQL queries
- **Code Quality**: 529 lines removed through refactoring, improving maintainability
- **Performance Maintained**: 1.38M+ ops/sec sustained throughout all test scenarios

This release positions GoSQLX as the most thoroughly tested Go SQL parser library, with comprehensive test coverage exceeding industry standards across all critical components.

### Related Pull Request

**PR #85**: [Phase 1 Test Coverage Achievement - CLI, Parser, and Tokenizer](https://github.com/ajitpratap0/GoSQLX/pull/85)
- 81 files changed, 25,883 insertions, 1,735 deletions
- 20 commits including 8 CI/CD fix commits
- All 16 CI checks passing (tests across 3 platforms × 3 Go versions, linting, security, benchmarks)
- Comprehensive review and validation

### Documentation Created
- **CLI_REFACTORING_SUMMARY.md**: CLI coverage and refactoring details
- **PARSER_COVERAGE_SUMMARY.md**: Parser test coverage breakdown
- **TOKENIZER_COVERAGE_SUMMARY.md**: Tokenizer coverage achievement details
- **SESSION_PROGRESS_SUMMARY.md**: Overall session progress tracking

### Key Improvements

**Production Readiness Enhancements:**
- **Battle-Tested Reliability**: 3,094 lines of new test code across 7 comprehensive test files
- **Real-World Validation**: 115+ production SQL queries tested across multiple database dialects (PostgreSQL, MySQL, SQL Server, Oracle)
- **International Support**: Full UTF-8 testing across 8 languages (Chinese, Japanese, Korean, Arabic, Russian, Spanish, French, German)
- **Thread Safety**: All tests pass with race detection enabled, zero race conditions detected across 20,000+ concurrent operations
- **Performance Validated**: 95%+ success rate on real-world SQL queries with maintained throughput (1.38M+ ops/sec)

**Code Quality Improvements:**
- **CLI Refactoring**: Net reduction of 529 lines through improved architecture and code consolidation
- **Enhanced Error Handling**: Better error messages and UTF-8 handling across all CLI commands
- **Improved Maintainability**: Consolidated input reading logic and consistent validation patterns

**Testing Infrastructure:**
- **Short Mode Support**: Fast pre-commit hook integration for developer productivity
- **Integration Testing**: Real-world SQL validation framework with success rate tracking
- **Edge Case Coverage**: Comprehensive testing of boundary conditions, empty inputs, and invalid syntax
- **Resource Management**: Proper object pooling validated in all test scenarios

### Complete Coverage Breakdown

**Before Phase 1:**
- CLI Package: ~50% coverage
- Parser Package: 57.4% coverage
- Tokenizer Package: 60.0% coverage

**After Phase 1:**
- **CLI Package**: 63.3% coverage ⬆️ **+13.3%** (exceeded 60% target)
- **Parser Package**: 75.0% coverage ⬆️ **+17.6%** (met 75% target exactly)
- **Tokenizer Package**: 76.5% coverage ⬆️ **+16.5%** (exceeded 70% target)

### Previous Test Coverage Enhancement - AST Package (v1.4.0)
- **Comprehensive Test Suite**: Added 10 new test files with ~1,800 lines of tests
- **Coverage Improvement**: Increased AST package coverage from 59.6% to 73.4% (+13.8 percentage points)
- **Production Confidence**: Exceeded 70% coverage target, validating production readiness
- **Quality Assurance**: All tests pass with race detection enabled, zero race conditions detected

### New Test Files Created
- **data_loading_test.go** (~250 lines): Cloud data loading features (StageParamsObject, DataLoadingOptions, helpers)
- **pool_test.go** (~180 lines): Object pooling infrastructure (Insert/Update/Delete statement pools, reuse validation)
- **span_test.go** (~450 lines): Source location tracking (SpannedNode, UnionSpans, all Span() methods)
- **alter_test.go** (~650 lines): ALTER statements (Table/Role/Policy/Connector operations, RoleOption methods)
- **dml_test.go**: Data Manipulation Language statement tests
- **data_type_test.go**: SQL data type handling tests
- **nodes_test.go** (~300 lines): AST node interfaces (marker methods, TokenLiteral(), Children())
- **operator_test.go**: Operator types and operations tests
- **types_test.go**: AST type definition tests

### Enhanced Existing Tests
- **value_test.go** (+180 lines): Added comprehensive Value.String() tests for 11 missing types (byte strings, raw strings, national/hex/double-quoted strings), plus all 40+ DateTimeField variants
- **trigger_test.go**: Applied go fmt formatting for code consistency

### Coverage Progression
| Stage | Coverage | Gain | Test File |
|-------|----------|------|-----------|
| Initial | 59.6% | - | Baseline |
| Data loading tests | 63.1% | +3.5% | data_loading_test.go |
| Pool tests | 67.7% | +4.6% | pool_test.go |
| Span tests | 72.3% | +4.6% | span_test.go |
| Value enhancements | 73.4% | +1.1% | value_test.go |
| **Final** | **73.4%** | **+13.8%** | **Total** |

### Testing Approach
- Table-driven test design with subtests for comprehensive coverage
- Edge case validation across all AST node types
- Race detection validated (go test -race) confirming thread safety
- Memory-efficient pool testing with reuse verification
- Source location tracking validation for error reporting

### Quality Metrics
- ✅ All tests pass with race detection enabled
- ✅ Code formatted with go fmt
- ✅ No issues reported by go vet
- ✅ Thread-safe operation confirmed across all test scenarios
- ✅ Production-ready reliability validated for enterprise SQL parsing

### Impact
This substantial test coverage increase provides strong confidence in the AST package's correctness, thread safety, and production readiness. The comprehensive test suite validates complex SQL parsing scenarios including JOINs, CTEs, window functions, and advanced DML/DDL operations.

## [1.4.0] - 2025-09-07 - CLI Release and Code Quality

### ✅ CLI Production Release
- **Complete CLI Tool Suite**: Production-ready CLI with validate, format, analyze, and parse commands
- **High-Performance CLI**: 1.38M+ operations/second validation, 2,600+ files/second formatting throughput
- **Robust Input Detection**: Intelligent file vs SQL detection using `os.Stat()` with security limits (10MB max)
- **Memory Leak Prevention**: Fixed critical memory leak in format command with proper AST cleanup patterns
- **Comprehensive Testing**: Added benchmark tests, integration tests, and CLI command tests
- **Error Handling**: Enhanced error messages with file access validation and context

### ✅ CLI Features
- **Multi-format Output**: Support for JSON, YAML, table, and tree output formats
- **Batch Processing**: Directory expansion and glob pattern support for processing multiple SQL files
- **Security Limits**: File size validation, extension checking, and input sanitization
- **CI/CD Integration**: Format checking mode with proper exit codes for continuous integration
- **Performance Benchmarking**: Comprehensive benchmark suite validating CLI performance claims

### 🚀 Performance & Quality  
- **Token Conversion Performance**: TokenType.String() method optimized with comprehensive hash map (90+ token types)
- **Code Reduction**: analyze.go reduced from 570 to 218 lines (-62%) through legacy code elimination
- **Static Analysis**: All go vet, go fmt, and linting issues resolved
- **Test Reliability**: Benchmark error handling corrected for concurrent test execution

### 🔧 Technical Implementation
- **TokenType String Mapping**: Complete hash map implementation covering all 90+ token types vs previous 24 cases
- **Legacy Type System Removal**: Eliminated `AnalysisResult` type and `convertAnalysisReport()` function overhead
- **Modern CLI Architecture**: Unified analysis system using only modern `AnalysisReport` types
- **Benchmark Corrections**: Fixed goroutine error handling in scalability_bench_test.go and comprehensive_bench_test.go

### 📚 Documentation Updates
- **FIXES_APPLIED.md**: Comprehensive documentation of all code quality improvements applied
- **Session tracking**: Detailed before/after comparisons and impact metrics for all optimizations
- **CLI usage patterns**: Updated examples reflecting enhanced command functionality

### 🔄 Backward Compatibility
- **100% functional compatibility**: All CLI commands maintain identical user-facing behavior  
- **API preservation**: No breaking changes to public interfaces or command-line arguments
- **Performance maintained**: All existing functionality performs at same or better speed

### Goals Achieved
- ✅ CLI command modernization and optimization
- ✅ Significant code reduction through legacy elimination (-350+ lines)  
- ✅ Performance optimization of core token conversion operations
- ✅ Complete static analysis compliance (go vet, go fmt clean)
- ✅ Enhanced test reliability and benchmark correctness

## [1.3.0] - 2025-09-04 - Phase 2.5: Window Functions

### ✅ Major Features Implemented
- **Complete Window Function Support**: Full SQL-99 compliant window function parsing with OVER clause
- **PARTITION BY and ORDER BY**: Complete window specification support with expression parsing
- **Window Frame Clauses**: ROWS and RANGE frame specifications with proper bounds (UNBOUNDED PRECEDING/FOLLOWING, CURRENT ROW)
- **Ranking Functions**: ROW_NUMBER(), RANK(), DENSE_RANK(), NTILE() with full integration
- **Analytic Functions**: LAG(), LEAD(), FIRST_VALUE(), LAST_VALUE() with offset and default value support
- **Function Call Enhancement**: Complete function call parsing with parentheses, arguments, and DISTINCT support
- **Enhanced Expression Parsing**: Upgraded parseExpression() to handle complex function calls and window specifications

### 🚀 Performance & Quality
- **1M+ operations/second** sustained throughput maintained (up to 1.38M peak with concurrency)
- **Zero performance regression** - all existing functionality performs at same speed
- **Race-free implementation** - comprehensive concurrent testing validates thread safety
- **Memory efficient** - object pooling preserved with 60-80% memory reduction
- **Production-grade reliability** - extensive load testing and memory leak detection

### 🎯 SQL Standards Compliance
- **~80-85% SQL-99 compliance** achieved (significant advancement from ~70% SQL-92 in v1.2.0)
- **Complete window function standard** implemented per SQL-99 specification
- **Advanced analytical capabilities** - full support for ranking and analytic window functions
- **Complex query compositions** - window functions integrated with CTEs and set operations from previous phases

### 🔧 Technical Implementation
- **parseFunctionCall()** - Complete function call parsing with OVER clause detection and window specification handling
- **parseWindowSpec()** - Window specification parsing with PARTITION BY, ORDER BY, and frame clause support
- **parseWindowFrame()** - Frame clause parsing with ROWS/RANGE and bound specifications (UNBOUNDED, CURRENT ROW)
- **parseFrameBound()** - Individual frame bound parsing with expression support for offset values
- **Enhanced parseExpression()** - Function call detection and routing to window function parsing
- **Updated parseSelectStatement()** - Integrated enhanced expression parsing for SELECT column lists

### 📊 Comprehensive Testing
- **6 comprehensive test functions** with 14 total test cases covering all window function scenarios
- **Basic window functions**: ROW_NUMBER() OVER (ORDER BY column)
- **Partitioned window functions**: RANK() OVER (PARTITION BY dept ORDER BY salary DESC)
- **Frame specifications**: SUM(column) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)
- **Complex compositions**: Multiple window functions in single queries with various specifications
- **100% test pass rate** with race detection enabled
- **Extensive error case coverage** with contextual error messages

### 📚 Documentation Updates
- **Enhanced parser package documentation** with Phase 2.5 examples and window function API references
- **Updated AST package documentation** with window function node descriptions
- **Enhanced keywords package documentation** for window function keyword support
- **Comprehensive function documentation** with usage examples for all new parsing methods

### 🔄 Backward Compatibility
- **100% backward compatible** - all existing functionality preserved without changes
- **API stability** - no breaking changes to public interfaces or method signatures
- **Legacy test compatibility** - all Phase 1, Phase 2, and prior tests continue passing
- **Performance maintained** - no degradation in existing query parsing performance

### Goals Achieved
- ✅ ~80-85% SQL-99 compliance milestone reached
- ✅ Production-grade window function implementation with complete SQL-99 feature set
- ✅ Enhanced parser architecture supporting complex function calls and specifications
- ✅ Comprehensive test coverage for all window function categories
- ✅ Zero performance regression while adding significant new functionality
- ✅ Complete integration with existing CTE and set operations from previous phases

## [1.2.0] - 2025-08-15 - Phase 2: Advanced SQL Features

### ✅ Major Features Implemented
- **Complete Common Table Expression (CTE) support**: Simple and recursive CTEs with full SQL-92 compliance
- **Set operations**: UNION, UNION ALL, EXCEPT, INTERSECT with proper left-associative parsing
- **Multiple CTE definitions**: Comma-separated CTEs in single query with column specifications
- **CTE Integration**: Full compatibility with all statement types (SELECT, INSERT, UPDATE, DELETE)
- **Enhanced parser architecture**: New parsing functions for WITH statements and set operations

### 🚀 Performance & Quality
- **946K+ sustained operations/second** (30s load testing) - production grade performance
- **1.25M+ operations/second** peak throughput with concurrent processing
- **<1μs latency** for complex queries with CTEs and set operations
- **Zero performance regression** from Phase 1 - all existing functionality maintained
- **Race-free implementation** - comprehensive concurrent testing validates thread safety
- **Memory efficient** - object pooling preserved with 60-80% memory reduction

### 🎯 SQL Standards Compliance
- **~70% SQL-92 compliance** achieved (up from ~40% in Phase 1)
- **Advanced SQL features**: WITH clause, RECURSIVE support, set operations
- **Complex query compositions**: CTEs combined with set operations in single queries
- **Proper operator precedence**: Left-associative parsing for chained set operations

### 🔧 Technical Implementation
- **parseWithStatement()** - Complete WITH clause parsing with recursive support
- **parseSelectWithSetOperations()** - Set operations parsing with proper precedence  
- **parseCommonTableExpr()** - Individual CTE parsing with column specifications
- **parseMainStatementAfterWith()** - Post-CTE statement routing with full integration
- **Enhanced AST structures** - Complete integration with existing AST framework

### 📊 Comprehensive Testing
- **24+ test functions** total (9 new Phase 2 tests added)
- **4 comprehensive CTE tests**: Simple CTE, Recursive CTE, Multiple CTEs, Column specs
- **5 comprehensive set operation tests**: All operations, chaining, CTE combinations
- **100% test pass rate** with race detection enabled
- **Extensive error case coverage** with contextual error messages

### 📚 Documentation Updates
- **Enhanced Go package documentation** with Phase 2 examples and API references
- **Comprehensive README updates** with CTE and set operations examples
- **Updated performance benchmarks** reflecting Phase 2 capabilities
- **Complete API documentation** for all new parsing functions

### 🔄 Backward Compatibility
- **100% backward compatible** - all existing functionality preserved
- **API stability** - no breaking changes to public interfaces
- **Legacy test compatibility** - all Phase 1 and prior tests continue passing
- **Performance maintained** - no degradation in existing query parsing performance

### Goals Achieved
- ✅ ~70% SQL-92 compliance milestone reached
- ✅ Production-grade CTE implementation with recursive support
- ✅ Complete set operations support with proper precedence
- ✅ Enhanced error handling with contextual messages
- ✅ Comprehensive test coverage for all new features
- ✅ Zero performance regression while adding major features

## [1.1.0] - 2025-01-03 - Phase 1: Core SQL Enhancements

### ✅ Implemented Features  
- **Complete JOIN support**: All JOIN types (INNER/LEFT/RIGHT/FULL OUTER/CROSS/NATURAL)
- **Proper join tree logic**: Left-associative join relationships with synthetic table references
- **USING clause support**: Single-column USING clause parsing (multi-column planned for Phase 2)
- **Enhanced error handling**: Contextual error messages for JOIN parsing
- **Comprehensive test coverage**: 15+ JOIN test scenarios including error cases
- **Race-free implementation**: Zero race conditions detected in concurrent testing

### 🏗️ Foundation Laid (Phase 2 Ready)
- **CTE AST structures**: WithClause and CommonTableExpr defined with TODO integration points
- **Token support**: Added WITH, RECURSIVE, UNION, EXCEPT, INTERSECT keywords
- **Parser hooks**: Integration points documented for Phase 2 CTE completion

### Goals
- Achieve 70% SQL-92 compliance
- Unified AST structure
- Consistent error system with context and hints

## [1.0.2] - 2025-08-23

### Added
- Comprehensive Go package documentation for all major packages
- Root-level doc.go file with module overview and usage examples
- Package-level documentation comments for proper pkg.go.dev indexing
- Performance metrics and feature highlights in documentation

### Improved
- Documentation quality for better developer experience
- Module discoverability on pkg.go.dev

## [1.0.1] - 2025-08-23

### Added
- Performance monitoring package (`pkg/sql/monitor`) for real-time metrics
- Metrics collection for tokenizer, parser, and pool operations
- Performance summary generation with throughput calculations
- Thread-safe concurrent metrics recording
- Configurable metrics enable/disable functionality
- GitHub issue templates for bug reports, feature requests, and performance issues
- Pull request template with comprehensive checklist
- Enhanced README with community badges and widgets
- Project metrics and star history visualization

### Fixed
- Parser now correctly handles multiple JOIN clauses in complex queries
- Resolved race conditions in monitor package with atomic operations
- Fixed mutex copy issues in metrics collection
- Added missing EOF tokens in benchmark tests
- Fixed Windows test compatibility issues
- Resolved all golangci-lint warnings and ineffectual assignments
- Fixed staticcheck U1000 warnings for unused code

### Improved
- Enhanced performance tracking capabilities
- Better observability for production deployments
- Real-time performance monitoring support
- CI/CD pipeline now fully green across all platforms (Linux, macOS, Windows)
- Test coverage for monitor package at 98.6%
- All workflows (Go, Lint, Tests) passing with Go 1.19, 1.20, and 1.21

## [1.0.0] - 2024-12-01

### Added
- Production-ready SQL parsing with zero-copy tokenization
- Object pooling system for 60-80% memory reduction
- Multi-dialect SQL support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- MySQL backtick identifier support
- Full Unicode/UTF-8 support for international SQL
- Comprehensive test suite with race condition detection
- Performance benchmarking suite
- Real-world SQL query validation (115+ queries)
- Thread-safe implementation with linear scaling to 128+ cores
- AST (Abstract Syntax Tree) generation from tokens
- Visitor pattern support for AST traversal
- Position tracking with line/column information
- Detailed error reporting with context

### Changed
- Improved tokenizer performance by 47% over v0.9.0
- Enhanced token processing speed to 8M tokens/sec
- Reduced memory allocations through intelligent pooling
- Updated token type system to prevent collisions
- Refactored parser for better maintainability

### Fixed
- Token type collisions in constant definitions
- Race conditions in concurrent usage
- Memory leaks in long-running operations
- Test compatibility issues with hardcoded expectations
- Import path inconsistencies in examples

### Performance
- **Throughput**: 2.2M operations/second
- **Token Processing**: 8M tokens/second
- **Latency**: < 200ns for simple queries
- **Memory**: 60-80% reduction with pooling
- **Concurrency**: Linear scaling to 128 cores
- **Race-free**: 0 race conditions detected

### Tested
- 20,000+ concurrent operations
- 115+ real-world SQL queries
- 8 international languages
- Extended load testing (30+ seconds)
- Memory leak detection

## [0.9.0] - 2024-01-15

### Added
- Initial release of GoSQLX
- Basic SQL tokenization
- Simple parser implementation
- Core AST node types
- Keyword recognition
- Basic error handling

### Known Issues
- Limited concurrency support
- Higher memory usage
- Token type collisions
- Limited SQL dialect support

## [0.8.0] - 2023-12-01 [Pre-release]

### Added
- Prototype tokenizer
- Basic SQL parsing
- Initial AST structure

---

## Version History Summary

| Version | Release Date | Status | Key Features |
|---------|--------------|--------|--------------|
| 1.7.0 | 2026-02-12 | Current | Schema-qualified names, Parser Batches 5-8, quoted identifiers fix |
| 1.6.0 | 2025-12-09 | Previous | PostgreSQL Extensions, LSP Server, VSCode Extension, 14x faster tokens |
| 1.5.0 | 2025-11-15 | Stable | Phase 1 Test Coverage: CLI 63.3%, Parser 75%, Tokenizer 76.5% |
| 1.4.0 | 2025-09-07 | Previous | Production CLI, high-performance commands, memory leak fixes |
| 1.3.0 | 2025-09-04 | Stable | Window functions, ~80-85% SQL-99 compliance |
| 1.2.0 | 2025-09-04 | Previous | CTEs, set operations, ~70% SQL-92 compliance |
| 1.1.0 | 2025-01-03 | Previous | Complete JOIN support, enhanced error handling |
| 1.0.0 | 2024-12-01 | Stable | Production ready, +47% performance |
| 0.9.0 | 2024-01-15 | Legacy | Initial public release |
| 0.8.0 | 2023-12-01 | Pre-release | Prototype version |

## Upgrade Guide

### From 0.9.0 to 1.0.0

1. **Token Type Changes**: Review any code that directly references token type constants
2. **Pool Usage**: Always use `defer` when returning objects to pools
3. **Import Paths**: Update imports from test packages if used
4. **Performance**: Expect 47% performance improvement, adjust timeouts accordingly

### Breaking Changes in 1.0.0

- Token type constants have been reorganized to prevent collisions
- Some internal APIs have been refactored for better performance
- Test helper functions have been updated

## Support

For questions about upgrading or changelog entries:
- Open an issue: https://github.com/ajitpratap0/GoSQLX/issues
- Join discussions: https://github.com/ajitpratap0/GoSQLX/discussions

[Unreleased]: https://github.com/ajitpratap0/GoSQLX/compare/v1.7.0...HEAD
[1.7.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/ajitpratap0/GoSQLX/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ajitpratap0/GoSQLX/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/ajitpratap0/GoSQLX/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/ajitpratap0/GoSQLX/releases/tag/v0.8.0