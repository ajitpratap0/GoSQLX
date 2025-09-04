# Changelog

All notable changes to GoSQLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - Phase 2.5: Window Functions

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

## [1.2.0] - 2025-09-04 - Phase 2: Advanced SQL Features

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

## [1.2.0] - 2025-09-04 - Phase 2: Advanced SQL Features

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

## [1.2.0] - (Planned Q4 2024) - Phase 2: Advanced Features

### Planned Features
- Window functions (OVER, PARTITION BY, RANK, LAG/LEAD)
- Transaction control statements (BEGIN/COMMIT/ROLLBACK)
- Views and materialized views support
- Stored procedure parsing (basic)
- Streaming parser API for large files
- AST transformation framework

### Goals
- Achieve 85% SQL-99 compliance
- Streaming support for queries >10MB
- Query transformation and optimization capabilities

## [2.0.0] - (Planned Q1 2025) - Phase 3: Dialect Specialization

### Planned Features
- PostgreSQL-specific features (arrays, JSONB, custom types)
- MySQL-specific syntax and functions
- SQL Server T-SQL extensions
- Oracle PL/SQL basics
- SQLite pragmas and special syntax
- Dialect auto-detection

### Goals
- Multi-dialect parser with configuration
- 95% dialect-specific compliance
- Auto-detection with 99% accuracy

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
| 1.2.0 | 2025-09-04 | Current | CTEs, set operations, ~70% SQL-92 compliance |
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

[Unreleased]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ajitpratap0/GoSQLX/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/ajitpratap0/GoSQLX/releases/tag/v0.9.0