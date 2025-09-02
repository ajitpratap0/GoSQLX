# Changelog

All notable changes to GoSQLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - (Planned Q3 2024) - Phase 1: Foundation

### Planned Features
- Common Table Expressions (CTEs) with RECURSIVE support
- Complete JOIN support (LEFT/RIGHT/FULL OUTER/CROSS/NATURAL)
- Set operations (UNION/EXCEPT/INTERSECT)
- Comprehensive subquery support in all contexts
- Standardized error handling system
- AST structure consolidation

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
| 1.0.0 | 2024-12-01 | Current | Production ready, +47% performance |
| 0.9.0 | 2024-01-15 | Previous | Initial public release |
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