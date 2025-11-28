# GoSQLX Clean Architecture Guide

**Version**: v1.5.1+ | **Last Updated**: November 2025

This document outlines the architectural principles and structure of the GoSQLX codebase after comprehensive cleanup and optimization.

## 📁 Directory Structure

```
GoSQLX/
├── cmd/gosqlx/                 # CLI application entry points
│   ├── main.go                 # Main application entry
│   └── cmd/                    # Cobra command definitions
│       ├── root.go             # Root command setup
│       ├── analyze.go          # Analysis command interface
│       ├── sql_analyzer.go     # Analysis business logic
│       ├── analysis_types.go   # Unified analysis types
│       ├── format.go           # Formatting command
│       ├── sql_formatter.go    # Formatting business logic  
│       ├── parse.go            # Parsing command
│       ├── validate.go         # Validation command
│       └── *_test.go           # Command tests
│
├── pkg/                        # Core library packages
│   ├── models/                 # Core data structures
│   │   ├── token.go            # Token definitions
│   │   ├── token_type.go       # Token type constants
│   │   ├── location.go         # Source position tracking
│   │   └── *.go                # Other core models
│   │
│   ├── sql/                    # SQL processing components
│   │   ├── tokenizer/          # Lexical analysis
│   │   ├── parser/             # Syntax analysis (11 modular files)
│   │   ├── ast/                # Abstract syntax trees
│   │   ├── keywords/           # SQL keyword definitions
│   │   ├── token/              # Token management
│   │   ├── security/           # SQL injection detection (v1.4+)
│   │   └── monitor/            # Performance monitoring
│   │
│   ├── gosqlx/                 # Simple high-level API (v1.4+)
│   │
│   └── metrics/                # Performance metrics
│
├── testdata/                   # Test data and fixtures
│   └── sql/                    # SQL test files
│       ├── basic_queries.sql   # Simple test queries
│       ├── performance_tests.sql # Performance test cases
│       ├── demo_queries.sql    # Demo and example queries
│       └── security_test.sql   # Security test cases
│
├── examples/                   # Example applications
├── docs/                       # Documentation
└── archive/                    # Historical artifacts
```

## 🏗️ Architectural Principles

### 1. **Separation of Concerns**
- **CLI Layer**: Command definitions and user interface (`cmd/gosqlx/cmd/`)
- **Business Logic**: Core analysis and processing logic (within command files)
- **Core Library**: Reusable components (`pkg/`)
- **Data Models**: Shared data structures (`pkg/models/`)

### 2. **Dependency Direction**
```
CLI Commands → Business Logic → Core Library → Models
```
- Commands depend on business logic
- Business logic depends on core library
- Core library depends on models
- No circular dependencies

### 3. **Package Organization**
- **Single Responsibility**: Each package has one clear purpose
- **Clear Interfaces**: Well-defined boundaries between packages  
- **Minimal Coupling**: Packages interact through defined interfaces
- **High Cohesion**: Related functionality grouped together

## 🧹 Cleanup Principles Applied

### 1. **File Consolidation**
- ✅ Removed duplicate `pkg/sql/models` package (unused)
- ✅ Consolidated scattered SQL files into `testdata/sql/` 
- ✅ Organized test files by functionality rather than size
- ✅ Removed IDE-specific files (`.idea/`)

### 2. **Naming Conventions**
- **Go Standard**: Follow Go naming conventions consistently
- **Descriptive Names**: File names clearly indicate purpose
- **Test Files**: Use `*_test.go` and `*_bench_test.go` patterns
- **Package Names**: Short, descriptive, lowercase

### 3. **Code Organization**
- **Command Pattern**: CLI commands separated from business logic
- **Business Logic**: Analysis logic in dedicated files
- **Type Definitions**: Unified type system with builders
- **Test Organization**: Comprehensive test suites with fixtures

## 📊 Package Responsibilities

### `cmd/gosqlx/cmd/`
**Purpose**: CLI command definitions and user interface
- Command setup and argument parsing
- Output formatting and display
- User interaction and validation
- Integration with business logic

### `pkg/models/`
**Purpose**: Core data structures used throughout the system
- Token definitions and types
- Location and span tracking
- Error types and interfaces
- Shared constants and enums

### `pkg/sql/tokenizer/`
**Purpose**: Lexical analysis - converting SQL text to tokens
- Token recognition and classification
- Position tracking and error reporting
- Unicode and international support
- Performance optimization with pooling

### `pkg/sql/parser/`
**Purpose**: Syntax analysis - converting tokens to AST
- Recursive descent parsing
- AST node construction
- Error recovery and reporting
- Token conversion and management

### `pkg/sql/ast/`
**Purpose**: Abstract Syntax Tree representation and operations
- AST node definitions and interfaces
- Tree traversal and visitor patterns
- Node manipulation and transformation
- Memory management with object pooling

**Statement Types** (v1.5.1+):
- `SelectStatement`, `InsertStatement`, `UpdateStatement`, `DeleteStatement`
- `CreateStatement`, `AlterStatement`, `DropStatement`
- `MergeStatement` (SQL:2003 F312)
- `MaterializedViewStatement` (CREATE/DROP/REFRESH)
- `WithStatement` (CTEs, recursive CTEs)

**Expression Types** (v1.5.1+):
- `BetweenExpression`, `InExpression`, `LikeExpression`, `IsNullExpression`
- `SubqueryExpression` (scalar, table, correlated, EXISTS)
- `WindowExpression` (OVER clause with PARTITION BY, ORDER BY, frames)
- `GroupingExpression` (GROUPING SETS, ROLLUP, CUBE)

### `pkg/sql/keywords/`
**Purpose**: SQL keyword recognition and categorization
- Multi-dialect keyword support
- Keyword classification and context
- Reserved word identification
- Dialect-specific variations

### `pkg/sql/security/` (v1.4+)
**Purpose**: SQL injection detection and security analysis
- Pattern-based injection detection
- Tautology recognition (`1=1`, `'a'='a'`)
- UNION-based injection detection
- Time-based blind injection detection
- Comment bypass detection
- Severity classification (Critical, High, Medium, Low)

### `pkg/gosqlx/` (v1.4+)
**Purpose**: Simple high-level API for common use cases
- One-line parsing: `gosqlx.Parse(sql)`
- Validation: `gosqlx.Validate(sql)`
- Batch processing: `gosqlx.ParseMultiple(queries)`
- Timeout support: `gosqlx.ParseWithTimeout(sql, timeout)`

## 🔄 Development Workflow

### 1. **Adding New Features**
1. Define data structures in `pkg/models/` if needed
2. Implement core logic in appropriate `pkg/sql/` package
3. Add business logic layer if needed
4. Create CLI command in `cmd/gosqlx/cmd/`
5. Add comprehensive tests with fixtures in `testdata/`

### 2. **Maintaining Code Quality**
- **Tests**: Every new feature must have tests
- **Documentation**: Update relevant docs with changes
- **Consistency**: Follow established naming and organization patterns
- **Performance**: Consider memory allocation and object pooling

### 3. **File Organization Rules**
- **No Root Clutter**: Keep root directory clean
- **Test Data**: All SQL files go in `testdata/sql/`
- **Documentation**: All docs in `docs/` directory
- **Examples**: Complete examples in `examples/` with their own README

## 🚀 Benefits Achieved

### 1. **Improved Maintainability**
- Clear separation of concerns
- Consistent naming and organization
- Reduced code duplication
- Better testability

### 2. **Enhanced Performance**
- Eliminated unused packages and files
- Optimized imports and dependencies
- Better memory management patterns
- Comprehensive benchmarking

### 3. **Better Developer Experience**
- Clear package responsibilities
- Consistent development patterns
- Comprehensive documentation
- Easy-to-understand structure

### 4. **Production Readiness**
- Robust error handling
- Comprehensive test coverage
- Performance monitoring
- Clean deployment artifacts

## 📋 Maintenance Guidelines

### Do's ✅
- Follow the established directory structure
- Maintain clear separation between CLI and business logic
- Write comprehensive tests for all new features
- Use the unified type system for analysis results
- Document architectural decisions
- Keep the root directory clean

### Don'ts ❌
- Don't create new model packages - use `pkg/models/`
- Don't scatter SQL files - use `testdata/sql/`
- Don't mix CLI logic with business logic
- Don't create circular dependencies between packages
- Don't commit IDE-specific files
- Don't duplicate functionality between packages

## 🎯 Future Considerations

### Scalability
- Package boundaries are designed for growth
- Clear interfaces allow for easy extension
- Performance monitoring is built-in
- Memory management is optimized

### Extensibility  
- New SQL dialects can be added to `pkg/sql/keywords/`
- New analysis types fit into the unified type system
- Additional CLI commands follow established patterns
- New parsers can integrate with existing AST system

This architecture provides a solid foundation for continued development while maintaining code quality, performance, and maintainability.