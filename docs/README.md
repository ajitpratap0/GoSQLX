# GoSQLX Documentation

Comprehensive documentation for the GoSQLX SQL parsing SDK.

**Current Version**: v1.7.0 | **Last Updated**: February 2026

## Feature Overview (v1.7.0)

GoSQLX is a production-ready, high-performance SQL parsing SDK for Go with comprehensive feature support:

### Core Capabilities
- **High-Performance Parsing** - 1.38M+ operations/second sustained, 1.5M peak with zero-copy tokenization
- **Multi-Dialect Support** - PostgreSQL, MySQL, SQL Server, Oracle, SQLite with ~80-85% SQL-99 compliance
- **Thread-Safe Operations** - Race-free concurrent processing validated with 20,000+ concurrent operations
- **Memory Efficient** - Object pooling architecture with 60-80% memory reduction
- **Production Ready** - Comprehensive error handling, position tracking, and recovery

### v1.6.0 PostgreSQL Extensions
- **LATERAL JOIN** - Correlated subqueries in FROM clause for advanced query patterns
- **JSON/JSONB Operators** - Full operator support (`->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`, `#-`)
- **DISTINCT ON** - PostgreSQL-specific row selection with deterministic ordering
- **FILTER Clause** - Conditional aggregation for selective aggregate functions (SQL:2003)
- **Aggregate ORDER BY** - ORDER BY within aggregate functions for position-dependent aggregates
- **RETURNING Clause** - Return modified rows from INSERT/UPDATE/DELETE operations

### Developer Tools
- **LSP Server** - Full Language Server Protocol support for IDE integration (diagnostics, hover, completion, formatting)
- **CLI Tool** - Command-line interface with validate, format, analyze, parse, and lsp commands
- **Security Scanner** - SQL injection detection with pattern scanning and severity classification
- **Linter** - 10 built-in linting rules (L001-L010) with auto-fix capabilities
- **Configuration** - YAML-based configuration (.gosqlx.yml) for project-wide settings

### Advanced SQL Features
- **Window Functions** - ROW_NUMBER, RANK, DENSE_RANK, NTILE, LAG, LEAD, FIRST_VALUE, LAST_VALUE with frames
- **CTEs** - Common Table Expressions including recursive CTEs with proper termination
- **Set Operations** - UNION, EXCEPT, INTERSECT with proper precedence
- **Complex JOINs** - All JOIN types (INNER, LEFT, RIGHT, FULL, CROSS, NATURAL) with left-associative parsing
- **MERGE Statements** - SQL:2003 F312 MERGE support for upsert operations
- **Grouping Sets** - ROLLUP, CUBE, GROUPING SETS for advanced analytics (SQL-99 T431)
- **Materialized Views** - CREATE/REFRESH/DROP MATERIALIZED VIEW support

## Documentation Index

### Getting Started

| Document | Description | Audience |
|----------|-------------|----------|
| [**GETTING_STARTED.md**](GETTING_STARTED.md) | 5-minute quickstart guide for new users | Beginners |
| [**CLI_GUIDE.md**](CLI_GUIDE.md) | Command-line tool usage and examples | CLI Users |
| [**LSP_GUIDE.md**](LSP_GUIDE.md) | Language Server Protocol integration for IDEs | IDE Users/Developers |

### Core Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [**API_REFERENCE.md**](API_REFERENCE.md) | Complete API documentation with 4,400+ lines of examples | Developers |
| [**USAGE_GUIDE.md**](USAGE_GUIDE.md) | Detailed usage patterns, best practices, and real-world examples | All Users |
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System design, component architecture, and internal implementation | Contributors/Advanced |
| [**TROUBLESHOOTING.md**](TROUBLESHOOTING.md) | Common issues, error messages, debugging techniques, and FAQ | Support/Debug |
| [**LINTING_RULES.md**](LINTING_RULES.md) | Complete linting rules reference (L001-L010) with examples | Developers/QA |
| [**CONFIGURATION.md**](CONFIGURATION.md) | Configuration file (.gosqlx.yml) guide with all options | DevOps/Teams |

### Reference Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [**ERROR_CODES.md**](ERROR_CODES.md) | Comprehensive error code reference (E1xxx-E4xxx) | Developers |
| [**SQL_COMPATIBILITY.md**](SQL_COMPATIBILITY.md) | SQL dialect support matrix and feature compatibility | Architects |
| [**sql99-compliance-analysis.md**](sql99-compliance-analysis.md) | SQL-99 standard compliance analysis (~80-85%) | Architects |

### Deployment & Operations

| Document | Description | Audience |
|----------|-------------|----------|
| [**PRODUCTION_GUIDE.md**](PRODUCTION_GUIDE.md) | Production deployment, monitoring, and performance optimization | DevOps/SRE |
| [**PERFORMANCE_TUNING.md**](PERFORMANCE_TUNING.md) | Performance optimization and benchmarking guide | Performance Engineers |
| [**SECURITY.md**](SECURITY.md) | Security analysis, vulnerability assessment, and SQL injection detection | Security Teams |

### Testing & Quality

| Document | Description | Audience |
|----------|-------------|----------|
| [**FUZZ_TESTING_GUIDE.md**](FUZZ_TESTING_GUIDE.md) | Fuzz testing methodology and coverage | QA Engineers |
| [**performance_regression_testing.md**](performance_regression_testing.md) | Performance regression testing guide | QA Engineers |
| [**COMPARISON.md**](COMPARISON.md) | Comparison with other SQL parsers | Evaluators |

### Migration & Upgrade

| Document | Description |
|----------|-------------|
| [**UPGRADE_GUIDE.md**](UPGRADE_GUIDE.md) | Version upgrade guide with breaking changes |
| [**migration/FROM_JSQLPARSER.md**](migration/FROM_JSQLPARSER.md) | Migrating from JSqlParser |
| [**migration/FROM_PG_QUERY.md**](migration/FROM_PG_QUERY.md) | Migrating from pg_query |
| [**migration/FROM_SQLFLUFF.md**](migration/FROM_SQLFLUFF.md) | Migrating from SQLFluff |

### Tutorials

| Document | Description |
|----------|-------------|
| [**tutorials/01-sql-validator-cicd.md**](tutorials/01-sql-validator-cicd.md) | Building a SQL validator for CI/CD pipelines |
| [**tutorials/02-custom-sql-formatter.md**](tutorials/02-custom-sql-formatter.md) | Creating custom SQL formatters |

## Quick Start Guides

### For New Users
1. Start with [GETTING_STARTED.md](GETTING_STARTED.md) - 5-minute quickstart guide
2. Review [USAGE_GUIDE.md](USAGE_GUIDE.md) - Basic usage patterns
3. Check [CLI_GUIDE.md](CLI_GUIDE.md) - Command-line tool usage
4. Explore [Examples](../examples/) - Working code samples

### For Developers
1. Read [API_REFERENCE.md](API_REFERENCE.md) - Complete API docs (4,400+ lines)
2. Study [ARCHITECTURE.md](ARCHITECTURE.md) - System design and internals
3. Review [USAGE_GUIDE.md](USAGE_GUIDE.md#advanced-patterns) - Advanced patterns
4. Check [LINTING_RULES.md](LINTING_RULES.md) - SQL linting rules reference

### For IDE Integration
1. Follow [LSP_GUIDE.md](LSP_GUIDE.md) - Language Server Protocol setup
2. Review [CONFIGURATION.md](CONFIGURATION.md) - Project configuration
3. Check [LINTING_RULES.md](LINTING_RULES.md) - Available linting rules

### For Production Deployment
1. Follow [PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md) - Deployment best practices
2. Review [SECURITY.md](SECURITY.md) - Security considerations and SQL injection detection
3. Check [SQL_COMPATIBILITY.md](SQL_COMPATIBILITY.md) - SQL dialect support matrix
4. Study [PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md) - Optimization techniques

## Documentation Structure

```
docs/
├── README.md                          # This documentation index
├── GETTING_STARTED.md                 # 5-minute quickstart guide
├── CLI_GUIDE.md                       # CLI tool documentation
├── LSP_GUIDE.md                       # Language Server Protocol guide
├── API_REFERENCE.md                   # Complete API documentation (4,400+ lines)
├── USAGE_GUIDE.md                     # Usage patterns and examples
├── ARCHITECTURE.md                    # System architecture
├── TROUBLESHOOTING.md                 # Problem solving guide
├── LINTING_RULES.md                   # Linting rules reference (L001-L010)
├── CONFIGURATION.md                   # Configuration file guide (.gosqlx.yml)
├── PRODUCTION_GUIDE.md                # Production deployment
├── PERFORMANCE_TUNING.md              # Performance optimization
├── SQL_COMPATIBILITY.md               # SQL dialect matrix
├── SECURITY.md                        # Security analysis & injection detection
├── ERROR_CODES.md                     # Error code reference (E1xxx-E4xxx)
├── COMPARISON.md                      # Parser comparison
├── UPGRADE_GUIDE.md                   # Version upgrade guide
├── FUZZ_TESTING_GUIDE.md              # Fuzz testing guide
├── performance_regression_testing.md  # Performance regression testing
├── sql99-compliance-analysis.md       # SQL-99 compliance analysis
├── migration/                         # Migration guides
│   ├── FROM_JSQLPARSER.md
│   ├── FROM_PG_QUERY.md
│   └── FROM_SQLFLUFF.md
└── tutorials/                         # Hands-on tutorials
    ├── 01-sql-validator-cicd.md
    └── 02-custom-sql-formatter.md
```

## Finding Information

### By Topic

**Installation & Setup**
- [Installation](GETTING_STARTED.md#installation)
- [Quick Start](GETTING_STARTED.md#quick-start)
- [Prerequisites](PRODUCTION_GUIDE.md#prerequisites)
- [CLI Installation](CLI_GUIDE.md#installation)

**Basic Usage**
- [Simple Tokenization](USAGE_GUIDE.md#simple-tokenization)
- [Parsing to AST](USAGE_GUIDE.md#parsing-to-ast)
- [Error Handling](USAGE_GUIDE.md#error-handling-with-position-info)
- [CLI Commands](CLI_GUIDE.md#commands)

**v1.6.0 Features**
- [LSP Server Setup](LSP_GUIDE.md#getting-started)
- [Linting Configuration](LINTING_RULES.md#configuration)
- [PostgreSQL Extensions](USAGE_GUIDE.md#postgresql-specific-features)
- [Security Scanning](SECURITY.md#sql-injection-detection)
- [Configuration Files](CONFIGURATION.md#configuration-file-format)

**Advanced Topics**
- [Concurrent Processing](USAGE_GUIDE.md#concurrent-processing)
- [Memory Management](ARCHITECTURE.md#memory-management)
- [Performance Tuning](PERFORMANCE_TUNING.md#optimization-strategies)
- [Object Pooling](ARCHITECTURE.md#object-pooling-architecture)

**Troubleshooting**
- [Common Issues](TROUBLESHOOTING.md#common-issues)
- [Error Codes Reference](ERROR_CODES.md)
- [FAQ](TROUBLESHOOTING.md#faq)
- [Performance Issues](TROUBLESHOOTING.md#performance-issues)
- [Memory Issues](TROUBLESHOOTING.md#memory-issues)

**SQL Dialects**
- [PostgreSQL](SQL_COMPATIBILITY.md#postgresql)
- [MySQL](SQL_COMPATIBILITY.md#mysql)
- [SQL Server](SQL_COMPATIBILITY.md#sql-server)
- [Oracle](SQL_COMPATIBILITY.md#oracle)
- [SQLite](SQL_COMPATIBILITY.md#sqlite)
- [Dialect Comparison](SQL_COMPATIBILITY.md#feature-comparison-matrix)

### By Use Case

**"I want to tokenize SQL"**
→ See [USAGE_GUIDE.md - Simple Tokenization](USAGE_GUIDE.md#simple-tokenization)

**"I want to parse SQL to AST"**
→ See [USAGE_GUIDE.md - Parsing to AST](USAGE_GUIDE.md#parsing-to-ast)

**"I want to validate SQL syntax"**
→ See [CLI_GUIDE.md - Validate Command](CLI_GUIDE.md#validate-command)

**"I want to format SQL files"**
→ See [CLI_GUIDE.md - Format Command](CLI_GUIDE.md#format-command)

**"I want IDE integration"**
→ See [LSP_GUIDE.md - Getting Started](LSP_GUIDE.md#getting-started)

**"I want to lint SQL files"**
→ See [LINTING_RULES.md - Overview](LINTING_RULES.md#overview)

**"I want to detect SQL injection"**
→ See [SECURITY.md - SQL Injection Detection](SECURITY.md#sql-injection-detection)

**"I want to configure GoSQLX"**
→ See [CONFIGURATION.md - Configuration Guide](CONFIGURATION.md#configuration-file-format)

**"I want to support PostgreSQL features"**
→ See [USAGE_GUIDE.md - PostgreSQL Features](USAGE_GUIDE.md#postgresql-specific-features)

**"I want to support Unicode SQL"**
→ See [USAGE_GUIDE.md - Unicode Support](USAGE_GUIDE.md#unicode-and-international-support)

**"I'm getting an error"**
→ See [ERROR_CODES.md - Error Reference](ERROR_CODES.md)

**"My application is slow"**
→ See [PERFORMANCE_TUNING.md - Optimization](PERFORMANCE_TUNING.md#optimization-strategies)

**"I found a memory leak"**
→ See [TROUBLESHOOTING.md - Memory Issues](TROUBLESHOOTING.md#memory-issues)

**"I want to migrate from another parser"**
→ See [Migration Guides](migration/) - JSqlParser, pg_query, or SQLFluff

## Coverage Matrix

| Topic | Getting Started | Usage | API Ref | Architecture | Troubleshooting | Production |
|-------|----------------|-------|---------|--------------|-----------------|------------|
| Installation | ✓ | ✓ | ✓ | | | ✓ |
| Basic Usage | ✓ | ✓ | ✓ | | ✓ | |
| CLI Tool | ✓ | | | | | |
| LSP Server | ✓ | | | | | |
| Linting | | | | | | |
| Configuration | | | | | | |
| Advanced Patterns | | ✓ | ✓ | ✓ | | ✓ |
| Error Handling | | ✓ | ✓ | | ✓ | |
| Performance | | ✓ | | ✓ | ✓ | ✓ |
| Memory Management | | ✓ | ✓ | ✓ | ✓ | ✓ |
| Concurrency | | ✓ | ✓ | ✓ | ✓ | |
| SQL Dialects | | ✓ | | | ✓ | |
| PostgreSQL Features | | ✓ | ✓ | | | |
| Unicode Support | | ✓ | | | ✓ | |
| Security | | | | | | ✓ |
| Debugging | | | | | ✓ | |
| Monitoring | | | | | | ✓ |

**Legend**: ✓ = Covered in document | CLI = CLI_GUIDE.md | LSP = LSP_GUIDE.md | Linting = LINTING_RULES.md | Configuration = CONFIGURATION.md

## Contributing to Documentation

We welcome documentation improvements! To contribute:

1. **Fix Typos/Errors**: Direct PRs welcome
2. **Add Examples**: Include working code samples
3. **Improve Clarity**: Simplify complex explanations
4. **Add Diagrams**: Visual representations help
5. **Update for Changes**: Keep docs in sync with code

### Documentation Standards

- Use clear, concise language
- Include code examples for all features
- Provide both simple and advanced examples
- Cross-reference related documentation
- Keep formatting consistent
- Test all code examples

## Getting Help

If you can't find what you need:

1. **Search**: Use GitHub's search in the repository
2. **Issues**: Check [existing issues](https://github.com/ajitpratap0/GoSQLX/issues)
3. **Ask**: Open a [new issue](https://github.com/ajitpratap0/GoSQLX/issues/new)
4. **Discuss**: Join [discussions](https://github.com/ajitpratap0/GoSQLX/discussions)

## Documentation Updates

| Document | Last Updated | Version | Status |
|----------|--------------|---------|--------|
| README.md | 2025-12 | v1.6.0 | ✓ Updated |
| GETTING_STARTED.md | 2025-12 | v1.6.0 | ✓ Updated |
| CLI_GUIDE.md | 2025-12 | v1.6.0 | ✓ Updated |
| LSP_GUIDE.md | 2025-12 | v1.6.0 | ✓ New |
| LINTING_RULES.md | 2025-12 | v1.6.0 | ✓ New |
| CONFIGURATION.md | 2025-12 | v1.6.0 | ✓ New |
| API_REFERENCE.md | 2025-12 | v1.6.0 | ✓ Updated |
| USAGE_GUIDE.md | 2025-12 | v1.6.0 | ✓ Updated |
| ARCHITECTURE.md | 2025-12 | v1.6.0 | ✓ Updated |
| TROUBLESHOOTING.md | 2025-12 | v1.6.0 | ✓ Updated |
| PRODUCTION_GUIDE.md | 2025-12 | v1.6.0 | ✓ Updated |
| SQL_COMPATIBILITY.md | 2025-12 | v1.6.0 | ✓ Updated |
| SECURITY.md | 2025-12 | v1.6.0 | ✓ Updated |
| ERROR_CODES.md | 2025-12 | v1.6.0 | ✓ Updated |
| PERFORMANCE_TUNING.md | 2025-12 | v1.6.0 | ✓ Updated |
| UPGRADE_GUIDE.md | 2025-12 | v1.6.0 | ✓ Updated |

## Recent Feature Additions

### v1.6.0 (December 2025) - PostgreSQL Extensions & Developer Tools
- **LATERAL JOIN** - Correlated subqueries in FROM clause
- **JSON/JSONB Operators** - Full operator support (`->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`, `#-`)
- **DISTINCT ON** - PostgreSQL-specific row selection
- **FILTER Clause** - Conditional aggregation (SQL:2003)
- **Aggregate ORDER BY** - ORDER BY within aggregate functions
- **RETURNING Clause** - Return modified rows from DML statements
- **LSP Server** - Language Server Protocol for IDE integration
- **Linter** - 10 built-in linting rules (L001-L010) with auto-fix
- **Configuration** - YAML-based project configuration (.gosqlx.yml)
- **Enhanced CLI** - Improved format, analyze, and parse commands

### v1.5.0 - Advanced SQL Features
- **Window Functions** - ROW_NUMBER, RANK, DENSE_RANK, NTILE, LAG, LEAD, FIRST_VALUE, LAST_VALUE
- **Window Frames** - ROWS/RANGE with PRECEDING/FOLLOWING/CURRENT ROW
- **CTEs** - Common Table Expressions with recursive support
- **Set Operations** - UNION, EXCEPT, INTERSECT with proper precedence

### v1.4.0 - Enterprise Features
- **SQL Injection Detection** - `pkg/sql/security` package for pattern detection
- **MERGE Statements** - SQL Server/PostgreSQL MERGE support (SQL:2003 F312)
- **Grouping Sets** - ROLLUP, CUBE, GROUPING SETS (SQL-99 T431)
- **Materialized Views** - CREATE/DROP/REFRESH MATERIALIZED VIEW
- **Advanced Operators** - BETWEEN, IN, LIKE, IS NULL with full expression support
- **Subquery Support** - Scalar, table, correlated, EXISTS subqueries
- **NULLS FIRST/LAST** - ORDER BY with null ordering (SQL-99 F851)

## What's New in v1.6.0

### PostgreSQL Extensions
GoSQLX now supports advanced PostgreSQL-specific features:
- **LATERAL JOIN** for correlated subqueries in FROM clause
- **JSON/JSONB operators** with full operator support (`->`, `->>`, `@>`, `?`, etc.)
- **DISTINCT ON** for PostgreSQL-specific row selection
- **FILTER clause** for conditional aggregation
- **RETURNING clause** for INSERT/UPDATE/DELETE operations

### Developer Tools
Three major new tools for improved developer experience:
1. **LSP Server** - Full Language Server Protocol implementation for IDE integration
   - Real-time diagnostics and error detection
   - Hover information for SQL keywords and functions
   - Code completion for SQL keywords
   - Document formatting with intelligent indentation

2. **Linter** - SQL code quality enforcement with 10 built-in rules
   - L001-L010 rules covering style, naming, and best practices
   - Auto-fix capabilities for many rules
   - Configurable severity levels and rule exclusions

3. **Configuration** - Project-wide settings via `.gosqlx.yml`
   - Linting rule configuration
   - Formatting preferences
   - Security scanner settings
   - Per-project customization

### Enhanced CLI
The command-line tool now includes:
- Improved `format` command with better indentation
- Enhanced `analyze` command with detailed metrics
- `lsp` command for starting the Language Server
- Better error messages and diagnostics

### Production Improvements
- **Performance**: Maintained 1.38M+ ops/sec with new features
- **Thread Safety**: All new features validated race-free
- **Memory Efficiency**: Object pooling extended to new components
- **Documentation**: 3 new comprehensive guides (LSP, Linting, Configuration)

## Key Highlights

### Production-Ready
- **Thread-Safe**: Zero race conditions, validated with 20,000+ concurrent operations
- **High Performance**: 1.38M+ operations/second sustained, 1.5M peak
- **Memory Efficient**: 60-80% memory reduction with object pooling
- **Reliable**: 95%+ success rate on real-world SQL queries

### Comprehensive SQL Support
- **80-85% SQL-99 Compliance**: Window functions, CTEs, set operations
- **Multi-Dialect**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Advanced Features**: MERGE, GROUPING SETS, materialized views
- **Modern SQL**: Full window function and CTE support

### Developer-Focused
- **IDE Integration**: LSP server for VS Code, Neovim, and other editors
- **Code Quality**: Built-in linter with 10 customizable rules
- **Security**: SQL injection detection with severity classification
- **Flexibility**: YAML configuration for project-wide settings

---

*For the main project documentation, see the [root README](../README.md)*