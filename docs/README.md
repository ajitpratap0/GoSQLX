# GoSQLX Documentation

Comprehensive documentation for the GoSQLX SQL parsing SDK.

**Current Version**: v1.6.0 | **Last Updated**: December 2025

## Documentation Index

### Getting Started

| Document | Description | Audience |
|----------|-------------|----------|
| [**GETTING_STARTED.md**](GETTING_STARTED.md) | 5-minute quickstart guide for new users | Beginners |
| [**CLI_GUIDE.md**](CLI_GUIDE.md) | Command-line tool usage and examples | CLI Users |

### Core Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [**API_REFERENCE.md**](API_REFERENCE.md) | Complete API documentation with 4,400+ lines of examples | Developers |
| [**USAGE_GUIDE.md**](USAGE_GUIDE.md) | Detailed usage patterns, best practices, and real-world examples | All Users |
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System design, component architecture, and internal implementation | Contributors/Advanced |
| [**TROUBLESHOOTING.md**](TROUBLESHOOTING.md) | Common issues, error messages, debugging techniques, and FAQ | Support/Debug |

### Reference Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [**ERROR_CODES.md**](ERROR_CODES.md) | Comprehensive error code reference (E1xxx-E4xxx) | Developers |
| [**sql99-compliance-analysis.md**](sql99-compliance-analysis.md) | SQL-99 standard compliance analysis (~80-85%) | Architects |

### Deployment & Operations

| Document | Description | Audience |
|----------|-------------|----------|
| [**PRODUCTION_GUIDE.md**](PRODUCTION_GUIDE.md) | Production deployment, monitoring, and performance optimization | DevOps/SRE |
| [**PERFORMANCE_TUNING.md**](PERFORMANCE_TUNING.md) | Performance optimization and benchmarking guide | Performance Engineers |
| [**SQL_COMPATIBILITY.md**](SQL_COMPATIBILITY.md) | SQL dialect support matrix and feature compatibility | Architects |
| [**SECURITY.md**](SECURITY.md) | Security analysis, vulnerability assessment, and SQL injection detection | Security Teams |

### Testing & Quality

| Document | Description | Audience |
|----------|-------------|----------|
| [**FUZZ_TESTING_GUIDE.md**](FUZZ_TESTING_GUIDE.md) | Fuzz testing methodology and coverage | QA Engineers |
| [**performance_regression_testing.md**](performance_regression_testing.md) | Performance regression testing guide | QA Engineers |
| [**COMPARISON.md**](COMPARISON.md) | Comparison with other SQL parsers | Evaluators |

### Migration Guides

| Document | Description |
|----------|-------------|
| [**migration/FROM_JSQLPARSER.md**](migration/FROM_JSQLPARSER.md) | Migrating from JSqlParser |
| [**migration/FROM_PG_QUERY.md**](migration/FROM_PG_QUERY.md) | Migrating from pg_query |
| [**migration/FROM_SQLFLUFF.md**](migration/FROM_SQLFLUFF.md) | Migrating from SQLFluff |

## Quick Start Guides

### For New Users
1. Start with [USAGE_GUIDE.md](USAGE_GUIDE.md) - Basic usage patterns
2. Review [Examples](../examples/) - Working code samples
3. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md#faq) - Common questions

### For Developers
1. Read [API_REFERENCE.md](API_REFERENCE.md) - Complete API docs
2. Study [ARCHITECTURE.md](ARCHITECTURE.md) - System design
3. Review [USAGE_GUIDE.md](USAGE_GUIDE.md#advanced-patterns) - Advanced patterns

### For Production Deployment
1. Follow [PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md) - Deployment guide
2. Review [SECURITY.md](SECURITY.md) - Security considerations
3. Check [SQL_COMPATIBILITY.md](SQL_COMPATIBILITY.md) - Dialect support

## Documentation Structure

```
docs/
├── README.md               # This documentation index
├── GETTING_STARTED.md      # 5-minute quickstart guide
├── CLI_GUIDE.md            # CLI tool documentation
├── API_REFERENCE.md        # Complete API documentation (4,400+ lines)
├── USAGE_GUIDE.md          # Usage patterns and examples
├── ARCHITECTURE.md         # System architecture
├── TROUBLESHOOTING.md      # Problem solving guide
├── PRODUCTION_GUIDE.md     # Production deployment
├── PERFORMANCE_TUNING.md   # Performance optimization
├── SQL_COMPATIBILITY.md    # SQL dialect matrix
├── SECURITY.md             # Security analysis
├── ERROR_CODES.md          # Error code reference
├── COMPARISON.md           # Parser comparison
├── FUZZ_TESTING_GUIDE.md   # Fuzz testing guide
├── sql99-compliance-analysis.md  # SQL-99 compliance
└── migration/              # Migration guides
    ├── FROM_JSQLPARSER.md
    ├── FROM_PG_QUERY.md
    └── FROM_SQLFLUFF.md
```

## Finding Information

### By Topic

**Installation & Setup**
- [Installation](USAGE_GUIDE.md#installation)
- [Prerequisites](PRODUCTION_GUIDE.md#prerequisites)
- [Quick Start](../README.md#quick-start)

**Basic Usage**
- [Simple Tokenization](USAGE_GUIDE.md#simple-tokenization)
- [Parsing to AST](USAGE_GUIDE.md#parsing-to-ast)
- [Error Handling](USAGE_GUIDE.md#error-handling-with-position-info)

**Advanced Topics**
- [Concurrent Processing](USAGE_GUIDE.md#concurrent-processing)
- [Memory Management](ARCHITECTURE.md#memory-management)
- [Performance Tuning](PRODUCTION_GUIDE.md#performance-optimization)

**Troubleshooting**
- [Common Issues](TROUBLESHOOTING.md#common-issues)
- [Error Codes Reference](TROUBLESHOOTING.md#error-codes-reference)
- [FAQ](TROUBLESHOOTING.md#faq)

**SQL Dialects**
- [PostgreSQL](USAGE_GUIDE.md#postgresql-specific-features)
- [MySQL](USAGE_GUIDE.md#mysql-specific-features)
- [SQL Server](USAGE_GUIDE.md#sql-server-specific-features)
- [Oracle](USAGE_GUIDE.md#oracle-specific-features)

### By Use Case

**"I want to tokenize SQL"**
→ See [USAGE_GUIDE.md#simple-tokenization](USAGE_GUIDE.md#simple-tokenization)

**"I want to parse SQL to AST"**
→ See [USAGE_GUIDE.md#parsing-to-ast](USAGE_GUIDE.md#parsing-to-ast)

**"I want to validate SQL syntax"**
→ See [USAGE_GUIDE.md#sql-validator](USAGE_GUIDE.md#sql-validator)

**"I want to support Unicode SQL"**
→ See [USAGE_GUIDE.md#unicode-and-international-support](USAGE_GUIDE.md#unicode-and-international-support)

**"I'm getting an error"**
→ See [TROUBLESHOOTING.md#error-codes-reference](TROUBLESHOOTING.md#error-codes-reference)

**"My application is slow"**
→ See [TROUBLESHOOTING.md#performance-issues](TROUBLESHOOTING.md#performance-issues)

**"I found a memory leak"**
→ See [TROUBLESHOOTING.md#memory-issues](TROUBLESHOOTING.md#memory-issues)

## Coverage Matrix

| Topic | API Ref | Usage | Architecture | Troubleshooting | Production |
|-------|---------|-------|--------------|-----------------|------------|
| Installation | ✓ | ✓ | | | ✓ |
| Basic Usage | ✓ | ✓ | | ✓ | |
| Advanced Patterns | ✓ | ✓ | ✓ | | ✓ |
| Error Handling | ✓ | ✓ | | ✓ | |
| Performance | | ✓ | ✓ | ✓ | ✓ |
| Memory Management | ✓ | ✓ | ✓ | ✓ | ✓ |
| Concurrency | ✓ | ✓ | ✓ | ✓ | |
| SQL Dialects | | ✓ | | ✓ | |
| Unicode Support | | ✓ | | ✓ | |
| Debugging | | | | ✓ | |
| Monitoring | | | | | ✓ |
| Security | | | | | ✓ |

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

| Document | Last Updated | Version |
|----------|--------------|---------|
| API_REFERENCE.md | 2025-11 | v1.5.1 |
| GETTING_STARTED.md | 2025-11 | v1.5.1 |
| CLI_GUIDE.md | 2025-11 | v1.5.1 |
| USAGE_GUIDE.md | 2025-11 | v1.5.1 |
| ARCHITECTURE.md | 2025-11 | v1.5.1 |
| TROUBLESHOOTING.md | 2025-11 | v1.5.1 |
| PRODUCTION_GUIDE.md | 2025-11 | v1.5.1 |
| SQL_COMPATIBILITY.md | 2025-11 | v1.5.1 |
| SECURITY.md | 2025-11 | v1.5.1 |
| ERROR_CODES.md | 2025-11 | v1.5.1 |
| PERFORMANCE_TUNING.md | 2025-11 | v1.5.1 |

## Recent Feature Additions (v1.4+)

- **SQL Injection Detection** - `pkg/sql/security` package for pattern detection
- **MERGE Statements** - SQL Server/PostgreSQL MERGE support
- **Grouping Sets** - ROLLUP, CUBE, GROUPING SETS (SQL-99 T431)
- **Materialized Views** - CREATE/DROP/REFRESH MATERIALIZED VIEW
- **Table Partitioning** - PARTITION BY RANGE/LIST/HASH
- **Advanced Operators** - BETWEEN, IN, LIKE, IS NULL with full expression support
- **Subquery Support** - Scalar, table, correlated, EXISTS subqueries
- **NULLS FIRST/LAST** - ORDER BY with null ordering (SQL-99 F851)

---

*For the main project documentation, see the [root README](../README.md)*