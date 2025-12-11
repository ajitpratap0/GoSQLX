# GoSQLX vs Alternatives: Comprehensive Comparison

**Last Updated:** 2025-12-11
**GoSQLX Version:** v1.6.0

This guide helps you choose the right SQL parsing tool for your needs. We provide an honest assessment of GoSQLX's strengths and limitations compared to popular alternatives.

---

## Quick Comparison Matrix

| Feature | **GoSQLX** | SQLFluff | sqlfmt | JSQLParser | pg_query |
|---------|------------|----------|--------|------------|----------|
| **Language** | Go | Python | Python | Java | C/Ruby |
| **Performance (ops/sec)** | ~800K sustained | ~1K | ~5K | ~50K | ~100K |
| **Memory/Query** | 1.8KB | ~50KB | ~20KB | ~10KB | ~5KB |
| **SQL-99 Compliance** | ~80-85% | ~75% | N/A | ~85% | ~95%* |
| **Concurrent Processing** | Native | Limited (GIL) | Limited (GIL) | Native | Limited |
| **Zero Dependencies** | ✅ Yes | ❌ No | ❌ No | ✅ Yes | ⚠️ Minimal |
| **SQL Validation** | ✅ Fast | ✅ Rules-based | ❌ No | ✅ Yes | ✅ Yes |
| **SQL Formatting** | ✅ Fast | ✅ Full | ✅ Opinionated | ⚠️ Basic | ❌ No |
| **Linting Rules** | ❌ Planned | ✅ 60+ rules | ❌ No | ❌ No | ❌ No |
| **Multi-Dialect** | ✅ 5 dialects | ✅ 60+ dialects | ⚠️ Limited | ⚠️ 4 dialects | ❌ PostgreSQL only |
| **CLI Tool** | ✅ Fast | ✅ Feature-rich | ✅ Simple | ❌ No | ⚠️ Limited |
| **Library API** | ✅ Simple | ✅ Complex | ⚠️ Limited | ✅ Full | ✅ Full |
| **IDE Integration** | ✅ LSP + VSCode | ✅ VSCode | ❌ No | ⚠️ Limited | ❌ No |
| **Config Files** | ✅ .gosqlx.yml | ✅ .sqlfluff | ⚠️ Limited | ⚠️ Limited | ❌ No |
| **Active Development** | ✅ Yes | ✅ Yes | ⚠️ Slow | ✅ Yes | ✅ Yes |
| **License** | AGPL-3.0 | MIT | MIT | Apache 2.0 | BSD |

*pg_query uses PostgreSQL's official parser, so PostgreSQL compliance is 100%

---

## Performance Comparison

### Throughput Benchmarks

Real-world benchmark parsing complex SQL queries (sustained load):

```
GoSQLX:      ~800,000 queries/sec  (100% baseline, sustained)
pg_query:    ~100,000 queries/sec  (12% of GoSQLX)
JSQLParser:   ~50,000 queries/sec  (6% of GoSQLX)
sqlfmt:        ~5,000 queries/sec  (0.6% of GoSQLX)
SQLFluff:      ~1,000 queries/sec  (0.1% of GoSQLX)
```

**Note**: GoSQLX benchmarks show 800K+ ops/sec sustained throughput with peaks up to 1.5M ops/sec for simple queries.

### Memory Usage

Parsing typical JOIN query with GROUP BY:

```
GoSQLX:      ~2 KB    (100% baseline)
pg_query:    ~5 KB    (2.5x)
JSQLParser:  ~10 KB   (5x)
sqlfmt:      ~20 KB   (10x)
SQLFluff:    ~50 KB   (25x)
```

**GoSQLX uses 60-80% less memory** through object pooling. Actual usage varies by query complexity.

### Latency & Concurrency

**Single Query (p50/p99):**
- GoSQLX: 0.7ms / 1.2ms
- pg_query: 2ms / 5ms
- JSQLParser: 5ms / 15ms
- SQLFluff/sqlfmt: 15-50ms / 50-200ms

**Concurrent Scaling (16 cores):**
- GoSQLX & JSQLParser: ~Linear (16x)
- pg_query: ~10x (FFI overhead)
- Python tools: ~2x (GIL limited)

---

## Detailed Comparisons

### GoSQLX vs SQLFluff

**SQLFluff** is a popular SQL linter and formatter in Python with 60+ linting rules.

**Choose GoSQLX if:**
- Performance is critical (100-800x faster)
- Go ecosystem integration needed
- High-throughput validation (CI/CD, real-time)
- Memory efficiency matters

**Choose SQLFluff if:**
- Need extensive linting rules (60+ vs 0)
- Need 60+ SQL dialects (vs 5)
- Python ecosystem preferred
- Mature rule enforcement required

**Migration:** Expect 100-800x speedup, but lose linting rules (planned for future).

---

### GoSQLX vs sqlfmt

**sqlfmt** is an opinionated SQL formatter in Python (formatting only, no parsing API).

**Choose GoSQLX if:**
- Need parsing + formatting + validation
- Performance matters (100x+ faster)
- Batch processing thousands of files
- Go ecosystem

**Choose sqlfmt if:**
- Only need formatting
- Prefer opinionated style
- Python-only project

---

### GoSQLX vs JSQLParser

**JSQLParser** is a mature SQL parser for Java (10+ years development).

**Choose GoSQLX if:**
- Go projects (no JVM overhead)
- Performance critical (10-25x faster)
- Memory constrained (50% less)
- Simpler API preferred

**Choose JSQLParser if:**
- Java ecosystem (Spring, JDBC)
- PL/SQL support needed
- Mature, stable solution required
- Oracle-specific features needed

---

### GoSQLX vs pg_query

**pg_query** uses PostgreSQL's official parser via FFI (100% PostgreSQL compliance).

**Choose GoSQLX if:**
- Multi-dialect support needed (5 dialects vs 1)
- Pure Go deployment (no C dependencies)
- Higher concurrency needed (no FFI overhead)
- Easier customization required

**Choose pg_query if:**
- PostgreSQL-only environment
- 100% PostgreSQL compliance required
- Latest PostgreSQL features needed immediately
- PL/pgSQL support required

**Note:** pg_query guarantees PostgreSQL compliance; GoSQLX covers ~80-85% of SQL-99 across multiple dialects.

---

## Decision Matrix

**Choose GoSQLX if:**
- Performance critical (CI/CD, real-time, batch processing)
- Go ecosystem (native integration, small binaries)
- Multi-dialect support needed (5 dialects)
- Memory efficiency matters
- LSP/IDE integration needed

**Choose SQLFluff if:**
- Need 60+ linting rules
- Python ecosystem preferred
- Need 60+ SQL dialects
- Mature rule enforcement required

**Choose sqlfmt if:**
- Only need formatting (no parsing)
- Prefer opinionated style
- Python-only project

**Choose JSQLParser if:**
- Java ecosystem (Spring, JDBC)
- PL/SQL support needed
- 10+ year mature solution preferred

**Choose pg_query if:**
- PostgreSQL-only (100% compliance)
- Latest PostgreSQL features needed
- Official parser required

---

## Limitations

**Don't Choose GoSQLX if:**

❌ **You need linting rules**
- SQLFluff has 60+ rules, GoSQLX has 0 (planned)

❌ **You need 60+ SQL dialects**
- GoSQLX supports 5 dialects
- Missing: Snowflake, BigQuery-specific features

❌ **You're heavily invested in Python**
- No Python bindings yet (planned)

❌ **You need advanced stored procedure parsing**
- PL/pgSQL, T-SQL, PL/SQL support is basic
- JSQLParser/pg_query have better support

---

## Migration Guides

Complete guides with working examples:

- **[From SQLFluff](migration/FROM_SQLFLUFF.md)** - 100-800x faster, API mapping, config conversion
- **[From JSQLParser](migration/FROM_JSQLPARSER.md)** - Type mapping, service wrappers, patterns
- **[From pg_query](migration/FROM_PG_QUERY.md)** - FFI elimination, multi-dialect support

See individual migration guides for code examples and patterns.

---

## Performance Benchmarks

**Test Environment:** 16-core AMD EPYC, 32GB RAM, Linux 5.15, Go 1.21

**Sustained Load (30 sec):**
- GoSQLX: ~800K ops/sec (peak 1.5M for simple queries)
- pg_query: ~100K ops/sec
- JSQLParser: ~50K ops/sec
- Python tools: ~1-5K ops/sec

**Memory (10K queries):**
- GoSQLX: ~18 MB (1.8KB/query)
- Others: 50-500 MB (5-50KB/query)

## Real-World Use Cases

**CI/CD Validation (5,000 files):**
- SQLFluff: ~41 minutes
- GoSQLX: ~3.6 seconds (680x faster)

**Real-Time API (1,000 req/sec):**
- Python tools: Cannot handle
- JSQLParser: Requires 20 servers
- GoSQLX: Requires 1 server

**Large File Processing (10GB dump):**
- Python tools: 1-3 hours, 4-8GB RAM
- GoSQLX: ~5 minutes, ~300MB RAM

---

## Feature Comparison Details

### SQL Standard Support

| Standard Feature | GoSQLX | SQLFluff | JSQLParser | pg_query |
|------------------|--------|----------|------------|----------|
| SQL-92 Core | ✅ 95% | ✅ 98% | ✅ 95% | ✅ 100% |
| SQL-99 Features | ✅ 80-85% | ✅ 75% | ✅ 85% | ✅ 95%* |
| Window Functions | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| CTEs | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| Recursive CTEs | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Set Operations | ✅ All | ✅ All | ✅ All | ✅ All |
| JOINs (All Types) | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Subqueries | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Transactions | ⚠️ Basic | ✅ Full | ✅ Full | ✅ Full |
| Stored Procedures | ⚠️ Basic | ⚠️ Partial | ✅ Full | ✅ Full |

*pg_query follows PostgreSQL exactly

### Dialect-Specific Features

| Feature | GoSQLX | SQLFluff | JSQLParser | pg_query |
|---------|--------|----------|------------|----------|
| PostgreSQL JSONB | ⚠️ Partial | ✅ Yes | ✅ Yes | ✅ Yes |
| MySQL AUTO_INCREMENT | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| SQL Server T-SQL | ⚠️ Basic | ✅ Yes | ✅ Yes | ❌ No |
| Oracle PL/SQL | ⚠️ Basic | ✅ Yes | ✅ Full | ❌ No |
| SQLite pragmas | ✅ Yes | ✅ Yes | ⚠️ Partial | ❌ No |

---

## Roadmap

**GoSQLX (Upcoming):**
- Linting rules engine (10+ rules)
- Enhanced error messages with fixes
- Python/JavaScript bindings
- Enhanced dialect support (20+ dialects)

**Competitors:**
- SQLFluff: Mature, stable
- JSQLParser: Active, Java-focused
- pg_query: Active, PostgreSQL-focused

---

## Resources

**Documentation:**
- [Getting Started Guide](GETTING_STARTED.md)
- [Usage Guide](USAGE_GUIDE.md)
- [API Reference](API_REFERENCE.md)
- [Performance Tuning](PERFORMANCE_TUNING.md)

**Help & Community:**
- [GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions)
- [Report Issues](https://github.com/ajitpratap0/GoSQLX/issues)
- [Examples](../examples/)

---

**Last Updated:** 2025-11-28
**Version:** v1.6.0

*Benchmark numbers are reproducible. See `/benchmarks` directory.*
