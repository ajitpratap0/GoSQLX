# Migrating from pg_query to GoSQLX

**Status:** Coming Soon

This guide will help you migrate from pg_query (Ruby/C FFI) to GoSQLX (Go).

## Key Differences

- **Language**: Ruby/C → Pure Go
- **Dependencies**: C library → Zero dependencies
- **Dialects**: PostgreSQL-only → Multi-dialect
- **Deployment**: Requires libpg_query → Single binary

## Migration Checklist

- [ ] Review feature comparison in [COMPARISON.md](../COMPARISON.md)
- [ ] Install GoSQLX library (pure Go, no C deps)
- [ ] Port Ruby code to Go
- [ ] Test on your PostgreSQL queries
- [ ] Consider multi-dialect benefits

## API Comparison

### Ruby (pg_query)

```ruby
result = PgQuery.parse("SELECT * FROM users")
tree = result.tree
# C library FFI calls
```

### Go (GoSQLX)

```go
ast, err := gosqlx.Parse("SELECT * FROM users")
// Pure Go, no FFI overhead
```

## Full Guide

Coming in v1.5.0 release.

For questions, see [GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions).
