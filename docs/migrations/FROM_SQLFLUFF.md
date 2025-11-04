# Migrating from SQLFluff to GoSQLX

**Status:** Coming Soon

This guide will help you migrate from SQLFluff (Python) to GoSQLX (Go).

## Key Differences

- **Language**: Python → Go
- **Performance**: ~1000x faster
- **Memory**: 95% less memory usage
- **Linting**: SQLFluff has 60+ rules, GoSQLX rules coming in v1.5.0

## Migration Checklist

- [ ] Review feature comparison in [COMPARISON.md](../COMPARISON.md)
- [ ] Install GoSQLX CLI or library
- [ ] Update CI/CD scripts
- [ ] Test validation on your SQL files
- [ ] Configure formatting style

## Quick Examples

### Validation

```bash
# SQLFluff
sqlfluff lint query.sql

# GoSQLX
gosqlx validate query.sql
```

### Formatting

```bash
# SQLFluff
sqlfluff fix query.sql

# GoSQLX
gosqlx format -i query.sql
```

## Full Guide

Coming in v1.5.0 release.

For questions, see [GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions).
