# Migrating from JSQLParser to GoSQLX

**Status:** Coming Soon

This guide will help you migrate from JSQLParser (Java) to GoSQLX (Go).

## Key Differences

- **Language**: Java → Go
- **Performance**: 25-50x faster
- **Memory**: 50% less memory usage
- **API**: Simpler, more idiomatic

## Migration Checklist

- [ ] Review feature comparison in [COMPARISON.md](../COMPARISON.md)
- [ ] Install GoSQLX library
- [ ] Port Java code to Go
- [ ] Test AST parsing
- [ ] Verify dialect support

## API Comparison

### Java (JSQLParser)

```java
Statement stmt = CCJSqlParserUtil.parse(sql);
if (stmt instanceof Select) {
    Select select = (Select) stmt;
    SelectBody selectBody = select.getSelectBody();
    // ...
}
```

### Go (GoSQLX)

```go
ast, err := gosqlx.Parse(sql)
if err != nil {
    log.Fatal(err)
}
// ... simpler interface
```

## Full Guide

Coming in v1.5.0 release.

For questions, see [GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions).
