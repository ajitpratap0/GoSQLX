# Upgrade Guide

This guide helps you upgrade between versions of GoSQLX.

---

## Upgrading to v1.5.0 from v1.4.0

**Release Date**: November 15, 2025
**Type**: Minor Release (Non-Breaking)
**Focus**: Test Coverage & Quality Assurance

### 🎯 Quick Summary

v1.5.0 is a **100% backward compatible** release focused on test coverage improvements. No code changes are required - this is a drop-in replacement for v1.4.0.

### ✅ What's New

**Test Coverage Improvements:**
- CLI Package: 63.3% coverage (was ~50%)
- Parser Package: 75.0% coverage (was 57.4%)
- Tokenizer Package: 76.5% coverage (was 60.0%)

**Quality Enhancements:**
- 3,094 lines of new test code
- 115+ real-world SQL queries validated
- Zero race conditions detected
- 95%+ success rate on production queries
- Full UTF-8 validation across 8 languages

**Code Quality:**
- 529 lines removed through refactoring
- Enhanced error messages
- Improved CLI command consistency

### 📦 Upgrade Steps

#### 1. Update Dependency

```bash
# Update to v1.5.0
go get -u github.com/ajitpratap0/GoSQLX@v1.5.0

# Update CLI tool (if installed)
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@v1.5.0
```

#### 2. Verify Installation

```bash
# Check version
go list -m github.com/ajitpratap0/GoSQLX
# Should show: github.com/ajitpratap0/GoSQLX v1.5.0

# Verify CLI (if installed)
gosqlx --version
```

#### 3. Run Tests

```bash
# Run your existing tests to ensure compatibility
go test ./...

# Optional: Run with race detection
go test -race ./...
```

### 🔄 Breaking Changes

**None!** This release is 100% backward compatible.

### 🆕 New Features to Leverage

While no code changes are required, you may want to take advantage of improved reliability:

1. **Enhanced Test Coverage**: Your usage patterns are now better validated by our comprehensive test suite

2. **International SQL Support**: Full confidence in UTF-8 handling for international applications

3. **Real-World Query Validation**: 115+ production queries tested means your queries are more likely to parse correctly

4. **CLI Reliability**: Enhanced CLI error messages and edge case handling

### ⚠️ Deprecations

**None.** All existing APIs and functionality remain fully supported.

### 📈 Performance Impact

**No performance regression** - all metrics maintained:
- Throughput: 1.38M+ ops/sec sustained (unchanged)
- Latency: <1μs for complex queries (unchanged)
- Memory: 60-80% reduction with pooling (unchanged)
- Scaling: Linear to 128+ cores (unchanged)

### 🐛 Bug Fixes

While no critical bugs were fixed, v1.5.0 includes:
- Enhanced edge case handling in CLI commands
- Improved UTF-8 character handling
- Better error messages for invalid SQL

### 📚 Documentation Updates

New documentation added:
- [RELEASE_NOTES_v1.5.0.md](RELEASE_NOTES_v1.5.0.md) - Comprehensive release notes
- [CLI_REFACTORING_SUMMARY.md](CLI_REFACTORING_SUMMARY.md) - CLI coverage details
- [PARSER_COVERAGE_SUMMARY.md](PARSER_COVERAGE_SUMMARY.md) - Parser test details
- [TOKENIZER_COVERAGE_SUMMARY.md](TOKENIZER_COVERAGE_SUMMARY.md) - Tokenizer test details
- Updated [CHANGELOG.md](CHANGELOG.md) with v1.5.0 release notes

### 🔗 Related Resources

- **Full Release Notes**: [RELEASE_NOTES_v1.5.0.md](RELEASE_NOTES_v1.5.0.md)
- **Pull Request**: [PR #85](https://github.com/ajitpratap0/GoSQLX/pull/85)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md#150---2025-11-15---phase-1-test-coverage-achievement)
- **Issues**: Report any issues at https://github.com/ajitpratap0/GoSQLX/issues

---

## Upgrading to v1.4.0 from v1.3.0

**Release Date**: September 7, 2025
**Type**: Minor Release
**Focus**: Production CLI & Performance

### Quick Summary

v1.4.0 introduces production-ready CLI tools and fixes a critical memory leak in the format command.

### Upgrade Steps

```bash
go get -u github.com/ajitpratap0/GoSQLX@v1.4.0
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@v1.4.0
```

### Breaking Changes

**None** - 100% backward compatible.

### New Features

- Production-ready CLI with validate, format, analyze, and parse commands
- Memory leak prevention in format command
- High-performance CLI (1.38M+ ops/sec validation, 2,600+ files/sec formatting)
- Multi-format output (JSON, YAML, table, tree)

### Bug Fixes

- Fixed critical memory leak in format command
- Enhanced error messages with file access validation

---

## Upgrading to v1.3.0 from v1.2.0

**Release Date**: September 4, 2025
**Type**: Minor Release
**Focus**: Window Functions

### Quick Summary

v1.3.0 adds complete SQL-99 window function support.

### Upgrade Steps

```bash
go get -u github.com/ajitpratap0/GoSQLX@v1.3.0
```

### Breaking Changes

**None** - 100% backward compatible.

### New Features

- Complete window function support (ROW_NUMBER, RANK, DENSE_RANK, NTILE)
- Analytic functions (LAG, LEAD, FIRST_VALUE, LAST_VALUE)
- PARTITION BY and ORDER BY support
- Window frame clauses (ROWS, RANGE)
- ~80-85% SQL-99 compliance achieved

---

## Upgrading to v1.2.0 from v1.1.0

**Release Date**: August 15, 2025
**Type**: Minor Release
**Focus**: CTEs & Set Operations

### Quick Summary

v1.2.0 adds Common Table Expressions (CTEs) and set operations support.

### Upgrade Steps

```bash
go get -u github.com/ajitpratap0/GoSQLX@v1.2.0
```

### Breaking Changes

**None** - 100% backward compatible.

### New Features

- Complete CTE support with RECURSIVE
- Set operations (UNION, UNION ALL, EXCEPT, INTERSECT)
- Multiple CTE definitions in single query
- ~70% SQL-92 compliance achieved

---

## Upgrading to v1.1.0 from v1.0.0

**Release Date**: January 3, 2025
**Type**: Minor Release
**Focus**: JOIN Support

### Quick Summary

v1.1.0 adds complete JOIN support across all JOIN types.

### Upgrade Steps

```bash
go get -u github.com/ajitpratap0/GoSQLX@v1.1.0
```

### Breaking Changes

**None** - 100% backward compatible.

### New Features

- Complete JOIN support (INNER, LEFT, RIGHT, FULL OUTER, CROSS, NATURAL)
- USING clause support (single-column)
- Enhanced error handling for JOIN operations

---

## Upgrading to v1.0.0 from v0.9.0

**Release Date**: December 1, 2024
**Type**: Major Release
**Focus**: Production Readiness

### Quick Summary

v1.0.0 is a **major release** with significant performance improvements and production-grade features.

### Upgrade Steps

```bash
go get -u github.com/ajitpratap0/GoSQLX@v1.0.0
```

### Breaking Changes

#### 1. Token Type Reorganization

Token type constants have been reorganized to prevent collisions.

**Action**: Review any code that directly references token type constants.

**Example**:
```go
// May need adjustment if you directly compare token types
if token.Type == token.SELECT { ... }
```

#### 2. Pool Usage Requirements

Object pooling now requires `defer` for proper cleanup.

**Action**: Always use `defer` when returning objects to pools.

**Example**:
```go
// REQUIRED pattern
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)  // MANDATORY
```

#### 3. Import Path Updates

Test helper imports may have changed.

**Action**: Update imports from test packages if used in your code.

### Performance Impact

**Major improvements** - you may need to adjust timeouts:
- +47% performance improvement over v0.9.0
- 2.2M operations/second throughput
- 8M tokens/second processing
- <200ns latency for simple queries

### Migration Checklist

- [ ] Update dependency to v1.0.0
- [ ] Review token type constant usage
- [ ] Add `defer` to all pool returns
- [ ] Update test helper imports
- [ ] Adjust performance timeouts if needed
- [ ] Run test suite to verify compatibility
- [ ] Deploy to staging environment
- [ ] Monitor performance metrics
- [ ] Deploy to production

---

## Need Help?

### Support Channels

- **Issues**: https://github.com/ajitpratap0/GoSQLX/issues
- **Discussions**: https://github.com/ajitpratap0/GoSQLX/discussions
- **Documentation**: https://pkg.go.dev/github.com/ajitpratap0/GoSQLX

### Common Upgrade Issues

**Q: My tests are failing after upgrade to v1.0.0**
A: Most likely a token type constant issue. Review the token type reorganization changes.

**Q: Getting memory issues after upgrade**
A: Ensure you're using `defer` with all pool returns. See pool usage examples in documentation.

**Q: Performance seems slower after upgrade**
A: This is unlikely - verify you're testing similar workloads. Contact us if issue persists.

**Q: Compatibility issues with Go version**
A: GoSQLX requires Go 1.24+. Update your Go version if needed.

---

## Version History

| Version | Release Date | Type | Key Changes |
|---------|--------------|------|-------------|
| **v1.5.0** | 2025-11-15 | Minor | Test Coverage: CLI 63.3%, Parser 75%, Tokenizer 76.5% |
| v1.4.0 | 2025-09-07 | Minor | Production CLI, Memory leak fixes |
| v1.3.0 | 2025-09-04 | Minor | Window Functions, ~80-85% SQL-99 |
| v1.2.0 | 2025-08-15 | Minor | CTEs, Set Operations, ~70% SQL-92 |
| v1.1.0 | 2025-01-03 | Minor | Complete JOIN support |
| v1.0.0 | 2024-12-01 | Major | Production ready, +47% performance |
| v0.9.0 | 2024-01-15 | Minor | Initial public release |

---

<div align="center">

**Questions or Issues?**
[Open an Issue](https://github.com/ajitpratap0/GoSQLX/issues/new) | [Start a Discussion](https://github.com/ajitpratap0/GoSQLX/discussions/new)

</div>
