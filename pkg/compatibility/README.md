# Backward Compatibility Test Suite

This package provides comprehensive backward compatibility testing for GoSQLX to ensure version-to-version stability and prevent regressions.

## Purpose

The backward compatibility test suite serves several critical functions:

1. **Regression Prevention**: Detect breaking changes before they reach production
2. **API Stability**: Ensure public interfaces remain stable across v1.x versions
3. **Query Compatibility**: Verify queries that worked in previous versions continue to work
4. **Safe Refactoring**: Enable confident code refactoring without breaking user code

## Test Structure

### 1. Compatibility Tests (`compatibility_test.go`)

Tests that verify queries working in previous versions continue to work:

- `TestBackwardCompatibility_v1_x`: Main regression test comparing current code against golden files
- `TestBackwardCompatibility_ExistingTestData`: Validates existing testdata still parses correctly

**Golden Files Structure**:
```
testdata/
├── v1.0.0/
│   └── queries.json      # Queries that worked in v1.0.0
├── v1.2.0/
│   └── queries.json      # Queries that worked in v1.2.0
├── v1.4.0/
│   └── queries.json      # Queries that worked in v1.4.0
└── v1.5.1/
    └── queries.json      # Queries that work in current version
```

**Golden File Format**:
```json
[
  {
    "name": "simple_select",
    "sql": "SELECT * FROM users",
    "dialect": "generic",
    "shouldPass": true,
    "description": "Basic SELECT statement",
    "addedVersion": "v1.0.0"
  }
]
```

### 2. API Stability Tests (`api_stability_test.go`)

Tests that ensure public API contracts remain unchanged:

- `TestAPIStability_PublicInterfaces`: Verifies interface methods haven't changed
- `TestAPIStability_PublicFunctions`: Checks function signatures remain stable
- `TestAPIStability_PoolBehavior`: Ensures object pool behavior is consistent
- `TestAPIStability_TokenTypes`: Validates token constants haven't changed
- `TestAPIStability_ParserOutput`: Confirms parser output structure is stable
- `TestAPIStability_ErrorHandling`: Verifies error handling remains consistent
- `TestAPIStability_ConcurrentUsage`: Ensures thread-safety is maintained

## Running Tests

```bash
# Run all compatibility tests
go test -v ./pkg/compatibility/

# Run specific test suite
go test -v -run TestBackwardCompatibility ./pkg/compatibility/
go test -v -run TestAPIStability ./pkg/compatibility/

# Run with race detection (recommended)
go test -race -v ./pkg/compatibility/

# Generate coverage report
go test -coverprofile=coverage.out ./pkg/compatibility/
go tool cover -html=coverage.out
```

## Adding New Golden Files

When releasing a new version:

1. Create directory for the version:
   ```bash
   mkdir -p pkg/compatibility/testdata/v1.6.0
   ```

2. Generate queries.json with all queries that should work:
   ```bash
   # Copy from previous version and add new queries
   cp pkg/compatibility/testdata/v1.5.1/queries.json \
      pkg/compatibility/testdata/v1.6.0/queries.json
   ```

3. Add new queries for features added in this version:
   ```json
   {
     "name": "new_feature_query",
     "sql": "SELECT ...",
     "dialect": "generic",
     "shouldPass": true,
     "description": "Description of new feature",
     "addedVersion": "v1.6.0"
   }
   ```

4. Run tests to verify:
   ```bash
   go test -v -run TestBackwardCompatibility_v1_6 ./pkg/compatibility/
   ```

## CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/ci.yml
- name: Backward Compatibility Tests
  run: |
    go test -v -race ./pkg/compatibility/
    if [ $? -ne 0 ]; then
      echo "::error::Backward compatibility broken - failing build"
      exit 1
    fi
```

## What Counts as a Breaking Change?

### Breaking Changes (Must NOT happen in v1.x):

1. **API Changes**:
   - Removing or renaming public functions
   - Changing function signatures
   - Removing or renaming interface methods
   - Changing struct field types in public structs

2. **Behavioral Changes**:
   - Queries that parsed successfully now fail
   - Different AST structure for same query
   - Changed error messages (if users depend on them)
   - Pool behavior changes

3. **Token Changes**:
   - Renaming token type constants
   - Changing token type values
   - Removing token types

### Non-Breaking Changes (Safe in v1.x):

1. **Additions**:
   - Adding new public functions
   - Adding new interface methods (with default implementations)
   - Adding new struct fields
   - Supporting new SQL syntax

2. **Internal Changes**:
   - Refactoring internal code
   - Performance improvements
   - Bug fixes that don't change behavior
   - Internal struct changes

3. **Enhancements**:
   - Better error messages
   - Additional validation
   - Performance optimizations

## Maintenance

### Regular Maintenance Tasks:

1. **After Each Release**:
   - Create golden files for the new version
   - Verify all tests pass
   - Update this README if test structure changes

2. **Monthly**:
   - Review failing queries in existing testdata
   - Update `shouldPass` flags if parser improves
   - Add more edge cases to golden files

3. **Before Major Refactoring**:
   - Run full compatibility test suite
   - Add additional golden files if needed
   - Verify tests pass after refactoring

## Test Coverage Goals

- **Compatibility Tests**: 100% of previously working queries
- **API Stability Tests**: 100% of public APIs
- **Edge Cases**: 90%+ coverage of error conditions

## Troubleshooting

### Test Failures

If backward compatibility tests fail:

1. **Identify the regression**:
   ```bash
   go test -v -run TestBackwardCompatibility_v1_5 ./pkg/compatibility/
   ```

2. **Review the failure**:
   - Is it a true regression (query that worked now fails)?
   - Is it a bug fix (query that should have failed now correctly fails)?
   - Is it a test data issue (incorrect golden file)?

3. **Fix the issue**:
   - **Regression**: Fix the code to restore compatibility
   - **Bug fix**: Update golden file with `shouldPass: false`
   - **Test issue**: Correct the golden file

### Adding Test Coverage

To add coverage for new SQL features:

1. Add query to latest version's `queries.json`
2. Set `shouldPass: true` if it works, `false` if not yet supported
3. Add `description` explaining the feature
4. Run tests to verify

## Version History

- **v1.5.1**: Initial backward compatibility test suite
  - 20 golden queries covering v1.0.0 - v1.5.1
  - API stability tests for public interfaces
  - Existing testdata validation
- **v1.5.0**: Phase 1-3 test coverage completed
- **v1.4.0**: Window functions and CTEs added
- **v1.2.0**: JOIN support added
- **v1.0.0**: Initial release with basic SQL support

## References

- [Semantic Versioning](https://semver.org/)
- [Go 1 Compatibility Promise](https://golang.org/doc/go1compat)
- [GoSQLX CHANGELOG.md](../../CHANGELOG.md)
- [GoSQLX API Reference](../../docs/API_REFERENCE.md)
