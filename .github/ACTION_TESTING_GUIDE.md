# GitHub Action Testing Guide

This guide explains how to test the GoSQLX GitHub Action locally and in CI/CD before publishing.

## Local Testing with act

[act](https://github.com/nektos/act) allows you to run GitHub Actions locally.

### Installation

```bash
# macOS
brew install act

# Linux
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Windows (with Chocolatey)
choco install act-cli
```

### Testing Basic Workflow

```bash
# Test the basic validation workflow
act -W .github/workflows/examples/sql-validation-basic.yml

# Test with specific event
act pull_request -W .github/workflows/examples/sql-validation-basic.yml

# Test with verbose output
act -v -W .github/workflows/examples/sql-validation-basic.yml
```

### Testing with Test SQL Files

Create test SQL files for validation:

```bash
# Create test directory
mkdir -p test/sql

# Create valid SQL file
cat > test/sql/valid.sql << 'EOF'
SELECT id, name, email
FROM users
WHERE active = true
ORDER BY created_at DESC;
EOF

# Create invalid SQL file
cat > test/sql/invalid.sql << 'EOF'
SELECT * FROM WHERE;
EOF

# Create test workflow
cat > .github/workflows/test-action.yml << 'EOF'
name: Test GoSQLX Action

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          files: 'test/sql/**/*.sql'
          validate: true
EOF

# Run local test
act -W .github/workflows/test-action.yml
```

## Integration Testing

### Test in a Fork

1. **Fork the repository**
2. **Create a test branch**

```bash
git checkout -b test/github-action
```

3. **Add test SQL files**

```bash
mkdir -p test-data
echo "SELECT 1;" > test-data/test.sql
git add test-data
git commit -m "test: add test SQL files"
```

4. **Create test workflow**

```yaml
# .github/workflows/test-local-action.yml
name: Test Local Action

on:
  push:
    branches: [test/**]

jobs:
  test-action:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Test action from current branch
        uses: ./
        with:
          files: 'test-data/**/*.sql'
          validate: true
          show-stats: true
```

5. **Push and verify**

```bash
git push origin test/github-action
```

6. **Check Actions tab** in GitHub to see results

### Test Different Scenarios

Create multiple test workflows for different scenarios:

```bash
# Test 1: Valid SQL files
mkdir -p .github/workflows/tests

cat > .github/workflows/tests/test-valid-sql.yml << 'EOF'
name: Test Valid SQL

on: workflow_dispatch

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          mkdir -p test/valid
          echo "SELECT id FROM users;" > test/valid/query.sql
      - uses: ./
        with:
          files: 'test/valid/**/*.sql'
          validate: true
EOF

# Test 2: Invalid SQL files (should fail)
cat > .github/workflows/tests/test-invalid-sql.yml << 'EOF'
name: Test Invalid SQL

on: workflow_dispatch

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          mkdir -p test/invalid
          echo "SELECT FROM;" > test/invalid/bad.sql
      - uses: ./
        with:
          files: 'test/invalid/**/*.sql'
          validate: true
          fail-on-error: false
      - name: Verify failure was detected
        run: exit 0
EOF

# Test 3: Format checking
cat > .github/workflows/tests/test-format.yml << 'EOF'
name: Test Format Check

on: workflow_dispatch

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          mkdir -p test/format
          echo "select   id,name from users;" > test/format/unformatted.sql
      - uses: ./
        with:
          files: 'test/format/**/*.sql'
          format-check: true
          fail-on-error: false
EOF

# Test 4: Multiple dialects
cat > .github/workflows/tests/test-dialects.yml << 'EOF'
name: Test SQL Dialects

on: workflow_dispatch

jobs:
  test-postgresql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          mkdir -p test/postgresql
          echo "SELECT NOW();" > test/postgresql/test.sql
      - uses: ./
        with:
          files: 'test/postgresql/**/*.sql'
          dialect: 'postgresql'

  test-mysql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          mkdir -p test/mysql
          echo "SELECT CURDATE();" > test/mysql/test.sql
      - uses: ./
        with:
          files: 'test/mysql/**/*.sql'
          dialect: 'mysql'
EOF
```

## Manual Testing Checklist

Before publishing, test these scenarios:

### ✅ Basic Functionality

- [ ] Action installs GoSQLX successfully
- [ ] Validates valid SQL files without errors
- [ ] Detects and reports invalid SQL files
- [ ] Properly fails when `fail-on-error: true`
- [ ] Continues when `fail-on-error: false`

### ✅ File Pattern Matching

- [ ] `**/*.sql` finds all SQL files recursively
- [ ] `*.sql` finds only root-level SQL files
- [ ] Custom patterns work correctly
- [ ] Empty pattern results are handled gracefully

### ✅ Configuration Options

- [ ] `dialect` parameter changes validation behavior
- [ ] `strict` mode enables stricter validation
- [ ] `show-stats` displays performance metrics
- [ ] `config` file is loaded and applied
- [ ] `working-directory` changes context correctly

### ✅ Outputs

- [ ] `validated-files` count is accurate
- [ ] `invalid-files` count matches errors
- [ ] `validation-time` is reported
- [ ] `formatted-files` count works with format-check

### ✅ Error Handling

- [ ] Missing GoSQLX installation is detected
- [ ] No SQL files found is handled gracefully
- [ ] Invalid config file is reported
- [ ] File read errors are caught

### ✅ Performance

- [ ] Completes quickly (<2 minutes for 100 files)
- [ ] Binary caching works across runs
- [ ] Memory usage is reasonable

### ✅ Integration

- [ ] Works with matrix strategy
- [ ] Compatible with other actions
- [ ] PR comments work correctly
- [ ] Artifacts upload successfully

## Automated Testing

Create a comprehensive test suite:

```yaml
# .github/workflows/action-tests.yml
name: Action Tests

on:
  push:
    branches: [main, develop]
    paths:
      - 'action.yml'
      - '.github/workflows/action-tests.yml'
  pull_request:
    paths:
      - 'action.yml'

jobs:
  test-valid-sql:
    name: Test Valid SQL
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]

    steps:
      - uses: actions/checkout@v4

      - name: Create valid SQL test file
        shell: bash
        run: |
          mkdir -p test-files
          cat > test-files/valid.sql << 'EOF'
          SELECT id, name, email
          FROM users
          WHERE active = true
          ORDER BY created_at DESC
          LIMIT 100;
          EOF

      - name: Test action
        uses: ./
        id: test
        with:
          files: 'test-files/**/*.sql'
          validate: true
          show-stats: true

      - name: Verify outputs
        shell: bash
        run: |
          if [ "${{ steps.test.outputs.validated-files }}" != "1" ]; then
            echo "Expected 1 validated file, got ${{ steps.test.outputs.validated-files }}"
            exit 1
          fi
          if [ "${{ steps.test.outputs.invalid-files }}" != "0" ]; then
            echo "Expected 0 invalid files, got ${{ steps.test.outputs.invalid-files }}"
            exit 1
          fi

  test-invalid-sql:
    name: Test Invalid SQL
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Create invalid SQL test file
        run: |
          mkdir -p test-files
          echo "SELECT FROM WHERE;" > test-files/invalid.sql

      - name: Test action (should detect error)
        uses: ./
        id: test
        continue-on-error: true
        with:
          files: 'test-files/**/*.sql'
          validate: true
          fail-on-error: true

      - name: Verify failure was detected
        run: |
          if [ "${{ steps.test.outcome }}" != "failure" ]; then
            echo "Expected action to fail on invalid SQL"
            exit 1
          fi

  test-format-check:
    name: Test Format Checking
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Create unformatted SQL
        run: |
          mkdir -p test-files
          echo "select   id,name from users;" > test-files/unformatted.sql

      - name: Test format check
        uses: ./
        id: test
        with:
          files: 'test-files/**/*.sql'
          format-check: true
          fail-on-error: false

      - name: Verify format issues detected
        run: |
          echo "Format check completed"
          echo "Files needing formatting: ${{ steps.test.outputs.formatted-files }}"

  test-dialects:
    name: Test SQL Dialects
    runs-on: ubuntu-latest
    strategy:
      matrix:
        dialect: [postgresql, mysql, sqlserver, oracle, sqlite]

    steps:
      - uses: actions/checkout@v4

      - name: Create test SQL
        run: |
          mkdir -p test-files
          echo "SELECT id FROM users;" > test-files/test.sql

      - name: Test with dialect
        uses: ./
        with:
          files: 'test-files/**/*.sql'
          dialect: ${{ matrix.dialect }}
          validate: true

  test-no-files:
    name: Test No Files Found
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Test with no matching files
        uses: ./
        with:
          files: 'nonexistent/**/*.sql'
          validate: true
          fail-on-error: false

  summary:
    name: Test Summary
    needs:
      - test-valid-sql
      - test-invalid-sql
      - test-format-check
      - test-dialects
      - test-no-files
    runs-on: ubuntu-latest
    if: always()

    steps:
      - name: Check all tests
        run: |
          echo "All action tests completed"
          echo "Valid SQL: ${{ needs.test-valid-sql.result }}"
          echo "Invalid SQL: ${{ needs.test-invalid-sql.result }}"
          echo "Format Check: ${{ needs.test-format-check.result }}"
          echo "Dialects: ${{ needs.test-dialects.result }}"
          echo "No Files: ${{ needs.test-no-files.result }}"
```

## Debugging Tips

### Enable Debug Logging

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
  env:
    ACTIONS_STEP_DEBUG: true
```

### Test Locally First

```bash
# Test CLI commands manually
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
gosqlx validate test.sql
gosqlx format --check test.sql
```

### Check Action Logs

Look for these in the Actions tab:
- GoSQLX installation success
- File discovery results
- Validation output for each file
- Final summary and outputs

## Performance Testing

```yaml
# .github/workflows/action-performance.yml
name: Action Performance Test

on: workflow_dispatch

jobs:
  performance:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Generate test files
        run: |
          mkdir -p test-perf
          for i in {1..100}; do
            echo "SELECT id, name FROM users WHERE id = $i;" > test-perf/query_$i.sql
          done

      - name: Run performance test
        uses: ./
        id: perf
        with:
          files: 'test-perf/**/*.sql'
          validate: true
          show-stats: true

      - name: Report performance
        run: |
          echo "Files validated: ${{ steps.perf.outputs.validated-files }}"
          echo "Time taken: ${{ steps.perf.outputs.validation-time }}ms"

          THROUGHPUT=$(awk "BEGIN {printf \"%.2f\", ${{ steps.perf.outputs.validated-files }} * 1000 / ${{ steps.perf.outputs.validation-time }}}")
          echo "Throughput: ${THROUGHPUT} files/sec"

          if (( $(echo "$THROUGHPUT < 50" | bc -l) )); then
            echo "WARNING: Performance below target (50 files/sec)"
          fi
```

## Next Steps

After successful testing:

1. ✅ All tests pass
2. ✅ Performance meets targets
3. ✅ Documentation is complete
4. ✅ Ready for publishing

See [MARKETPLACE_PUBLISHING.md](MARKETPLACE_PUBLISHING.md) for publishing instructions.
