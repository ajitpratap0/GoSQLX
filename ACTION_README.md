# GoSQLX GitHub Action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GoSQLX%20Validator-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=github)](https://github.com/marketplace/actions/gosqlx-sql-validator)
[![GitHub Release](https://img.shields.io/github/release/ajitpratap0/GoSQLX.svg?style=flat)](https://github.com/ajitpratap0/GoSQLX/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Ultra-fast SQL validation, linting, and formatting for your CI/CD pipelines. **100-1000x faster** than traditional SQL linters like SQLFluff.

## Features

- **Ultra-Fast Performance**: 1.38M+ operations/second, validate 100+ files in milliseconds
- **Multi-Dialect Support**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Comprehensive Validation**: Syntax checking with detailed error reporting
- **Format Checking**: Ensure consistent SQL formatting across your codebase
- **Security Analysis**: Basic SQL injection pattern detection (Phase 4)
- **Zero Configuration**: Works out of the box with intelligent defaults
- **Production Ready**: Race-free, memory-efficient with object pooling

## Performance Comparison

| Tool | Time (100 files) | Performance |
|------|-----------------|-------------|
| GoSQLX | ~100ms | ⚡ **Baseline** |
| SQLFluff | ~10-100s | 🐌 100-1000x slower |

## Quick Start

### Basic Usage

Add this to your workflow file (e.g., `.github/workflows/sql-validation.yml`):

```yaml
name: SQL Validation

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  validate-sql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate SQL files
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
          validate: true
          fail-on-error: true
```

### Validate with Format Checking

```yaml
- name: Validate and check formatting
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: 'queries/**/*.sql'
    validate: true
    format-check: true
    strict: true
    show-stats: true
```

### Multi-Dialect Validation

```yaml
- name: Validate PostgreSQL queries
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: 'postgresql/**/*.sql'
    dialect: 'postgresql'
    strict: true

- name: Validate MySQL queries
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: 'mysql/**/*.sql'
    dialect: 'mysql'
    strict: true
```

### With Custom Configuration

```yaml
- name: Validate with custom config
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
    config: '.gosqlx.yml'
    validate: true
    lint: true
```

## Configuration

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `files` | Glob pattern for SQL files | Yes | `**/*.sql` |
| `validate` | Enable SQL validation | No | `true` |
| `lint` | Enable SQL linting (Phase 4) | No | `false` |
| `format-check` | Check SQL formatting | No | `false` |
| `fail-on-error` | Fail build on errors | No | `true` |
| `config` | Path to config file | No | `` |
| `dialect` | SQL dialect to use | No | `` (auto-detect) |
| `strict` | Enable strict mode | No | `false` |
| `show-stats` | Show performance stats | No | `false` |
| `gosqlx-version` | GoSQLX version | No | `latest` |
| `working-directory` | Working directory | No | `.` |

### Outputs

| Output | Description |
|--------|-------------|
| `validated-files` | Number of files validated |
| `invalid-files` | Number of invalid files |
| `formatted-files` | Number of files needing formatting |
| `validation-time` | Total validation time (ms) |

### File Patterns

The `files` input supports glob patterns:

```yaml
# All SQL files recursively
files: '**/*.sql'

# Specific directory
files: 'queries/*.sql'

# Multiple patterns (use matrix)
files: '{migrations,queries}/**/*.sql'

# Single directory only
files: '*.sql'
```

## Advanced Examples

### Complete CI/CD Pipeline

```yaml
name: Complete SQL Validation

on:
  push:
    branches: [main, develop]
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  validate:
    name: SQL Validation & Formatting
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Validate SQL syntax
        uses: ajitpratap0/GoSQLX@v1
        id: validate
        with:
          files: '**/*.sql'
          validate: true
          strict: true
          show-stats: true
          fail-on-error: true

      - name: Check SQL formatting
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
          format-check: true
          fail-on-error: true

      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const output = `
            ### SQL Validation Results ✅

            - **Files Validated**: ${{ steps.validate.outputs.validated-files }}
            - **Invalid Files**: ${{ steps.validate.outputs.invalid-files }}
            - **Validation Time**: ${{ steps.validate.outputs.validation-time }}ms
            - **Throughput**: ${(${{ steps.validate.outputs.validated-files }} * 1000 / ${{ steps.validate.outputs.validation-time }}).toFixed(2)} files/sec

            GoSQLX completed validation in ${{ steps.validate.outputs.validation-time }}ms ⚡
            `;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            });
```

### Matrix Strategy for Multiple Dialects

```yaml
jobs:
  validate:
    name: Validate ${{ matrix.dialect }} SQL
    runs-on: ubuntu-latest

    strategy:
      matrix:
        dialect: [postgresql, mysql, sqlserver]
        include:
          - dialect: postgresql
            path: 'sql/postgresql/**/*.sql'
          - dialect: mysql
            path: 'sql/mysql/**/*.sql'
          - dialect: sqlserver
            path: 'sql/sqlserver/**/*.sql'

    steps:
      - uses: actions/checkout@v4

      - name: Validate ${{ matrix.dialect }} queries
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: ${{ matrix.path }}
          dialect: ${{ matrix.dialect }}
          strict: true
          show-stats: true
```

### Pre-commit Hook Alternative

Use as a faster alternative to traditional pre-commit SQL validation:

```yaml
name: Fast Pre-commit SQL Check

on:
  pull_request:
    paths:
      - '**.sql'

jobs:
  quick-validate:
    runs-on: ubuntu-latest
    timeout-minutes: 2  # Should complete in seconds

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed SQL files
        id: changed-files
        uses: tj-actions/changed-files@v40
        with:
          files: '**.sql'

      - name: Validate changed SQL files
        if: steps.changed-files.outputs.any_changed == 'true'
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: ${{ steps.changed-files.outputs.all_changed_files }}
          validate: true
          format-check: true
          strict: true
```

### Scheduled SQL Audit

```yaml
name: Weekly SQL Audit

on:
  schedule:
    - cron: '0 0 * * 0'  # Every Sunday at midnight
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Comprehensive SQL audit
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
          validate: true
          lint: true
          format-check: true
          strict: true
          show-stats: true
          fail-on-error: false  # Report but don't fail

      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sql-audit-report
          path: ${{ github.workspace }}
```

## Configuration File

Create a `.gosqlx.yml` file in your repository root for advanced configuration:

```yaml
# .gosqlx.yml
validate:
  dialect: postgresql
  strict_mode: true
  recursive: true
  pattern: "*.sql"

format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 100
  compact: false

analyze:
  security: true
  performance: true
  complexity: true
```

Then reference it in your workflow:

```yaml
- name: Validate with config
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
    config: '.gosqlx.yml'
```

## Badges

Add status badges to your README:

### Validation Status

```markdown
[![SQL Validation](https://github.com/USERNAME/REPO/workflows/SQL%20Validation/badge.svg)](https://github.com/USERNAME/REPO/actions)
```

### Custom Badge

```markdown
[![GoSQLX](https://img.shields.io/badge/validated%20with-GoSQLX-blue)](https://github.com/ajitpratap0/GoSQLX)
```

## Troubleshooting

### No SQL files found

If the action reports no files found:

1. Check your `files` pattern matches your repository structure
2. Ensure SQL files are committed to the repository
3. Try absolute patterns like `**/*.sql` instead of relative paths
4. Use `working-directory` if files are in a subdirectory

### Validation fails unexpectedly

1. Check the SQL dialect matches your queries (`dialect` input)
2. Try without `strict` mode first to see basic errors
3. Review error annotations in the Actions log
4. Test locally with `gosqlx validate <file>`

### Performance issues

1. Use specific file patterns instead of `**/*.sql` for large repos
2. Consider matrix strategy to parallelize validation
3. Cache GoSQLX binary (done automatically)
4. Use `changed-files` action to validate only modified files

## Local Testing

Test the action behavior locally:

```bash
# Install GoSQLX
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

# Validate files
gosqlx validate **/*.sql

# Check formatting
gosqlx format --check **/*.sql

# Run analysis
gosqlx analyze --all query.sql
```

## Contributing

We welcome contributions! Please see:

- [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
- [GitHub Issues](https://github.com/ajitpratap0/GoSQLX/issues) for bugs/features
- [Discussions](https://github.com/ajitpratap0/GoSQLX/discussions) for questions

## Performance Metrics

### Benchmark Results (v1.4.0)

- **Tokenization**: 8M tokens/second
- **Parsing**: 1.38M operations/second sustained, 1.5M peak
- **Validation**: <10ms for typical queries (50-500 characters)
- **Batch Processing**: 100+ files/second
- **Memory**: 60-80% reduction with object pooling

### Real-World Performance

| Repository Size | Files | Time | Throughput |
|----------------|-------|------|------------|
| Small (10 files) | 10 | <100ms | 100+ files/sec |
| Medium (100 files) | 100 | ~1s | 100+ files/sec |
| Large (1000 files) | 1000 | ~10s | 100+ files/sec |

## Version Compatibility

| Action Version | GoSQLX Version | Go Version |
|---------------|----------------|------------|
| v1.x | v1.4.0+ | 1.19+ |

## License

GNU Affero General Public License v3.0 (AGPL-3.0) - see [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [github.com/ajitpratap0/GoSQLX](https://github.com/ajitpratap0/GoSQLX)
- **Issues**: [GitHub Issues](https://github.com/ajitpratap0/GoSQLX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions)

## Acknowledgments

Built with:
- [GitHub Actions](https://github.com/features/actions)
- [Go](https://golang.org/)
- [Cobra CLI](https://github.com/spf13/cobra)

---

**Made with ⚡ by the GoSQLX team** | [View on GitHub Marketplace](https://github.com/marketplace/actions/gosqlx-sql-validator)
