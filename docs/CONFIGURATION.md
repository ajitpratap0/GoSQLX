# Configuration Guide

**Version**: v1.6.0
**Last Updated**: December 2025

GoSQLX provides a comprehensive configuration system through YAML configuration files.

## Quick Start

```bash
# Create .gosqlx.yml in your project root
gosqlx config init

# Validate your configuration
gosqlx config validate

# View your current configuration
gosqlx config show
```

### Example Configuration

```yaml
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 80

validate:
  dialect: postgresql
  strict_mode: false

output:
  format: auto
  verbose: false

analyze:
  security: true
  performance: true
  complexity: true
```

---

## Configuration Schema

### Complete Structure

```yaml
format:
  indent: <int>                 # Indentation size (0-8)
  uppercase_keywords: <bool>    # Convert keywords to uppercase
  max_line_length: <int>        # Maximum line length (0-500)
  compact: <bool>               # Use compact formatting

validate:
  dialect: <string>             # SQL dialect
  strict_mode: <bool>           # Enable strict validation
  recursive: <bool>             # Recursively process directories
  pattern: <string>             # File pattern for recursive processing
  security:
    max_file_size: <int>        # Maximum file size in bytes

output:
  format: <string>              # Output format
  verbose: <bool>               # Enable verbose output

analyze:
  security: <bool>              # Enable security analysis
  performance: <bool>           # Enable performance analysis
  complexity: <bool>            # Enable complexity analysis
  all: <bool>                   # Enable all analysis features
```

---

## Configuration Locations & Precedence

GoSQLX searches for configuration files in this order:

1. **CLI Flags** (highest priority)
2. **Current Directory**: `.gosqlx.yml`
3. **Home Directory**: `~/.gosqlx.yml`
4. **System-wide**: `/etc/gosqlx.yml`
5. **Built-in Defaults** (lowest priority)

---

## Default Values

### Format Configuration

| Option | Default | Type | Range |
|--------|---------|------|-------|
| `format.indent` | `2` | int | 0-8 |
| `format.uppercase_keywords` | `true` | bool | - |
| `format.max_line_length` | `80` | int | 0-500 |
| `format.compact` | `false` | bool | - |

### Validation Configuration

| Option | Default | Type | Options |
|--------|---------|------|---------|
| `validate.dialect` | `postgresql` | string | postgresql, mysql, sqlserver, oracle, sqlite, generic |
| `validate.strict_mode` | `false` | bool | - |
| `validate.recursive` | `false` | bool | - |
| `validate.pattern` | `*.sql` | string | Any glob pattern |
| `validate.security.max_file_size` | `10485760` | int | Bytes (10MB) |

### Output Configuration

| Option | Default | Type | Options |
|--------|---------|------|---------|
| `output.format` | `auto` | string | json, yaml, table, tree, auto |
| `output.verbose` | `false` | bool | - |

### Analyze Configuration

| Option | Default | Type | Purpose |
|--------|---------|------|---------|
| `analyze.security` | `true` | bool | SQL injection detection |
| `analyze.performance` | `true` | bool | Optimization suggestions |
| `analyze.complexity` | `true` | bool | Complexity metrics |
| `analyze.all` | `false` | bool | Enable all features |

---

## Configuration Options

### Format Options

#### `format.indent`

Number of spaces for indentation.

- **Range**: 0-8
- **Default**: 2

```yaml
format:
  indent: 4  # Use 4 spaces
```

#### `format.uppercase_keywords`

Convert SQL keywords to uppercase.

```yaml
format:
  uppercase_keywords: true  # SELECT, FROM, WHERE
  # or
  uppercase_keywords: false  # select, from, where
```

#### `format.max_line_length`

Maximum line length before wrapping.

- **Range**: 0-500 (0 = unlimited)
- **Default**: 80

```yaml
format:
  max_line_length: 120
```

#### `format.compact`

Use compact formatting with minimal whitespace.

```yaml
format:
  compact: true
```

### Validation Options

#### `validate.dialect`

SQL dialect for validation.

**Options**: `postgresql`, `mysql`, `sqlserver`, `oracle`, `sqlite`, `generic`

```yaml
validate:
  dialect: mysql
```

#### `validate.strict_mode`

Enable strict validation mode.

```yaml
validate:
  strict_mode: true  # Fail on any non-standard SQL
```

#### `validate.recursive`

Recursively process directories.

```yaml
validate:
  recursive: true
  pattern: "**/*.sql"  # All SQL files in all directories
```

#### `validate.security.max_file_size`

Maximum file size to process (bytes).

```yaml
validate:
  security:
    max_file_size: 52428800  # 50 MB
```

### Output Options

#### `output.format`

Output format for results.

**Options**: `json`, `yaml`, `table`, `tree`, `auto`

```yaml
output:
  format: json  # For CI/CD pipelines
```

#### `output.verbose`

Enable verbose output.

```yaml
output:
  verbose: true
```

### Analyze Options

```yaml
analyze:
  security: true     # SQL injection detection
  performance: true  # Optimization suggestions
  complexity: true   # Complexity metrics
  all: true          # Enable all (overrides above)
```

---

## CLI Commands

### Initialize Configuration

```bash
# Create .gosqlx.yml in current directory
gosqlx config init

# Create in specific location
gosqlx config init --path ~/.gosqlx.yml
```

### Validate Configuration

```bash
# Validate from default locations
gosqlx config validate

# Validate specific file
gosqlx config validate --file .gosqlx.yml
```

### Show Configuration

```bash
# Show current configuration (YAML)
gosqlx config show

# Show as JSON
gosqlx config show --format json
```

---

## Usage Examples

### Example 1: Minimal Development

```yaml
format:
  indent: 2

validate:
  dialect: postgresql
```

### Example 2: Team Configuration

```yaml
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 100

validate:
  dialect: postgresql
  strict_mode: false

output:
  format: table
```

### Example 3: CI/CD Pipeline

```yaml
format:
  indent: 2
  uppercase_keywords: true

validate:
  dialect: postgresql
  strict_mode: true

output:
  format: json
  verbose: false

analyze:
  all: true
```

### Example 4: Personal Preferences

Store in `~/.gosqlx.yml`:

```yaml
format:
  indent: 4
  uppercase_keywords: false
  compact: true

output:
  verbose: true
```

### Example 5: Enterprise MySQL

```yaml
format:
  indent: 4
  uppercase_keywords: true
  max_line_length: 120

validate:
  dialect: mysql
  strict_mode: true
  recursive: true
  pattern: "**/*.sql"
  security:
    max_file_size: 52428800

output:
  format: json

analyze:
  all: true
```

---

## Validation Rules

### Format Validation

| Option | Rule | Error |
|--------|------|-------|
| `indent` | 0-8 | "format.indent must be between 0 and 8" |
| `max_line_length` | 0-500 | "format.max_line_length must be between 0 and 500" |

### Dialect Validation

Valid values: `postgresql`, `mysql`, `sqlserver`, `oracle`, `sqlite`, `generic`

### Output Format Validation

Valid values: `json`, `yaml`, `table`, `tree`, `auto`

---

## Troubleshooting

### Configuration File Not Found

```bash
# Show which config is being used
gosqlx config show

# Validate your config file
gosqlx config validate --file .gosqlx.yml
```

### YAML Syntax Error

Common mistakes:

```yaml
# Wrong - missing quotes for glob patterns
validate:
  pattern: **/*.sql  # Error!

# Right - with quotes
validate:
  pattern: "**/*.sql"  # Correct

# Wrong - inconsistent indentation
format:
  indent: 2
 uppercase_keywords: true  # Error!

# Right - consistent indentation
format:
  indent: 2
  uppercase_keywords: true
```

### CLI Flags Not Overriding

CLI flags should always take highest priority:

```bash
# Override config file settings
gosqlx format --indent=4 --uppercase=false query.sql

# Or specify explicit config file
gosqlx format --config ~/custom-config.yml query.sql
```

---

## Best Practices

### 1. Project Configuration

Store `.gosqlx.yml` in project root and commit to git:

```bash
gosqlx config init
git add .gosqlx.yml
git commit -m "chore: add GoSQLX configuration"
```

### 2. Minimal Configuration

Only specify settings that differ from defaults:

```yaml
# Good - minimal
format:
  indent: 4

validate:
  dialect: mysql
```

### 3. Comment Your Configuration

```yaml
# Team uses 2-space indentation
format:
  indent: 2

# Target PostgreSQL for production
validate:
  dialect: postgresql
  strict_mode: true  # Enforce strict validation in CI/CD
```

### 4. Validate Before Committing

```bash
gosqlx config validate
gosqlx config show
git add .gosqlx.yml
git commit -m "config: update GoSQLX settings"
```

---

## Related Documentation

- [CLI Guide](CLI_GUIDE.md) - Complete CLI reference
- [Linting Rules](LINTING_RULES.md) - Linting rules reference
- [API Reference](API_REFERENCE.md) - Full API documentation

---

**Last Updated**: December 2025
**Version**: v1.6.0
