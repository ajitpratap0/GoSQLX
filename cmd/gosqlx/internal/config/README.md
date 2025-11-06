# GoSQLX Configuration Package

This package provides configuration file support for the GoSQLX CLI, enabling persistent settings and team-wide consistency.

## Overview

The configuration system allows users to define default settings for all CLI commands through YAML configuration files. This reduces the need for repetitive command-line flags and ensures consistent behavior across team members.

## Features

- **Multiple configuration locations** with precedence chain
- **CLI flag override** - command-line flags always take priority
- **Schema validation** - ensures configuration correctness
- **Partial configuration** - only specify settings you want to change
- **Template generation** - create configuration files with sensible defaults
- **Type safety** - strongly-typed Go structs with validation

## Configuration Locations

Configuration files are searched in the following order (highest priority first):

1. **Current directory**: `.gosqlx.yml`
2. **Home directory**: `~/.gosqlx.yml`
3. **System-wide**: `/etc/gosqlx.yml`
4. **Built-in defaults**: Hardcoded sensible defaults

## Configuration Schema

```go
type Config struct {
    Format     FormatConfig     // SQL formatting options
    Validation ValidationConfig // SQL validation options
    Output     OutputConfig     // Output formatting options
    Analyze    AnalyzeConfig    // Analysis feature options
}
```

### Format Configuration

```go
type FormatConfig struct {
    Indent            int  // Indentation size (0-8 spaces)
    UppercaseKeywords bool // Convert keywords to uppercase
    MaxLineLength     int  // Maximum line length (0-500, 0=unlimited)
    Compact           bool // Use compact formatting
}
```

### Validation Configuration

```go
type ValidationConfig struct {
    Dialect    string // SQL dialect (postgresql, mysql, sqlserver, oracle, sqlite, generic)
    StrictMode bool   // Enable strict validation
    Recursive  bool   // Recursively process directories
    Pattern    string // File pattern for recursive processing
}
```

### Output Configuration

```go
type OutputConfig struct {
    Format  string // Output format (json, yaml, table, tree, auto)
    Verbose bool   // Enable verbose output
}
```

### Analyze Configuration

```go
type AnalyzeConfig struct {
    Security    bool // Enable security analysis
    Performance bool // Enable performance analysis
    Complexity  bool // Enable complexity analysis
    All         bool // Enable all analysis features
}
```

## Usage

### Loading Configuration

```go
import "github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"

// Load from default locations (with precedence)
cfg, err := config.LoadDefault()
if err != nil {
    // Handle error
}

// Load from specific file
cfg, err := config.Load("/path/to/config.yml")
if err != nil {
    // Handle error
}

// Create default configuration
cfg := config.DefaultConfig()
```

### Saving Configuration

```go
cfg := config.DefaultConfig()
cfg.Format.Indent = 4
cfg.Validation.Dialect = "mysql"

err := cfg.Save(".gosqlx.yml")
if err != nil {
    // Handle error
}
```

### Validating Configuration

```go
cfg, err := config.Load("config.yml")
if err != nil {
    // Handle error
}

// Validate configuration values
err = cfg.Validate()
if err != nil {
    // Configuration is invalid
    fmt.Printf("Invalid configuration: %v\n", err)
}
```

### Merging Configurations

```go
// Load base configuration
base := config.DefaultConfig()

// Create override configuration (e.g., from CLI flags)
override := &config.Config{
    Format: config.FormatConfig{
        Indent: 4,
    },
}

// Merge (override takes precedence)
base.Merge(override)
```

## CLI Commands

### Initialize Configuration

```bash
# Create .gosqlx.yml in current directory
gosqlx config init

# Create config in specific location
gosqlx config init --path ~/.gosqlx.yml
```

### Validate Configuration

```bash
# Validate default config location
gosqlx config validate

# Validate specific file
gosqlx config validate --file /path/to/config.yml
```

### Show Configuration

```bash
# Show current configuration as YAML
gosqlx config show

# Show as JSON
gosqlx config show --format json

# Show specific config file
gosqlx config show --file /path/to/config.yml
```

## Example Configurations

### Minimal Configuration

```yaml
# Only specify what you want to change
format:
  indent: 4

validate:
  dialect: mysql
```

### Team Configuration

```yaml
# .gosqlx.yml - Project root configuration
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 100

validate:
  dialect: postgresql
  strict_mode: true
  recursive: false
  pattern: "*.sql"

output:
  format: table
  verbose: false

analyze:
  security: true
  performance: true
  complexity: true
  all: false
```

### CI/CD Configuration

```yaml
# Optimized for continuous integration
format:
  indent: 2
  uppercase_keywords: true
  max_line_length: 80
  compact: false

validate:
  dialect: postgresql
  strict_mode: true

output:
  format: json  # Machine-readable output
  verbose: false

analyze:
  all: true  # Comprehensive analysis
```

### Personal Configuration

```yaml
# ~/.gosqlx.yml - Personal preferences
format:
  indent: 4
  uppercase_keywords: false
  compact: true

output:
  verbose: true  # Always show details
```

## Configuration Precedence

When multiple configuration sources exist, settings are merged with this precedence (highest to lowest):

1. **CLI flags** - Explicit command-line arguments
2. **Current directory** - `.gosqlx.yml` in working directory
3. **Home directory** - `~/.gosqlx.yml` in user's home
4. **System-wide** - `/etc/gosqlx.yml` (Linux/macOS)
5. **Built-in defaults** - Hardcoded in the application

### Example

Given these configurations:

**~/.gosqlx.yml** (home):
```yaml
format:
  indent: 4
  uppercase_keywords: true
```

**.gosqlx.yml** (current):
```yaml
format:
  indent: 2
```

**CLI command**:
```bash
gosqlx format --uppercase=false query.sql
```

**Effective configuration**:
- `indent: 2` (from current directory)
- `uppercase_keywords: false` (from CLI flag)
- All other settings from defaults

## Validation Rules

The package validates configuration values to ensure correctness:

- **indent**: Must be between 0 and 8
- **max_line_length**: Must be between 0 and 500
- **dialect**: Must be one of: postgresql, mysql, sqlserver, oracle, sqlite, generic
- **output.format**: Must be one of: json, yaml, table, tree, auto

## Testing

The package includes comprehensive tests:

```bash
# Run all config tests
go test ./cmd/gosqlx/internal/config/

# Run with coverage
go test -cover ./cmd/gosqlx/internal/config/

# Run specific test
go test -run TestLoadDefault ./cmd/gosqlx/internal/config/
```

## Schema Validation

The `schema.go` file defines the complete configuration schema with validation functions:

```go
import "github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"

// Validate individual settings
err := config.ValidateDialect("mysql")
err = config.ValidateIndent(4)
err = config.ValidateOutputFormat("json")
err = config.ValidateMaxLineLength(100)

// Get schema information
schema := config.GetSchema()
fmt.Printf("Valid dialects: %v\n", schema.Validation.Dialect.Options)
```

## Integration with CLI Commands

All CLI commands automatically integrate with the configuration system:

```go
// In a CLI command handler
func commandRun(cmd *cobra.Command, args []string) error {
    // Load configuration
    cfg, err := config.LoadDefault()
    if err != nil {
        cfg = config.DefaultConfig()
    }

    // Override with CLI flags if explicitly set
    if cmd.Flags().Changed("indent") {
        cfg.Format.Indent = indentFlag
    }

    // Use configuration
    formatter := NewFormatter(cfg.Format)
    // ...
}
```

## Best Practices

1. **Project configuration**: Place `.gosqlx.yml` in project root for team consistency
2. **Personal overrides**: Use `~/.gosqlx.yml` for personal preferences
3. **CI/CD**: Use explicit CLI flags in CI pipelines for clarity
4. **Validation**: Always run `gosqlx config validate` after editing config files
5. **Documentation**: Comment your config files to explain choices
6. **Version control**: Commit `.gosqlx.yml` to git for team sharing
7. **Minimal config**: Only specify settings that differ from defaults

## Error Handling

The package provides clear error messages for common issues:

```go
// File not found - falls back to defaults
cfg, err := config.Load("nonexistent.yml")
// err: "failed to read config file: no such file or directory"

// Invalid YAML syntax
cfg, err := config.Load("malformed.yml")
// err: "failed to parse config file: yaml: ..."

// Invalid values
err := cfg.Validate()
// err: "format.indent must be between 0 and 8, got 15"

// Invalid dialect
cfg.Validation.Dialect = "unknown"
err = cfg.Validate()
// err: "validate.dialect must be one of: [postgresql mysql ...], got 'unknown'"
```

## Template File

The package includes a template configuration file (`template.yml`) with:
- Comprehensive comments
- All available options
- Sensible defaults
- Usage examples

This template is automatically used by `gosqlx config init`.

## Performance

The configuration system is designed for efficiency:
- **Fast loading**: YAML parsing is optimized
- **Cached defaults**: Default config is reused
- **Minimal overhead**: Configuration loading adds <1ms to startup
- **No hot reloading**: Config is loaded once per command execution

## Thread Safety

All configuration operations are thread-safe:
- Read operations can be performed concurrently
- Each command gets its own config instance
- No shared mutable state

## Future Enhancements

Planned improvements for future releases:
- Environment variable overrides
- Configuration validation on file change
- IDE integration for config autocomplete
- Configuration profiles (dev, staging, prod)
- Remote configuration support

## Contributing

When adding new configuration options:
1. Update the struct types in `config.go`
2. Add validation in `Validate()` method
3. Update schema in `schema.go`
4. Add tests in `config_test.go`
5. Update template in `template.yml`
6. Update documentation

## License

This package is part of GoSQLX and is licensed under the MIT License.
