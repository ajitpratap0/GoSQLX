# config package

Unified configuration loading for the CLI, LSP and library defaults.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/config` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/config))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

The configuration package provides unified configuration management for GoSQLX.

## Types

### `Config`
```go
type Config struct {
    Linter   LinterConfig   // Linter settings
    Format   FormatConfig   // Formatting settings
    Dialect  string         // SQL dialect (postgresql, mysql, sqlite, etc.)
    MaxDepth int            // Maximum parsing depth
}
```

### `LinterConfig`
```go
type LinterConfig struct {
    Enabled bool              // Enable linting
    Rules   map[string]bool   // Rule enablement (L001, L002, etc.)
    Severity map[string]string // Rule severity overrides
}
```

### `FormatConfig`
```go
type FormatConfig struct {
    IndentSize        int  // Indent size (default: 2)
    UppercaseKeywords bool // Uppercase SQL keywords
    InsertFinalNewline bool // Insert newline at end of file
}
```

## Functions

### `Load(filename string) (*Config, error)`
Load configuration from file (.gosqlx.yml).

```go
cfg, err := config.Load(".gosqlx.yml")
if err != nil {
    log.Fatal(err)
}
```

### `LoadFromEnv() *Config`
Load configuration from environment variables.

```go
cfg := config.LoadFromEnv()
```

### `Default() *Config`
Get default configuration.

```go
cfg := config.Default()
```

## Configuration File Example

```yaml
# .gosqlx.yml
dialect: postgresql

linter:
  enabled: true
  rules:
    L001: true  # Trailing whitespace
    L002: true  # Mixed tabs/spaces
    L003: true  # Consecutive blank lines
    L004: true  # Indentation depth
    L005: true  # Line length
    L006: false # Column alignment (disabled)
    L007: true  # Keyword case
    L008: false # Comma placement (disabled)
    L009: true  # Aliasing consistency
    L010: true  # Redundant whitespace

  severity:
    L007: error  # Override: keyword case is error instead of warning

format:
  indent_size: 2
  uppercase_keywords: true
  insert_final_newline: true

max_depth: 100
```

**v1.6.0 Performance:**
- **22.5x faster config file loading** with caching (1302ns vs 29379ns)
- Thread-safe cache with automatic invalidation on file modification
