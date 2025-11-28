# Config Package

Unified configuration management for GoSQLX that can be shared across CLI, LSP server, and VSCode extension.

## Features

- **Multiple Sources**: Load configuration from files (YAML/JSON), environment variables, and LSP initialization options
- **Layered Configuration**: Merge configurations with proper precedence (defaults → file → environment → LSP/CLI flags)
- **Validation**: Comprehensive validation for all configuration options
- **LSP Integration**: First-class support for Language Server Protocol configuration exchange
- **Type Safety**: Strongly-typed configuration with sensible defaults

## Usage

### Loading from Files

```go
import "github.com/ajitpratap0/GoSQLX/pkg/config"

// Load from single file
cfg, err := config.LoadFromFile("gosqlx.yaml")
if err != nil {
    log.Fatal(err)
}

// Try multiple paths in order
cfg, err := config.LoadFromFiles([]string{
    "./gosqlx.yaml",
    "~/.config/gosqlx/config.yaml",
    "/etc/gosqlx/config.yaml",
})

// Get default search paths
paths := config.GetDefaultConfigPaths()
cfg, err := config.LoadFromFiles(paths)
```

### Loading from Environment Variables

```go
// Load from environment (GOSQLX_* variables)
cfg, err := config.LoadFromEnvironment("GOSQLX")

// Custom prefix
cfg, err := config.LoadFromEnvironment("MYAPP")
```

Environment variable names follow the pattern: `PREFIX_SECTION_FIELD`

Examples:
- `GOSQLX_FORMAT_INDENT=4`
- `GOSQLX_VALIDATION_DIALECT=postgresql`
- `GOSQLX_LSP_TRACE_SERVER=verbose`

### Layered Configuration

```go
// Load with automatic layering: defaults → file → environment
cfg, err := config.LoadWithDefaults("gosqlx.yaml", true)

// Manual merging for custom scenarios
defaultCfg := config.DefaultConfig()
fileCfg, _ := config.LoadFromFile("config.yaml")
envCfg, _ := config.LoadFromEnvironment("GOSQLX")

// Later configs override earlier ones
merged := config.Merge(defaultCfg, fileCfg, envCfg)
```

### LSP Integration

```go
// Load from LSP initialization options
cfg, err := config.LoadFromLSPInitOptions(initOptions)

// Convert to LSP settings format for VSCode
settings := config.ToLSPSettings(cfg)

// Parse from VSCode settings.json format
cfg, err := config.FromLSPSettings(settings)

// Merge LSP configuration changes
updated, err := config.MergeLSPConfig(baseCfg, changes)

// Get initialization options for LSP client
initOpts := config.ToLSPInitializationOptions(cfg)
```

## Configuration Structure

### Format Settings

```yaml
format:
  indent: 2                    # Indentation spaces
  uppercase_keywords: true     # Convert SQL keywords to uppercase
  max_line_length: 120        # Maximum line length
  compact: false              # Use compact formatting
```

### Validation Settings

```yaml
validation:
  dialect: postgresql         # SQL dialect (postgresql, mysql, sqlserver, oracle, sqlite)
  strict_mode: false          # Enable strict validation
  recursive: false            # Recursively validate directories
  pattern: "*.sql"            # File pattern for validation
  security:
    max_file_size: 10485760   # Maximum file size (10MB)
```

### Output Settings

```yaml
output:
  format: text               # Output format (text, json, yaml)
  verbose: false             # Enable verbose output
```

### Analysis Settings

```yaml
analyze:
  security: false            # Enable security analysis
  performance: false         # Enable performance analysis
  complexity: false          # Enable complexity analysis
  all: false                 # Enable all analysis types
```

### LSP Settings

```yaml
lsp:
  rate_limit_requests: 100   # Max requests per window
  rate_limit_window: 1s      # Rate limit time window
  request_timeout: 30s       # Request timeout
  max_document_size: 1048576 # Max document size (1MB)
  max_content_length: 10485760 # Max content length (10MB)
  trace_server: off          # LSP trace level (off, messages, verbose)
```

### Server Settings

```yaml
server:
  log_level: info            # Log level (debug, info, warn, error)
  log_file: ""               # Log file path (empty for stderr)
  metrics_enabled: true      # Enable metrics collection
  shutdown_timeout: 5s       # Graceful shutdown timeout
```

## JSON Configuration Example

```json
{
  "format": {
    "indent": 4,
    "uppercaseKeywords": true,
    "maxLineLength": 100
  },
  "validation": {
    "dialect": "mysql",
    "strictMode": true
  },
  "lsp": {
    "traceServer": "verbose"
  }
}
```

## Validation

All configuration values are validated after loading:

```go
cfg := config.DefaultConfig()
cfg.Format.Indent = -1  // Invalid

if err := cfg.Validate(); err != nil {
    log.Printf("Invalid config: %v", err)
}
```

Validation rules:
- **Format.Indent**: Must be non-negative
- **Format.MaxLineLength**: Must be non-negative
- **Validation.Dialect**: Must be one of: postgresql, mysql, sqlserver, oracle, sqlite
- **Validation.Security.MaxFileSize**: Must be non-negative
- **Output.Format**: Must be one of: text, json, yaml
- **LSP.TraceServer**: Must be one of: off, messages, verbose
- **Server.LogLevel**: Must be one of: debug, info, warn, error

## Testing

The package includes comprehensive tests with 78.6% coverage:

```bash
go test ./pkg/config/
go test -race ./pkg/config/   # With race detection
go test -cover ./pkg/config/  # With coverage report
```

## Notes

### Boolean Configuration Merging

When using environment variables or layered configuration, boolean values can only be set to `true` via override. Setting them to `false` via environment variables won't override a `true` value from a file or defaults. This is a limitation of the zero-value merge approach.

**Workaround**: Use file-based configuration for boolean `false` values.

### Configuration Source Tracking

The `Source` field tracks where configuration was loaded from:
- `"default"` - DefaultConfig()
- `"lsp"` - LSP initialization options
- `"environment"` - Environment variables
- `"/path/to/file.yaml"` - File path
- `"default+file+environment"` - Merged sources
