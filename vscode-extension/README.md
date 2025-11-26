# GoSQLX - SQL Parser & Linter for VS Code

High-performance SQL parsing, validation, formatting, and analysis powered by [GoSQLX](https://github.com/ajitpratap0/GoSQLX).

## Features

### Real-time SQL Validation
Get instant feedback on SQL syntax errors as you type. Errors are highlighted directly in the editor with detailed messages in the Problems panel.

### SQL Formatting
Format your SQL code with customizable indentation and keyword casing.

- **Keyboard shortcut**: `Ctrl+Shift+F` (Windows/Linux) or `Cmd+Shift+F` (Mac)
- **Command palette**: "GoSQLX: Format SQL"
- **Right-click menu**: Format SQL

### Intelligent Autocomplete
Get context-aware suggestions for:
- SQL keywords (100+ supported)
- SQL functions with signatures
- Common SQL snippets and patterns

### Hover Documentation
Hover over SQL keywords to see documentation and usage examples.

### SQL Analysis
Analyze query complexity, find potential issues, and get optimization suggestions.

## Supported SQL Dialects

- PostgreSQL
- MySQL
- SQL Server
- Oracle
- SQLite
- Generic SQL

## Requirements

You need to have the `gosqlx` CLI tool installed:

```bash
# Install via Go
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

# Verify installation
gosqlx --version
```

Make sure `gosqlx` is in your system PATH.

## Extension Settings

This extension contributes the following settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `gosqlx.enable` | `true` | Enable GoSQLX language server |
| `gosqlx.executablePath` | `gosqlx` | Path to the gosqlx executable |
| `gosqlx.trace.server` | `off` | Traces communication with the language server |
| `gosqlx.format.indentSize` | `2` | Number of spaces for indentation |
| `gosqlx.format.uppercaseKeywords` | `true` | Convert keywords to uppercase |
| `gosqlx.validation.enable` | `true` | Enable real-time SQL validation |
| `gosqlx.dialect` | `generic` | SQL dialect for validation |

## Commands

| Command | Description |
|---------|-------------|
| `GoSQLX: Validate SQL` | Validate the current SQL file |
| `GoSQLX: Format SQL` | Format the current SQL file |
| `GoSQLX: Analyze SQL` | Analyze query complexity and structure |
| `GoSQLX: Restart Language Server` | Restart the GoSQLX language server |
| `GoSQLX: Show Output Channel` | Show the GoSQLX output channel |

## Performance

GoSQLX delivers exceptional performance:

| Operation | Speed |
|-----------|-------|
| Validation | 1.38M+ ops/sec |
| Formatting | 2,600+ files/sec |
| Parsing | 1.5M+ ops/sec |

## Troubleshooting

### Language server not starting

1. Ensure `gosqlx` is installed and in your PATH:
   ```bash
   which gosqlx
   gosqlx --version
   ```

2. Check the GoSQLX output channel for errors:
   - Open Command Palette (`Ctrl+Shift+P`)
   - Run "GoSQLX: Show Output Channel"

3. Try specifying the full path in settings:
   ```json
   {
     "gosqlx.executablePath": "/path/to/gosqlx"
   }
   ```

### Validation not working

1. Ensure the file has a `.sql` extension
2. Check that `gosqlx.validation.enable` is `true`
3. Restart the language server

## Contributing

Contributions are welcome! Please see our [Contributing Guide](https://github.com/ajitpratap0/GoSQLX/blob/main/CONTRIBUTING.md).

## License

GNU Affero General Public License v3.0 (AGPL-3.0) - see [LICENSE](https://github.com/ajitpratap0/GoSQLX/blob/main/LICENSE)

## Release Notes

### 0.1.0

Initial release:
- Real-time SQL validation
- SQL formatting with customizable options
- Syntax highlighting for SQL
- Intelligent autocomplete
- Hover documentation
- SQL analysis command
- Multi-dialect support
