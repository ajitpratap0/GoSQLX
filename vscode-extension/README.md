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

### Multi-Dialect Support
Full support for database-specific syntax:
- **PostgreSQL**: Dollar-quoted strings, JSONB operators, array operations, window functions
- **MySQL**: Backtick identifiers, LIMIT/OFFSET syntax, GROUP_CONCAT, hash comments
- **SQL Server**: Bracket identifiers, TOP clause, CROSS/OUTER APPLY, TRY/CATCH
- **Oracle**: CONNECT BY hierarchical queries, ROWNUM, DECODE, MODEL clause
- **SQLite**: Lightweight syntax, ATTACH/DETACH, FTS full-text search
- **Generic SQL**: Standard SQL-99 compliance

## Requirements

You need to have the `gosqlx` CLI tool installed:

```bash
# Install via Go
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

# Verify installation
gosqlx --version
```

Make sure `gosqlx` is in your system PATH.

### Platform-Specific Installation

**macOS/Linux:**
```bash
# Add Go bin to PATH (add to ~/.bashrc or ~/.zshrc)
export PATH="$PATH:$(go env GOPATH)/bin"

# Reload shell
source ~/.bashrc  # or source ~/.zshrc
```

**Windows:**
```powershell
# Add Go bin to PATH (run in PowerShell as Admin)
$env:Path += ";$(go env GOPATH)\bin"

# Or permanently via System Properties > Environment Variables
# Add: %USERPROFILE%\go\bin
```

## Extension Settings

This extension contributes the following settings:

| Setting | Default | Scope | Description |
|---------|---------|-------|-------------|
| `gosqlx.enable` | `true` | Resource | Enable GoSQLX language server |
| `gosqlx.executablePath` | `gosqlx` | Machine | Path to the gosqlx executable |
| `gosqlx.trace.server` | `off` | Window | Traces communication with the language server |
| `gosqlx.format.indentSize` | `2` | Resource | Number of spaces for indentation |
| `gosqlx.format.uppercaseKeywords` | `true` | Resource | Convert keywords to uppercase |
| `gosqlx.validation.enable` | `true` | Resource | Enable real-time SQL validation |
| `gosqlx.dialect` | `generic` | Resource | SQL dialect for validation |
| `gosqlx.timeouts.startup` | `10000` | Window | Language server startup timeout (ms) |
| `gosqlx.timeouts.validation` | `5000` | Window | Executable validation timeout (ms) |
| `gosqlx.timeouts.analysis` | `30000` | Window | SQL analysis timeout (ms) |
| `gosqlx.telemetry.enable` | `false` | Global | Enable anonymous usage telemetry |
| `gosqlx.performance.showStatusBar` | `false` | Window | Show performance metrics in status bar |
| `gosqlx.performance.collectMetrics` | `true` | Window | Collect performance metrics |

### Workspace Settings

Settings with `Resource` scope can be configured per-workspace in `.vscode/settings.json`:

```json
{
  "gosqlx.dialect": "postgresql",
  "gosqlx.format.indentSize": 4,
  "gosqlx.format.uppercaseKeywords": false
}
```

## Commands

| Command | Description |
|---------|-------------|
| `GoSQLX: Validate SQL` | Validate the current SQL file |
| `GoSQLX: Format SQL` | Format the current SQL file |
| `GoSQLX: Analyze SQL` | Analyze query complexity and structure |
| `GoSQLX: Restart Language Server` | Restart the GoSQLX language server |
| `GoSQLX: Show Output Channel` | Show the GoSQLX output channel |
| `GoSQLX: Show Performance Metrics` | Display performance statistics |
| `GoSQLX: Validate Configuration` | Check configuration for errors |

## Performance

GoSQLX delivers exceptional performance:

| Operation | Speed |
|-----------|-------|
| Validation | 1.38M+ ops/sec |
| Formatting | 2,600+ files/sec |
| Parsing | 1.5M+ ops/sec |

## Troubleshooting

### Language server not starting

**Symptom**: Status bar shows "GoSQLX: Executable not found"

1. **Verify gosqlx is installed:**
   ```bash
   # macOS/Linux
   which gosqlx
   gosqlx --version

   # Windows
   where gosqlx
   gosqlx --version
   ```

2. **Check PATH configuration:**
   ```bash
   # macOS/Linux - verify GOPATH/bin is in PATH
   echo $PATH | grep -o "$(go env GOPATH)/bin"

   # If not found, add to shell profile:
   echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Specify full path in settings:**
   ```json
   {
     "gosqlx.executablePath": "/full/path/to/gosqlx"
   }
   ```

4. **Check the output channel:**
   - Open Command Palette (`Ctrl+Shift+P`)
   - Run "GoSQLX: Show Output Channel"

### Permission denied errors

**Symptom**: "EACCES" or "permission denied" errors

**macOS/Linux:**
```bash
# Check permissions
ls -la $(which gosqlx)

# Fix permissions
chmod +x $(which gosqlx)
```

**Windows:**
- Run VS Code as Administrator
- Check Windows Defender/antivirus settings
- Verify the executable is not blocked (Properties > Unblock)

### Timeout errors

**Symptom**: "Analysis timed out" or "startup timeout"

1. **Increase timeout settings:**
   ```json
   {
     "gosqlx.timeouts.startup": 30000,
     "gosqlx.timeouts.analysis": 60000
   }
   ```

2. **Check system resources:**
   - Close resource-intensive applications
   - Check CPU/memory usage

3. **Try with simpler SQL:**
   - Complex queries may take longer
   - Break down large queries for analysis

### Validation not working

**Symptom**: No syntax errors shown for invalid SQL

1. **Verify language detection:**
   - Ensure the file has a `.sql` extension
   - Check status bar shows "SQL" as language

2. **Check validation is enabled:**
   ```json
   {
     "gosqlx.validation.enable": true
   }
   ```

3. **Restart the language server:**
   - Run "GoSQLX: Restart Language Server"

4. **Verify dialect setting:**
   - Some syntax is dialect-specific
   - Try `"gosqlx.dialect": "generic"`

### Formatting issues

**Symptom**: Format command does nothing or produces unexpected results

1. **Check for syntax errors:**
   - Files with syntax errors may not format correctly
   - Fix errors first, then format

2. **Verify language server is running:**
   - Status bar should show "GoSQLX" (not error state)
   - Try restarting the server

3. **Check format settings:**
   ```json
   {
     "gosqlx.format.indentSize": 2,
     "gosqlx.format.uppercaseKeywords": true
   }
   ```

### Remote development issues

**Symptom**: Extension not working in Remote SSH/WSL/Container

1. **Install gosqlx in remote environment:**
   ```bash
   # Run in remote terminal
   go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
   ```

2. **Configure remote PATH:**
   - Add Go bin to PATH in remote shell profile
   - Restart remote VS Code window

3. **Use remote-specific settings:**
   ```json
   // Remote settings
   {
     "gosqlx.executablePath": "/home/user/go/bin/gosqlx"
   }
   ```

### Connection reset errors

**Symptom**: "ECONNRESET" or "connection reset"

1. **Restart VS Code:**
   - Close all VS Code windows
   - Reopen the workspace

2. **Check for zombie processes:**
   ```bash
   # macOS/Linux
   ps aux | grep gosqlx
   kill <pid>  # if found

   # Windows
   tasklist | findstr gosqlx
   taskkill /F /PID <pid>
   ```

3. **Check system sleep/resume:**
   - Connections may break after sleep
   - Restart language server after wake

### Version mismatch errors

**Symptom**: "JSON parse error" or unexpected responses

1. **Update gosqlx:**
   ```bash
   go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
   ```

2. **Verify version:**
   ```bash
   gosqlx --version
   ```

3. **Check extension version:**
   - Update extension to latest version
   - Restart VS Code

### Debug logging

For persistent issues, enable verbose logging:

```json
{
  "gosqlx.trace.server": "verbose"
}
```

Then check the output channel for detailed logs.

## Telemetry

GoSQLX can collect anonymous usage data to help improve the extension. This is **disabled by default**.

When enabled:
- **What we collect**: Command usage counts, operation durations, error codes
- **What we NEVER collect**: SQL content, file paths, personal information

To opt in:
```json
{
  "gosqlx.telemetry.enable": true
}
```

Telemetry also respects VS Code's global telemetry setting.

## Contributing

Contributions are welcome! Please see our [Contributing Guide](https://github.com/ajitpratap0/GoSQLX/blob/main/CONTRIBUTING.md).

## License

Apache License 2.0 - see [LICENSE](https://github.com/ajitpratap0/GoSQLX/blob/main/LICENSE)

## Release Notes

### 0.1.0

Initial release:
- Real-time SQL validation
- SQL formatting with customizable options
- Syntax highlighting for SQL with multi-dialect support
- Intelligent autocomplete
- Hover documentation
- SQL analysis command
- Multi-dialect support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- Configurable timeouts
- Performance metrics
- Configuration validation
- Enhanced error messaging with actionable suggestions
- Workspace settings support
