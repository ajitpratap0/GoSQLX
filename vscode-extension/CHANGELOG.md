# Change Log

All notable changes to the "GoSQLX" extension will be documented in this file.

## [1.10.3] - 2026-03-14

### Fixed
- LSP server now accepts --stdio flag from vscode-languageclient
- Empty executablePath no longer triggers validation warning

## [1.10.2] - 2026-03-14

### Fixed
- Include vscode-languageclient in VSIX package (extension failed to activate)

## [1.10.1] - 2026-03-13

### Added
- **Bundled binary** — GoSQLX binary is now included in the extension package; no separate installation needed
- **Platform-specific packages** — optimized downloads for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64
- **Smart binary resolution** — automatically uses bundled binary, falls back to user setting or PATH

### Changed
- Version aligned with GoSQLX core (1.10.1)
- `gosqlx.executablePath` default changed from `"gosqlx"` to `""` (empty = use bundled binary)
- Automated CI publishing via GitHub Actions on every GoSQLX release tag

## [0.1.0] - 2025-11-27

### Added
- Initial release of GoSQLX VS Code extension
- Real-time SQL validation via GoSQLX Language Server
- SQL syntax highlighting with comprehensive TextMate grammar
- SQL formatting with customizable options
  - Configurable indent size
  - Uppercase/lowercase keywords option
- Intelligent autocomplete for SQL keywords and functions
- Hover documentation for SQL keywords
- SQL analysis command for query complexity analysis
- Multi-dialect support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- Extension settings panel
- Command palette integration
- Context menu integration
- Status bar indicator
- Output channel for debugging

### Technical
- Language Server Protocol (LSP) client implementation
- TextMate grammar with patterns for:
  - Comments (line and block)
  - Strings (single, double, dollar-quoted, backtick)
  - Numbers (integer, float, hex)
  - Operators (comparison, arithmetic, JSON)
  - Keywords (DML, DDL, joins, window functions, CTEs)
  - Functions (aggregate, window, string, datetime, math, JSON, array)
  - Data types (PostgreSQL comprehensive list)
  - Parameters (positional and named)
