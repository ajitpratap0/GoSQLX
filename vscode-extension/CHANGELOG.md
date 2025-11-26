# Change Log

All notable changes to the "GoSQLX" extension will be documented in this file.

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
