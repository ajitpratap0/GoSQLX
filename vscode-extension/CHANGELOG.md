# Change Log

All notable changes to the "GoSQLX" extension will be documented in this file.

## [1.14.0] - 2026-04-12

### Added
- **Dialect-aware SQL formatting**: `transform.FormatSQLWithDialect()` renders TOP (SQL Server), FETCH FIRST (Oracle), or LIMIT per dialect
- **Snowflake dialect at 100%** of QA corpus (87/87): MATCH_RECOGNIZE, @stage, SAMPLE, QUALIFY, VARIANT colon-paths, time-travel, LATERAL FLATTEN, TRY_CAST, LIKE ANY/ALL
- **ClickHouse dialect at 83%** of QA corpus (69/83, up from 53%): nested column types, parametric aggregates, bare-bracket arrays, ORDER BY WITH FILL, CODEC, WITH TOTALS, LIMIT BY, SETTINGS/TTL
- **MariaDB dialect**: SEQUENCE DDL, temporal tables, CONNECT BY hierarchical queries
- **SQL transpilation**: MySQL to PostgreSQL, PostgreSQL to MySQL, PostgreSQL to SQLite via `gosqlx transpile` CLI
- **Live schema introspection**: PostgreSQL, MySQL, and SQLite loaders via `gosqlx.LoadSchema()`
- **DML Transform API**: SET clause and RETURNING clause transforms
- **30 linter rules** (expanded from 10): safety (L011-L015), performance (L016-L023), naming (L024-L030)
- **Optimization advisor**: OPT-009 through OPT-020 rules via `gosqlx optimize`
- **Query fingerprinting**: Normalize and SHA-256 hash SQL for deduplication
- **OpenTelemetry integration** sub-module with span instrumentation
- **GORM integration** sub-module with query metadata plugin
- New CLI subcommands: `transpile`, `optimize`, `stats`, `watch`, `action`
- SQL Server PIVOT/UNPIVOT parsing
- C binding coverage hardened from 18% to 93%

### Fixed
- Parsed SQL Server `TOP` clauses now render correctly in formatted output (previously silently dropped)
- MINUS consumed as alias fixed for Snowflake/Oracle set operations

### Security
- OpenTelemetry SDK upgraded to v1.43.0 (CVE-2026-39883)

## [1.13.0] - 2026-03-20

### Added
- **ClickHouse SQL dialect support** with 30+ keywords: PREWHERE, FINAL, GLOBAL IN/NOT IN
- **LSP semantic token provider** (`textDocument/semanticTokens/full`) with 6-type legend: keyword, identifier, number, string, operator, comment
- **LSP diagnostic debouncing** (300ms) prevents excessive re-parsing on rapid typing
- LSP document cleanup on `textDocument/didClose`
- Glama MCP registry integration with stdio transport support
- Sentry error monitoring on the website

### Changed
- `ParseFromModelTokens` is now the canonical parse entry point (positions always populated)
- Docker base image Go 1.25 to 1.26
- Next.js 16.1.6 to 16.1.7 (3 CVE fixes)
- Lighthouse Desktop: 100 Performance / 100 Accessibility / 100 SEO

### Deprecated
- `parser.Parse([]token.Token)` -- use `ParseFromModelTokens` instead
- `ParseFromModelTokensWithPositions` -- consolidated into `ParseFromModelTokens`

## [1.12.1] - 2026-03-15

### Changed
- Version aligned with GoSQLX core (1.12.1)

## [1.12.0] - 2026-03-15

### Changed
- Homepage URL updated to `https://gosqlx.dev`

## [1.11.1] - 2026-03-15

### Fixed
- Version aligned with GoSQLX core (1.11.1)

## [1.10.4] - 2026-03-14

### Fixed
- SQL formatting in VS Code now uses the full AST-based formatter

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
