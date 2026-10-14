import { PROJECT } from '@/data/metrics';

export const NAV_LINKS = [
  { href: '/docs', label: 'Docs' },
  { href: '/playground', label: 'Playground' },
  { href: '/blog', label: 'Changelog' },
  { href: '/vscode', label: 'VS Code' },
  { href: '/benchmarks', label: 'Benchmarks' },
  { href: '/compare', label: 'Compare' },
];

export const FEATURES = [
  { icon: 'globe', title: 'Multi-Dialect', description: 'PostgreSQL, MySQL, MariaDB, SQLite, SQL Server, Oracle, Snowflake, ClickHouse.', color: 'accent-purple' },
  { icon: 'lock', title: 'Thread-Safe', description: 'Race-detector clean in CI.', color: 'accent-green' },
  { icon: 'bolt', title: 'Zero-Copy', description: 'Direct byte slice operations. No unnecessary allocations.', color: 'accent-orange' },
  { icon: 'recycle', title: 'Object Pooling', description: 'sync.Pool recycling for ASTs, tokenizers, expressions.', color: 'accent-indigo' },
  { icon: 'shield', title: 'Security Scanner', description: 'SQL injection detection with severity classification.', color: 'red' },
  { icon: 'cpu', title: 'MCP Server', description: `${PROJECT.mcpToolCount} SQL tools for Claude, Cursor, and any MCP client.`, color: 'cyan' },
];

export const DOCS_SIDEBAR = [
  { category: 'Getting Started', items: [
    { slug: 'getting-started', file: 'GETTING_STARTED.md', label: 'Getting Started', description: 'Install GoSQLX, parse your first SQL statement in Go, and walk the AST in minutes, with copy-paste examples for the high-level API and the CLI.' },
    { slug: 'feature-tour', file: 'FEATURE_TOUR.md', label: 'Feature Tour', description: 'A guided tour of GoSQLX features: parsing, formatting, linting, security scanning, transforms, fingerprinting and transpilation, each with a short example.' },
    { slug: 'cli-guide', file: 'CLI_GUIDE.md', label: 'CLI Guide', description: 'Reference for the gosqlx command line tool: validate, format, lint, parse, analyze and lsp commands, flags, output formats and CI usage with examples.' },
  ]},
  { category: 'Core', items: [
    { slug: 'usage-guide', file: 'USAGE_GUIDE.md', label: 'Usage Guide', description: 'Practical patterns for GoSQLX in Go: high-level and low-level APIs, object pooling, dialect selection, error handling and concurrent use in services.' },
    { slug: 'api-reference', file: 'API_REFERENCE.md', label: 'API Reference', description: 'Complete API reference for GoSQLX packages: gosqlx, tokenizer, parser, ast, errors and models, with function signatures, types and usage notes.' },
    { slug: 'architecture', file: 'ARCHITECTURE.md', label: 'Architecture', description: 'How GoSQLX is built: the zero-copy tokenizer, recursive descent parser, AST and visitor pattern, object pools and package dependencies, explained.' },
    { slug: 'configuration', file: 'CONFIGURATION.md', label: 'Configuration', description: 'Configure GoSQLX through .gosqlx.yml and command line flags: dialect, formatter style, linter rule severity, LSP options and per-project overrides.' },
  ]},
  { category: 'Reference', items: [
    { slug: 'error-codes', file: 'ERROR_CODES.md', label: 'Error Codes', description: 'Every GoSQLX error code from E1001 to E3004 for tokenizer, parser and semantic failures, with meanings, typical causes and suggested fixes.' },
    { slug: 'sql-compatibility', file: 'SQL_COMPATIBILITY.md', label: 'SQL Compatibility', description: 'Which SQL syntax GoSQLX supports across PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake and ClickHouse, with a dialect coverage matrix.' },
    { slug: 'linting-rules', file: 'LINTING_RULES.md', label: 'Linting Rules', description: 'All 30 built-in GoSQLX linter rules, L001 to L030, with what each checks, why it matters, example violations, fixes and auto-fix support.' },
  ]},
  { category: 'Advanced', items: [
    { slug: 'lsp-guide', file: 'LSP_GUIDE.md', label: 'LSP Guide', description: 'Set up the GoSQLX Language Server for diagnostics, completion, hover, formatting and symbols in VS Code, Neovim, JetBrains and other LSP editors.' },
    { slug: 'mcp-guide', file: 'MCP_GUIDE.md', label: 'MCP Guide', description: 'Expose GoSQLX to AI assistants through the Model Context Protocol: available tools for parsing, validating, formatting and analyzing SQL, plus setup steps.' },
    { slug: 'security', file: 'SECURITY.md', label: 'Security', description: 'Detect SQL injection with the GoSQLX security scanner: finding severities, supported patterns, usage from Go and the CLI, and how to report issues.' },
    { slug: 'production-guide', file: 'PRODUCTION_GUIDE.md', label: 'Production Guide', description: 'Run GoSQLX in production: sizing object pools, concurrency and race safety, metrics and monitoring, error handling, timeouts and deployment advice.' },
    { slug: 'performance-tuning', file: 'PERFORMANCE_TUNING.md', label: 'Performance Tuning', description: 'Tune GoSQLX for throughput: reuse pooled tokenizers and ASTs, choose the right API, profile hot paths and read benchmark results for your workload.' },
  ]},
  { category: 'Tutorials', items: [
    { slug: 'tutorials/01-sql-validator-cicd', file: 'tutorials/01-sql-validator-cicd.md', label: 'SQL Validator CI/CD', description: 'Tutorial: build a SQL validator with GoSQLX and run it in CI/CD, failing pull requests on syntax errors, lint violations and unsafe queries.' },
    { slug: 'tutorials/02-custom-sql-formatter', file: 'tutorials/02-custom-sql-formatter.md', label: 'Custom SQL Formatter', description: 'Tutorial: build a custom SQL formatter with GoSQLX by walking the AST, choosing keyword case and indentation, and checking output against golden tests.' },
  ]},
  { category: 'Migration', items: [
    { slug: 'migration/from-jsqlparser', file: 'migration/FROM_JSQLPARSER.md', label: 'From JSQLParser', description: 'Migrate from JSqlParser to GoSQLX: how Java parsing concepts map to Go APIs, equivalent AST nodes, visitor usage and a step-by-step porting checklist.' },
    { slug: 'migration/from-pg-query', file: 'migration/FROM_PG_QUERY.md', label: 'From pg_query', description: 'Migrate from pg_query_go to GoSQLX: swap the cgo dependency for a pure Go parser, map AST nodes and functions, and handle multiple SQL dialects.' },
    { slug: 'migration/from-sqlfluff', file: 'migration/FROM_SQLFLUFF.md', label: 'From SQLFluff', description: 'Migrate from SQLFluff to GoSQLX: map lint rules and configuration to GoSQLX equivalents, compare speed and dialects, and move CI checks over.' },
  ]},
  { category: 'Editors', items: [
    { slug: 'editors/vscode', file: 'editors/vscode.md', label: 'VS Code', description: 'Install the GoSQLX VS Code extension for SQL diagnostics, formatting, completion and hover, and configure the language server for your project.' },
    { slug: 'editors/neovim', file: 'editors/neovim.md', label: 'Neovim', description: 'Configure Neovim to use the GoSQLX language server through nvim-lspconfig for SQL diagnostics, formatting, completion and hover, with a working example.' },
    { slug: 'editors/jetbrains', file: 'editors/jetbrains.md', label: 'JetBrains', description: 'Connect JetBrains IDEs such as GoLand, IntelliJ and DataGrip to the GoSQLX language server for SQL diagnostics, formatting and completion, step by step.' },
  ]},
];
