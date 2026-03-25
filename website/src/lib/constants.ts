export const NAV_LINKS = [
  { href: '/docs', label: 'Docs' },
  { href: '/playground', label: 'Playground' },
  { href: '/blog', label: 'Changelog' },
  { href: '/vscode', label: 'VS Code' },
  { href: '/benchmarks', label: 'Benchmarks' },
];

export const FEATURES = [
  { icon: 'globe', title: 'Multi-Dialect', description: 'PostgreSQL, MySQL, MariaDB, SQLite, SQL Server, Oracle, Snowflake, ClickHouse.', color: 'accent-purple' },
  { icon: 'lock', title: 'Thread-Safe', description: 'Zero race conditions. 20,000+ concurrent ops tested.', color: 'accent-green' },
  { icon: 'bolt', title: 'Zero-Copy', description: 'Direct byte slice operations. No unnecessary allocations.', color: 'accent-orange' },
  { icon: 'recycle', title: 'Object Pooling', description: 'sync.Pool recycling for ASTs, tokenizers, expressions.', color: 'accent-indigo' },
  { icon: 'shield', title: 'Security Scanner', description: 'SQL injection detection with severity classification.', color: 'red' },
  { icon: 'cpu', title: 'MCP Server', description: '7 SQL tools for Claude, Cursor, and any MCP client.', color: 'cyan' },
];

export const DOCS_SIDEBAR = [
  { category: 'Getting Started', items: [
    { slug: 'getting-started', file: 'GETTING_STARTED.md', label: 'Getting Started' },
    { slug: 'cli-guide', file: 'CLI_GUIDE.md', label: 'CLI Guide' },
  ]},
  { category: 'Core', items: [
    { slug: 'usage-guide', file: 'USAGE_GUIDE.md', label: 'Usage Guide' },
    { slug: 'api-reference', file: 'API_REFERENCE.md', label: 'API Reference' },
    { slug: 'architecture', file: 'ARCHITECTURE.md', label: 'Architecture' },
    { slug: 'configuration', file: 'CONFIGURATION.md', label: 'Configuration' },
  ]},
  { category: 'Reference', items: [
    { slug: 'error-codes', file: 'ERROR_CODES.md', label: 'Error Codes' },
    { slug: 'sql-compatibility', file: 'SQL_COMPATIBILITY.md', label: 'SQL Compatibility' },
    { slug: 'linting-rules', file: 'LINTING_RULES.md', label: 'Linting Rules' },
  ]},
  { category: 'Advanced', items: [
    { slug: 'lsp-guide', file: 'LSP_GUIDE.md', label: 'LSP Guide' },
    { slug: 'mcp-guide', file: 'MCP_GUIDE.md', label: 'MCP Guide' },
    { slug: 'security', file: 'SECURITY.md', label: 'Security' },
    { slug: 'production-guide', file: 'PRODUCTION_GUIDE.md', label: 'Production Guide' },
    { slug: 'performance-tuning', file: 'PERFORMANCE_TUNING.md', label: 'Performance Tuning' },
  ]},
  { category: 'Tutorials', items: [
    { slug: 'tutorials/01-sql-validator-cicd', file: 'tutorials/01-sql-validator-cicd.md', label: 'SQL Validator CI/CD' },
    { slug: 'tutorials/02-custom-sql-formatter', file: 'tutorials/02-custom-sql-formatter.md', label: 'Custom SQL Formatter' },
  ]},
  { category: 'Migration', items: [
    { slug: 'migration/from-jsqlparser', file: 'migration/FROM_JSQLPARSER.md', label: 'From JSQLParser' },
    { slug: 'migration/from-pg-query', file: 'migration/FROM_PG_QUERY.md', label: 'From pg_query' },
    { slug: 'migration/from-sqlfluff', file: 'migration/FROM_SQLFLUFF.md', label: 'From SQLFluff' },
  ]},
  { category: 'Editors', items: [
    { slug: 'editors/vscode', file: 'editors/vscode.md', label: 'VS Code' },
    { slug: 'editors/neovim', file: 'editors/neovim.md', label: 'Neovim' },
    { slug: 'editors/jetbrains', file: 'editors/jetbrains.md', label: 'JetBrains' },
  ]},
];
