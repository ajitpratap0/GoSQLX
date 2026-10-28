import { PROJECT, REALWORLD_CORPUS, REALWORLD_STATUS } from '@/data/metrics';

/** Appends the "not released yet" qualifier while REALWORLD_CORPUS.released is false. */
const unreleased = (text: string) => (REALWORLD_STATUS ? `${text} (${REALWORLD_STATUS})` : text);

export const NAV_LINKS = [
  { href: '/docs', label: 'Docs' },
  { href: '/playground', label: 'Playground' },
  { href: '/blog', label: 'Blog' },
  { href: '/changelog', label: 'Changelog' },
  { href: '/vscode', label: 'VS Code' },
  { href: '/benchmarks', label: 'Benchmarks' },
  { href: '/compare', label: 'Compare' },
];

export interface Feature {
  icon: string;
  title: string;
  description: string;
  color: string;
  /** Spans the full row from md up, so an odd card count still fills every row. */
  wide?: boolean;
}

export const FEATURES: Feature[] = [
  {
    icon: 'globe',
    title: 'Multi-Dialect',
    description: `PostgreSQL, MySQL, MariaDB, SQLite, SQL Server, Oracle, Snowflake, ClickHouse. ${unreleased(
      `All ${REALWORLD_CORPUS.total.toLocaleString('en-US')} statements of a production-style corpus (hand-written to imitate ORM and application SQL) across the ${PROJECT.dialectCount} dialects parse, format and round-trip`,
    )}.`,
    color: 'accent',
  },
  { icon: 'lock', title: 'Thread-Safe', description: 'Race-detector clean in CI.', color: 'brand' },
  { icon: 'bolt', title: 'Zero-Copy', description: 'Direct byte slice operations. No unnecessary allocations.', color: 'accent-warm' },
  { icon: 'recycle', title: 'Object Pooling', description: 'sync.Pool recycling for ASTs, tokenizers, expressions.', color: 'accent' },
  { icon: 'shield', title: 'Security Scanner', description: 'SQL injection detection with severity classification.', color: 'danger' },
  { icon: 'cpu', title: 'MCP Server', description: `${PROJECT.mcpToolCount} SQL tools for Claude, Cursor, and any MCP client.`, color: 'cyan' },
  {
    icon: 'code',
    title: 'Format & Transpile',
    description: `Dialect-aware formatting and SQL transpilation between dialects, since v1.14. ${unreleased(
      'gosqlx.Format and gosqlx format keep comments and optimizer hints',
    )}.`,
    color: 'brand',
    wide: true,
  },
];

export interface DocsSidebarItem {
  /** URL path under /docs/ (no leading or trailing slash). */
  slug: string;
  /** Markdown source, relative to the repo-level docs/ folder. */
  file: string;
  label: string;
  /** Hand-written meta description, 120-155 characters. */
  description: string;
  /** 1 renders the item indented under the previous top-level item. */
  depth?: 1;
}

export interface DocsSidebarCategory {
  category: string;
  /** One line shown on the /docs/ landing page. */
  summary: string;
  items: DocsSidebarItem[];
}

/**
 * Docs information architecture. Moving or removing a slug here requires a
 * permanent redirect in src/lib/docs-redirects.ts.
 */
export const DOCS_SIDEBAR: DocsSidebarCategory[] = [
  { category: 'Start', summary: 'Install GoSQLX, parse your first query and learn the CLI.', items: [
    { slug: 'getting-started', file: 'GETTING_STARTED.md', label: 'Getting Started', description: 'Install GoSQLX, parse your first SQL statement in Go, and walk the AST in minutes, with copy-paste examples for the high-level API and the CLI.' },
    { slug: 'feature-tour', file: 'FEATURE_TOUR.md', label: 'Feature Tour', description: 'A guided tour of GoSQLX features: parsing, formatting, linting, security scanning, transforms, fingerprinting and transpilation, each with a short example.' },
    { slug: 'usage-guide', file: 'USAGE_GUIDE.md', label: 'Usage Guide', description: 'Practical patterns for GoSQLX in Go: high-level and low-level APIs, object pooling, dialect selection, error handling and concurrent use in services.' },
    { slug: 'cli-guide', file: 'CLI_GUIDE.md', label: 'CLI Guide', description: 'Reference for the gosqlx command line tool: validate, format, lint, parse, analyze, transpile, stats, watch and lsp commands, flags, output formats and CI use.' },
  ]},
  { category: 'Guides', summary: 'Task-focused walkthroughs with working code.', items: [
    { slug: 'guides/parse-postgresql-in-go', file: 'guides/parse-postgresql-in-go.md', label: 'Parse PostgreSQL in Go', description: 'Parse PostgreSQL queries in pure Go with GoSQLX: DISTINCT ON, JSONB operators, RETURNING and LATERAL, AST walkers, and syntax errors with positions.' },
    { slug: 'guides/format-sql-in-go', file: 'guides/format-sql-in-go.md', label: 'Format SQL in Go', description: 'Format SQL in Go with GoSQLX: pretty-print queries from code, set indentation and keyword style, format dialect SQL and check .sql files in CI.' },
    { slug: 'guides/extract-table-names-from-sql-in-go', file: 'guides/extract-table-names-from-sql-in-go.md', label: 'Extract table names from SQL in Go', description: 'Extract table, column and function names from SQL in Go with GoSQLX, including joins, subqueries and schemas, and filter out CTE names for lineage.' },
    { slug: 'guides/detect-sql-injection-in-go', file: 'guides/detect-sql-injection-in-go.md', label: 'Detect SQL injection in Go', description: 'Detect SQL injection patterns in Go with the GoSQLX scanner: tautologies, UNION and stacked queries, severity thresholds, and scanning files in CI.' },
    { slug: 'guides/lint-sql-in-ci', file: 'guides/lint-sql-in-ci.md', label: 'Lint SQL in CI', description: 'Lint and validate SQL files in CI with GoSQLX: a GitHub Actions workflow with annotations, plain shell commands, and a Go test applying all 30 rules.' },
    { slug: 'guides/sql-validator-cicd', file: 'tutorials/01-sql-validator-cicd.md', label: 'Build a SQL Validator for CI/CD', description: 'Tutorial: build a SQL syntax validator with GoSQLX and wire it into a CI/CD pipeline so pull requests with invalid SQL files fail the build.' },
    { slug: 'guides/custom-sql-formatter', file: 'tutorials/02-custom-sql-formatter.md', label: 'Build a Custom SQL Formatter', description: 'Tutorial: build a custom SQL formatter with GoSQLX by parsing queries into an AST, walking the nodes and controlling keyword case and indentation.' },
    { slug: 'guides/production', file: 'PRODUCTION_GUIDE.md', label: 'Run in Production', description: 'Run GoSQLX in production: sizing object pools, concurrency and race safety, metrics and monitoring, error handling, timeouts and deployment advice.' },
    { slug: 'guides/performance-tuning', file: 'PERFORMANCE_TUNING.md', label: 'Performance Tuning', description: 'Tune GoSQLX for throughput: reuse pooled tokenizers and ASTs, choose the right API, profile hot paths and read benchmark results for your workload.' },
    { slug: 'guides/troubleshooting', file: 'TROUBLESHOOTING.md', label: 'Troubleshooting', description: 'Fix common GoSQLX problems: parse errors, LSP server and linter issues, security scanner surprises, performance and memory problems, with debugging tips.' },
    { slug: 'guides/syntax-highlighting', file: 'HIGHLIGHTING.md', label: 'Syntax Highlighting', description: 'Highlight SQL with GoSQLX for terminals, HTML pages and editors: the categories, themes, the highlight CLI command, LSP semantic tokens and the WASM build.' },
  ]},
  { category: 'Integrations', summary: 'Editors, language server and AI assistants.', items: [
    { slug: 'integrations/vscode', file: 'editors/vscode.md', label: 'VS Code', description: 'Install the GoSQLX VS Code extension for SQL diagnostics, formatting, completion and hover, and configure the language server for your project.' },
    { slug: 'integrations/neovim', file: 'editors/neovim.md', label: 'Neovim', description: 'Configure Neovim to use the GoSQLX language server through nvim-lspconfig for SQL diagnostics, formatting, completion and hover, with a working example.' },
    { slug: 'integrations/jetbrains', file: 'editors/jetbrains.md', label: 'JetBrains', description: 'Connect JetBrains IDEs such as GoLand, IntelliJ and DataGrip to the GoSQLX language server for SQL diagnostics, formatting and completion, step by step.' },
    { slug: 'integrations/lsp', file: 'LSP_GUIDE.md', label: 'Language Server (LSP)', description: 'Set up the GoSQLX Language Server for diagnostics, completion, hover, formatting and symbols in VS Code, Neovim, JetBrains and other LSP editors.' },
    { slug: 'integrations/mcp', file: 'MCP_GUIDE.md', label: 'MCP Server', description: 'Expose GoSQLX to AI assistants through the Model Context Protocol: available tools for parsing, validating, formatting and analyzing SQL, plus setup steps.' },
    { slug: 'integrations/chatgpt', file: 'CHATGPT_APP.md', label: 'ChatGPT App', description: 'How gosqlx-mcp works as a ChatGPT app and in MCP Apps hosts: tool and resource metadata, the analyze_sql report widget, structured content and testing.' },
  ]},
  { category: 'Reference', summary: 'API, CLI configuration, errors, rules and dialects.', items: [
    { slug: 'reference/api', file: 'API_REFERENCE.md', label: 'API Reference', description: 'GoSQLX API reference index: every package from the high-level gosqlx API to the tokenizer, parser and AST, with pooling advice and a complete example.' },
    { slug: 'reference/api/gosqlx', file: 'api/gosqlx.md', label: 'gosqlx package', depth: 1, description: 'Reference for the gosqlx package, the high-level GoSQLX API: Parse, ParseTree, Validate, Format, Lint and metadata extraction with pooling built in.' },
    { slug: 'reference/api/tokenizer', file: 'api/tokenizer.md', label: 'tokenizer package', depth: 1, description: 'Reference for the GoSQLX tokenizer package: the zero-copy SQL lexer, pooled tokenizer instances, token types and the spans attached to each token.' },
    { slug: 'reference/api/parser', file: 'api/parser.md', label: 'parser package', depth: 1, description: 'Reference for the GoSQLX parser package: the recursive descent parser that turns tokens into an AST, with context-aware parsing and parser reuse.' },
    { slug: 'reference/api/ast', file: 'api/ast.md', label: 'ast package', depth: 1, description: 'Reference for the GoSQLX ast package: statement and expression node types, DDL and DML nodes, window and CTE types, object pools and visitors.' },
    { slug: 'reference/api/keywords', file: 'api/keywords.md', label: 'keywords package', depth: 1, description: 'Reference for the GoSQLX keywords package: keyword lookup and categories, reserved words, functions and data types, and dialect-specific keyword checks.' },
    { slug: 'reference/api/models', file: 'api/models.md', label: 'models package', depth: 1, description: 'Reference for the GoSQLX models package: the token, span and location types shared by the tokenizer, parser, AST and error reporting.' },
    { slug: 'reference/api/errors', file: 'api/errors.md', label: 'errors package', depth: 1, description: 'Reference for the GoSQLX errors package: structured errors with codes, source positions, hints and help links, and helpers to build and inspect them.' },
    { slug: 'reference/api/metrics', file: 'api/metrics.md', label: 'metrics package', depth: 1, description: 'Reference for the GoSQLX metrics package: enable, record and read counters and timings for tokenizer and parser operations in production services.' },
    { slug: 'reference/api/security', file: 'api/security.md', label: 'security package', depth: 1, description: 'Reference for the GoSQLX security package: the SQL injection scanner, its finding and result types, severity levels and every detection pattern.' },
    { slug: 'reference/api/highlight', file: 'api/highlight.md', label: 'highlight package', depth: 1, description: 'Reference for the GoSQLX highlight package: classify SQL into byte-offset spans by category, then render them as ANSI, HTML or CSS with built-in themes.' },
    { slug: 'reference/api/linter', file: 'api/linter.md', label: 'linter package', depth: 1, description: 'Reference for the GoSQLX linter package: the lint engine, the Rule interface, violations, auto-fix support and how to build a linter with your rules.' },
    { slug: 'reference/api/lsp', file: 'api/lsp.md', label: 'lsp package', depth: 1, description: 'Reference for the GoSQLX lsp package: the Language Server Protocol server, its handlers and capabilities, and how to embed it in your own tool.' },
    { slug: 'reference/api/mcp', file: 'api/mcp.md', label: 'mcp package', depth: 1, description: 'Reference for the GoSQLX mcp package: the Model Context Protocol server, its configuration and the SQL tools it registers for AI assistants.' },
    { slug: 'reference/api/config', file: 'api/config.md', label: 'config package', depth: 1, description: 'Reference for the GoSQLX config package: the Config, linter and format settings, and loading configuration from a file, the environment or defaults.' },
    { slug: 'reference/configuration', file: 'CONFIGURATION.md', label: 'Configuration', description: 'Configure GoSQLX with a .gosqlx.yml file: format, validation, output and analyze options, defaults, file locations, precedence and CLI overrides.' },
    { slug: 'reference/error-codes', file: 'ERROR_CODES.md', label: 'Error Codes', description: 'Every GoSQLX error code from E1001 to E4002 covering tokenizer, parser, semantic and unsupported-feature failures, with causes and suggested fixes.' },
    { slug: 'reference/linting-rules', file: 'LINTING_RULES.md', label: 'Linting Rules', description: 'All 30 built-in GoSQLX linter rules, L001 to L030, with what each checks, why it matters, example violations, fixes and auto-fix support.' },
    { slug: 'reference/sql-compatibility', file: 'SQL_COMPATIBILITY.md', label: 'SQL Compatibility', description: 'Which SQL syntax GoSQLX supports across PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake and ClickHouse, with a dialect coverage matrix.' },
  ]},
  { category: 'Concepts', summary: 'How GoSQLX works and the guarantees it makes.', items: [
    { slug: 'concepts/architecture', file: 'ARCHITECTURE.md', label: 'Architecture', description: 'How GoSQLX is built: the zero-copy tokenizer, recursive descent parser, AST and visitor pattern, object pools and package dependencies, explained.' },
    { slug: 'concepts/security', file: 'SECURITY.md', label: 'Security Model', description: 'The GoSQLX security model: test results, architecture, CLI input sanitization, best practices for users, hardening, and the SQL injection scanner.' },
  ]},
  { category: 'Migration', summary: 'Upgrade between GoSQLX releases, or move to GoSQLX from other SQL parsers and linters.', items: [
    { slug: 'migration/upgrading', file: 'MIGRATION.md', label: 'Upgrading GoSQLX', description: 'Upgrade GoSQLX between releases: new APIs worth adopting, behavior changes to check, deprecations and companion component versions, release by release.' },
    { slug: 'migration/from-jsqlparser', file: 'migration/FROM_JSQLPARSER.md', label: 'From JSQLParser', description: 'Migrate from JSqlParser to GoSQLX: how Java parsing concepts map to Go APIs, equivalent AST nodes, visitor usage and a step-by-step porting checklist.' },
    { slug: 'migration/from-pg-query', file: 'migration/FROM_PG_QUERY.md', label: 'From pg_query', description: 'Migrate from pg_query_go to GoSQLX: swap the cgo dependency for a pure Go parser, map AST nodes and functions, and handle multiple SQL dialects.' },
    { slug: 'migration/from-sqlfluff', file: 'migration/FROM_SQLFLUFF.md', label: 'From SQLFluff', description: 'Migrate from SQLFluff to GoSQLX: map lint rules and configuration to GoSQLX equivalents, compare speed and dialects, and move CI checks over.' },
  ]},
];

/** Stable DOM id for a docs category card on /docs/ (breadcrumb anchor target). */
export function docsCategoryAnchor(category: string): string {
  return category.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
