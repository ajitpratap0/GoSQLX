/**
 * Per-competitor "alternative" pages (issue #675). Prose only: every performance
 * figure is read at render time from the committed harness JSON via
 * @/data/competitor-metrics (#673). Never type a competitor number here.
 * SERVER-ONLY (the data module must not reach a client bundle).
 */

export interface CompetitorPage {
  /** URL segment under /compare/. */
  slug: string;
  /** Parser id in the harness JSON; null for tools the harness does not cover. */
  parserId: string | null;
  name: string;
  /** Short label used in titles. */
  short: string;
  repo: string;
  /** Heading summary. */
  summary: string;
  description: string;
  /** Plain-language facts, each one verifiable from the linked repo or the harness JSON. */
  facts: { label: string; value: string }[];
  pickThem: string[];
  pickGoSQLX: string[];
  /** Dated source for any maintenance claim. */
  maintenance?: { before: string; linkText: string; after: string; href: string };
  migrationDoc?: { label: string; slug: string };
}

export const COMPETITOR_PAGES: CompetitorPage[] = [
  {
    slug: 'pg-query-go',
    parserId: 'pg_query_go',
    name: 'pg_query_go',
    short: 'pg_query_go',
    repo: 'https://github.com/pganalyze/pg_query_go',
    summary:
      'pg_query_go wraps the real PostgreSQL parser (libpg_query) through CGo, so it is the exact PostgreSQL grammar.',
    description:
      'GoSQLX as a pg_query_go alternative: pure Go, no CGo, multi-dialect. When to pick each, with reproducible end-to-end parse numbers.',
    facts: [
      { label: 'Approach', value: 'Bindings to PostgreSQL’s own parser, converted to Go structs' },
      { label: 'Dialect', value: 'PostgreSQL only' },
      { label: 'CGo required', value: 'Yes (needs a C toolchain, complicates cross-compilation)' },
    ],
    pickThem: [
      'You need exact PostgreSQL grammar fidelity, including every syntax edge case, because it is the same parser the server uses.',
      'You only target PostgreSQL and already build with CGo.',
      'You need parse-tree compatibility with other pg_query bindings.',
    ],
    pickGoSQLX: [
      'You want a pure Go dependency: no CGo, easy cross-compilation, WASM builds.',
      'You work with more than one dialect (PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, ClickHouse).',
      'You also want formatting, linting, security scanning, an LSP or an MCP server from the same library.',
    ],
    migrationDoc: { label: 'Migrating from pg_query', slug: 'migration/from-pg-query' },
  },
  {
    slug: 'vitess-sqlparser',
    parserId: 'vitess',
    name: 'Vitess sqlparser',
    short: 'vitess-sqlparser',
    repo: 'https://github.com/vitessio/vitess',
    summary:
      'The Vitess sqlparser (vitess.io/vitess/go/vt/sqlparser) is the MySQL parser used by Vitess, written in Go.',
    description:
      'GoSQLX as a Vitess sqlparser alternative: multi-dialect, standalone module. Where Vitess fits better, and reproducible end-to-end parse numbers.',
    facts: [
      { label: 'Approach', value: 'yacc-generated MySQL grammar inside the Vitess module' },
      { label: 'Dialect', value: 'MySQL' },
      { label: 'CGo required', value: 'No' },
    ],
    pickThem: [
      'You target MySQL and want the parser that powers Vitess, including its MySQL-specific AST and rewriting tools.',
      'You already depend on the Vitess module for sharding or routing.',
      'Your queries are MySQL only and you want the parser the MySQL ecosystem in Go builds on.',
    ],
    pickGoSQLX: [
      'You need more than MySQL: PostgreSQL, SQL Server, Oracle, SQLite, Snowflake and ClickHouse dialects as well.',
      'You want a standalone parser module instead of importing a subpackage of a large project.',
      'You want formatter, linter, security scanner and IDE tooling alongside the parser.',
    ],
  },
  {
    slug: 'xwb1989-sqlparser',
    parserId: 'xwb1989',
    name: 'xwb1989/sqlparser',
    short: 'xwb1989/sqlparser',
    repo: 'https://github.com/xwb1989/sqlparser',
    summary:
      'xwb1989/sqlparser is a standalone MySQL parser extracted from Vitess. It is widely imported, but its last commit was 2018-06-06.',
    description:
      'GoSQLX as an xwb1989/sqlparser alternative: maintained, multi-dialect, with CTE and window function support. Dated maintenance facts and reproducible numbers.',
    facts: [
      { label: 'Approach', value: 'Fork of the Vitess MySQL parser, extracted as a standalone package' },
      { label: 'Dialect', value: 'MySQL' },
      { label: 'CGo required', value: 'No' },
    ],
    pickThem: [
      'You have an existing integration that only uses simple MySQL statements and it works for you.',
      'You need the exact AST shape of this package for code you cannot change yet.',
    ],
    pickGoSQLX: [
      'You need syntax this parser rejects in the benchmark run below, such as CTEs and window functions.',
      'You want a dependency that still receives releases.',
      'You need other dialects, or formatting, linting and security scanning.',
    ],
    maintenance: {
      before: 'Latest commit on the default branch: ',
      linkText: '2018-06-06 (120387863bf2)',
      after: '. This is the version pinned in the benchmark harness.',
      href: 'https://github.com/xwb1989/sqlparser/commit/120387863bf27d04bc07db8015110a6e96d0146c',
    },
  },
  {
    slug: 'tidb-parser',
    parserId: 'tidb',
    name: 'TiDB parser',
    short: 'TiDB parser',
    repo: 'https://github.com/pingcap/tidb/tree/master/pkg/parser',
    summary:
      'The TiDB parser (github.com/pingcap/tidb/pkg/parser) is the MySQL-compatible parser of the TiDB database, written in Go.',
    description:
      'GoSQLX as a TiDB parser alternative: multi-dialect, self-contained. When the TiDB parser is the right pick, with reproducible parse numbers.',
    facts: [
      { label: 'Approach', value: 'yacc-generated MySQL-compatible grammar from the TiDB project' },
      { label: 'Dialect', value: 'MySQL (TiDB flavour)' },
      { label: 'CGo required', value: 'No' },
    ],
    pickThem: [
      'You target MySQL or TiDB and want TiDB-specific syntax and its AST visitors.',
      'You are building tooling around TiDB and want to match how the database itself parses SQL.',
    ],
    pickGoSQLX: [
      'You need dialects beyond MySQL.',
      'You want a self-contained module with formatting, linting and security scanning included.',
      'You want to avoid importing a subpackage of a database server module.',
    ],
  },
  {
    slug: 'sqlfluff',
    parserId: null,
    name: 'SQLFluff',
    short: 'SQLFluff',
    repo: 'https://github.com/sqlfluff/sqlfluff',
    summary:
      'SQLFluff is a Python SQL linter and auto-formatter with a large dialect list and templating support (Jinja, dbt).',
    description:
      'GoSQLX as a SQLFluff alternative for linting and formatting: what moves over, what does not, and when to stay with SQLFluff.',
    facts: [
      { label: 'Language', value: 'Python (CLI and library)' },
      { label: 'Focus', value: 'Linting and auto-formatting, including templated SQL' },
      { label: 'Benchmarked here', value: 'No: the harness compares Go parsers only, so this page has no speed figures' },
    ],
    pickThem: [
      'You lint templated SQL (Jinja, dbt) and need the templater to run before linting.',
      'You rely on SQLFluff’s larger dialect list or its rule set and configuration conventions.',
      'Your pipeline is Python and you want a Python API.',
    ],
    pickGoSQLX: [
      'You want a single static Go binary for CI, with no Python runtime to install.',
      'You embed linting, parsing or formatting in a Go service, or need an LSP or MCP server.',
      'Your SQL is untemplated and covered by the supported dialects.',
    ],
    migrationDoc: { label: 'Migrating from SQLFluff', slug: 'migration/from-sqlfluff' },
  },
];

export function getCompetitorPage(slug: string): CompetitorPage | undefined {
  return COMPETITOR_PAGES.find((c) => c.slug === slug);
}
