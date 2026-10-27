/**
 * Single source of truth for every number shown on the site (issue #657).
 *
 * Components MUST import figures from here instead of hardcoding them;
 * `scripts/check-metrics-drift.mjs` (run in website CI) fails on known banned
 * literals outside this directory. Every performance figure is labelled with
 * its stage (tokenize / parse / end-to-end), hardware and Go version.
 *
 * Benchmark values come from `BenchmarkPerformanceBaseline` (pkg/sql/parser),
 * the parse stage only (pre-tokenized input -> AST via ParseFromModelTokens),
 * median of 20 runs with -benchmem, and are recorded in
 * `performance_baselines.json` (`current_performance`). They are NOT tokenize
 * or end-to-end numbers. This file is seeded by hand from that JSON; it will
 * later be fed by the generated metrics.json (plan section 5.2).
 *
 * Competitor numbers come only from the reproducible benchmark harness
 * (issue #673, benchmarks/compare). They live in ./competitor-metrics.ts, which
 * must only be imported by server code: this file is reachable from client
 * components (Navbar, Sidebar, ParseChart) and would otherwise ship the whole
 * harness JSON in a shared client chunk.
 */

/** Supported dialect names; the single source for PROJECT.dialectCount. */
export const DIALECT_NAMES = [
  'PostgreSQL',
  'MySQL',
  'MariaDB',
  'SQL Server',
  'Oracle',
  'SQLite',
  'Snowflake',
  'ClickHouse',
] as const;

/** Project facts (not performance). */
export const PROJECT = {
  /** Latest released tag. */
  version: 'v1.16.0',
  /** Dialects supported (PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, ClickHouse). */
  dialectCount: DIALECT_NAMES.length,
  /** Built-in linter rules L001-L030. */
  lintRuleCount: 30,
  /** MCP tools exposed by the gosqlx MCP server. */
  mcpToolCount: 7,
  /** Minimum supported Go version. */
  minGo: 'Go 1.26+',
  /** Top-level Go test functions under pkg/ and cmd/ (counted 2026-10-14; a floor, rounded down). */
  testFunctions: 3100,
  /** SQL-99 compliance is an estimate, see docs/sql99-compliance-analysis.md. */
  sql99: '~80\u201385%',
} as const;

/** QA-corpus pass rates, labelled with the release they were measured on. */
export const QA_CORPUS = {
  release: 'v1.15.0',
  snowflake: { pass: 87, total: 87 },
  clickhouse: { pass: 83, total: 83 },
} as const;

/**
 * Real-world dialect corpus (testdata/realworld/<dialect>/*.sql), added in
 * PR #866 and brought to zero known failures in PR #867 (CHANGELOG.md
 * [Unreleased], lines 15-26). Every statement goes through split, parse,
 * format, reparse, format idempotency and a dropped-word check;
 * TestRealWorldCorpus (pkg/gosqlx/realworld_corpus_test.go) enforces it in CI
 * against testdata/realworld/known_failures.txt as a ratchet.
 *
 * Counts were taken from `go run ./scripts/dialect-audit` at `sourceCommit`
 * (each run printed failed=0). Not in a release yet: while `released` is
 * false, every place that shows these figures must say so.
 */
const REALWORLD_PER_DIALECT = {
  postgresql: { pass: 300, total: 300 },
  mysql: { pass: 405, total: 405 },
  mariadb: { pass: 374, total: 374 },
  sqlserver: { pass: 276, total: 276 },
  oracle: { pass: 368, total: 368 },
  sqlite: { pass: 348, total: 348 },
  snowflake: { pass: 325, total: 325 },
  clickhouse: { pass: 392, total: 392 },
} as const;

const realworldSum = (field: 'pass' | 'total') =>
  Object.values(REALWORLD_PER_DIALECT).reduce((n, d) => n + d[field], 0);

export const REALWORLD_CORPUS = {
  released: false,
  /** origin/main commit the counts were measured on. */
  sourceCommit: '8d8c5272',
  /** Passing and total statements per dialect; keys are the parser dialect strings. */
  perDialect: REALWORLD_PER_DIALECT,
  /** 2,788 at sourceCommit (sum of perDialect). */
  total: realworldSum('total'),
  /** Every corpus statement passes; known_failures.txt is empty. */
  passing: realworldSum('pass'),
  failing: realworldSum('total') - realworldSum('pass'),
  /** Reproduce one dialect's figure from a repo checkout; replace <d> with a dialect key. */
  command: 'go run ./scripts/dialect-audit -dialect <d> testdata/realworld/<d>/*.sql',
} as const;

export type RealWorldDialect = keyof typeof REALWORLD_CORPUS.perDialect;

/** Qualifier shown next to corpus figures until they ship in a tagged release. */
export const REALWORLD_STATUS = REALWORLD_CORPUS.released ? '' : 'on main, next release';

export const BENCH_ENV = {
  hardware: 'Apple M4',
  goVersion: 'Go 1.27',
  stage: 'parse stage',
  /** Date the PARSE_BENCHMARKS figures were re-measured (ISO). */
  measuredOn: '2026-10-22',
  /** Parse-stage benchmark source file and CI baseline file, as repo paths. */
  benchFile: 'pkg/sql/parser/performance_regression_test.go',
  baselinesFile: 'performance_baselines.json',
  source: 'BenchmarkPerformanceBaseline, median of 20 runs, re-measured 2026-10-22',
  /** Command that reproduces PARSE_BENCHMARKS from a repo checkout (summarise the 20 runs with benchstat). */
  command: "go test -run='^$' -bench=BenchmarkPerformanceBaseline -benchmem -count=20 ./pkg/sql/parser/",
} as const;

export interface ParseBenchmark {
  name: string;
  /** The query shape measured by BenchmarkPerformanceBaseline. */
  query: string;
  /** Median ns/op on Apple M4. */
  nsPerOp: number;
  /** Regression-test baseline (ns/op) used by CI with a tolerance; not a measurement. */
  ciBaselineNs: number;
}

export const PARSE_BENCHMARKS: ParseBenchmark[] = [
  { name: 'Simple SELECT', query: 'SELECT id, name FROM users', nsPerOp: 349, ciBaselineNs: 800 },
  { name: 'INSERT', query: 'Simple INSERT statement', nsPerOp: 406, ciBaselineNs: 950 },
  { name: 'CTE', query: 'WITH clause', nsPerOp: 644, ciBaselineNs: 1400 },
  { name: 'Window Function', query: 'ROW_NUMBER() OVER (PARTITION BY ... ORDER BY ...)', nsPerOp: 631, ciBaselineNs: 1500 },
  { name: 'Complex Query', query: 'JOIN, WHERE, ORDER BY, LIMIT', nsPerOp: 1234, ciBaselineNs: 2900 },
];

export function opsPerSec(nsPerOp: number): number {
  return Math.round(1e9 / nsPerOp);
}

export function formatOps(ops: number): string {
  if (ops >= 1_000_000) return `${(ops / 1_000_000).toFixed(2)}M`;
  return `${Math.round(ops / 1_000)}K`;
}


/** Parse-stage throughput for the simple SELECT, as a whole number of ops/sec. */
export const HEADLINE_OPS_PER_SEC = opsPerSec(PARSE_BENCHMARKS[0].nsPerOp);

/** Short stage-labelled caption for the headline figure. */
export const HEADLINE_CAPTION = `simple SELECT, ${BENCH_ENV.stage}, ${BENCH_ENV.hardware}, ${BENCH_ENV.goVersion}`;

/** "3,100+" style formatting for counts. */
export function formatCount(n: number): string {
  return `${n.toLocaleString('en-US')}+`;
}
