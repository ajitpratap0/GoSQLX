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
 * median of 10 runs with -benchmem, and are recorded in
 * `performance_baselines.json` (`current_performance`). They are NOT tokenize
 * or end-to-end numbers. This file is seeded by hand from that JSON; it will
 * later be fed by the generated metrics.json (plan section 5.2).
 *
 * Competitor numbers are intentionally absent until the reproducible benchmark
 * harness (issue #673) lands; after that they may only come from its committed
 * JSON output.
 */

/** Project facts (not performance). */
export const PROJECT = {
  /** Latest released tag. */
  version: 'v1.15.0',
  /** Dialects supported (PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, ClickHouse). */
  dialectCount: 8,
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
  release: 'v1.14.0',
  snowflake: { pass: 87, total: 87 },
  clickhouse: { pass: 69, total: 83 },
} as const;

export const BENCH_ENV = {
  hardware: 'Apple M4',
  goVersion: 'Go 1.27',
  stage: 'parse stage',
  source: 'BenchmarkPerformanceBaseline, median of 10 runs, re-measured 2026-10-13',
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
  { name: 'Simple SELECT', query: 'SELECT id, name FROM users', nsPerOp: 318, ciBaselineNs: 800 },
  { name: 'INSERT', query: 'Simple INSERT statement', nsPerOp: 382, ciBaselineNs: 950 },
  { name: 'CTE', query: 'WITH clause', nsPerOp: 561, ciBaselineNs: 1400 },
  { name: 'Window Function', query: 'ROW_NUMBER() OVER (PARTITION BY ... ORDER BY ...)', nsPerOp: 585, ciBaselineNs: 1500 },
  { name: 'Complex Query', query: 'JOIN, WHERE, ORDER BY, LIMIT', nsPerOp: 1165, ciBaselineNs: 2900 },
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
