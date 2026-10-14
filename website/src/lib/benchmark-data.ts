/**
 * Single source of truth for every benchmark number shown on the site.
 *
 * Values come from `BenchmarkPerformanceBaseline` (pkg/sql/parser), the parse
 * stage only (pre-tokenized input -> AST via ParseFromModelTokens), median of
 * 10 runs with -benchmem, and are recorded in `performance_baselines.json`
 * (`current_performance`). They are NOT tokenize or end-to-end numbers.
 *
 * Competitor numbers are intentionally absent until the reproducible benchmark
 * harness (issue #673) lands; after that they may only come from its committed
 * JSON output.
 */

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

export const HEADLINE_OPS = formatOps(opsPerSec(PARSE_BENCHMARKS[0].nsPerOp));
