/**
 * Competitor benchmark data (issue #673). SERVER-ONLY: import this from server
 * components only, never from a client component or a module a client component
 * imports (such as metrics.ts), or the harness JSON lands in the client bundle.
 */

import competitorRun from './competitor-benchmarks.json';

/*
 * Competitor comparison (issue #673). The JSON is a verbatim copy of
 * benchmarks/compare/results/latest.json, produced by `task bench:publish`;
 * `scripts/check-metrics-drift.mjs` fails if the two diverge. Never type a
 * competitor number by hand.
 */
export interface CompetitorParser {
  id: string;
  name: string;
  module: string;
  version: string;
  dialect: string;
  cgo: boolean;
}

export interface CompetitorQuery {
  id: string;
  name: string;
  sql: string;
}

export interface CompetitorResult {
  query: string;
  parser: string;
  supported: boolean;
  samples: number;
  /** Median ns/op; null when the parser rejects the query. */
  nsPerOp: number | null;
  bytesPerOp: number | null;
  allocsPerOp: number | null;
}

export interface CompetitorRun {
  schemaVersion: number;
  generatedAt: string;
  commit: string;
  dirty: boolean;
  goVersion: string;
  hardware: { cpu: string; goos: string; goarch: string; numCPU: number };
  stage: string;
  method: { command: string; count: number; statistic: string; rawOutput: string };
  caveat: string;
  parsers: CompetitorParser[];
  queries: CompetitorQuery[];
  results: CompetitorResult[];
}

export const COMPETITOR_RUN: CompetitorRun = competitorRun;

/** Look up one (query, parser) result from the committed harness run. */
export function competitorResult(queryId: string, parserId: string): CompetitorResult | undefined {
  return COMPETITOR_RUN.results.find((r) => r.query === queryId && r.parser === parserId);
}
