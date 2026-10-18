/**
 * Expands benchmark placeholders in blog articles into markdown generated from
 * the committed competitor harness JSON (issue #673). Articles never contain a
 * hand-typed competitor figure: every number below is read from COMPETITOR_RUN.
 *
 * SERVER-ONLY: imports competitor-metrics.ts.
 *
 * Placeholders (one per line or inline):
 *   {{bench:env}}            hardware, OS/arch, Go version, commit and date
 *   {{bench:command}}        the exact command the harness ran
 *   {{bench:caveat}}         the harness caveat text
 *   {{bench:libraries}}      table of libraries, pinned versions and dialects
 *   {{bench:queries}}        table of the corpus statements
 *   {{bench:table:ns}}       median ns/op for every (query, library)
 *   {{bench:table:allocs}}   median allocs/op for every (query, library)
 *   {{bench:table:bytes}}    median B/op for every (query, library)
 *   {{bench:table:summary}}  per-library summary relative to GoSQLX
 */
import {
  COMPETITOR_RUN,
  competitorResult,
  type CompetitorResult,
} from '@/data/competitor-metrics';

const BASE_ID = 'gosqlx';

type Metric = 'nsPerOp' | 'allocsPerOp' | 'bytesPerOp';

function fmtNumber(n: number): string {
  return n >= 100 ? Math.round(n).toLocaleString('en-US') : String(n);
}

function cell(r: CompetitorResult | undefined, metric: Metric): string {
  if (!r || !r.supported) return 'rejected';
  const v = r[metric];
  return v === null ? 'n/a' : fmtNumber(v);
}

function escapeCell(s: string): string {
  return s.replace(/\|/g, '\\|');
}

function metricTable(metric: Metric): string {
  const { parsers, queries } = COMPETITOR_RUN;
  const head = `| Query | ${parsers.map((p) => p.name).join(' | ')} |`;
  const sep = `|---|${parsers.map(() => '---:').join('|')}|`;
  const rows = queries.map(
    (q) => `| ${q.name} | ${parsers.map((p) => cell(competitorResult(q.id, p.id), metric)).join(' | ')} |`,
  );
  return [head, sep, ...rows].join('\n');
}

function geometricMean(values: number[]): number {
  return Math.exp(values.reduce((acc, v) => acc + Math.log(v), 0) / values.length);
}

/** Per-library comparison against GoSQLX over the queries both accept. */
function summaryTable(): string {
  const rows = COMPETITOR_RUN.parsers
    .filter((p) => p.id !== BASE_ID)
    .map((p) => {
      const ratios: number[] = [];
      let fasterThanBase = 0;
      let rejected = 0;
      for (const q of COMPETITOR_RUN.queries) {
        const base = competitorResult(q.id, BASE_ID);
        const other = competitorResult(q.id, p.id);
        if (!other || !other.supported || other.nsPerOp === null) {
          rejected++;
          continue;
        }
        if (!base || !base.supported || base.nsPerOp === null) continue;
        ratios.push(other.nsPerOp / base.nsPerOp);
        if (other.nsPerOp < base.nsPerOp) fasterThanBase++;
      }
      const gm = ratios.length > 0 ? `${geometricMean(ratios).toFixed(2)}x` : 'n/a';
      return `| ${p.name} | ${p.cgo ? 'yes' : 'no'} | ${ratios.length} | ${rejected} | ${fasterThanBase} of ${ratios.length} | ${gm} |`;
    });
  return [
    '| Library | CGo | Queries compared | Queries rejected | Faster than GoSQLX on | Time relative to GoSQLX (geometric mean) |',
    '|---|---|---:|---:|---:|---:|',
    ...rows,
  ].join('\n');
}

function librariesTable(): string {
  return [
    '| Library | Module | Version | Dialect | CGo |',
    '|---|---|---|---|---|',
    ...COMPETITOR_RUN.parsers.map(
      (p) => `| ${p.name} | \`${p.module}\` | \`${p.version}\` | ${escapeCell(p.dialect)} | ${p.cgo ? 'yes' : 'no'} |`,
    ),
  ].join('\n');
}

function queriesTable(): string {
  return [
    '| Query | SQL |',
    '|---|---|',
    ...COMPETITOR_RUN.queries.map((q) => `| ${q.name} | \`${escapeCell(q.sql)}\` |`),
  ].join('\n');
}

function envLine(): string {
  const { hardware, goVersion, commit, generatedAt, method } = COMPETITOR_RUN;
  const date = generatedAt.slice(0, 10);
  return (
    `${hardware.cpu} (${hardware.goos}/${hardware.goarch}, ${hardware.numCPU} CPUs), ${goVersion}, ` +
    `GoSQLX commit \`${commit.slice(0, 12)}\`, run on ${date}; ${method.statistic} of ${method.count} runs, ` +
    `${COMPETITOR_RUN.stage === 'e2e' ? 'end-to-end stage (SQL text in, AST out)' : `${COMPETITOR_RUN.stage} stage`}`
  );
}

const EXPANSIONS: Record<string, () => string> = {
  env: envLine,
  command: () => `\`${COMPETITOR_RUN.method.command}\``,
  caveat: () => COMPETITOR_RUN.caveat,
  libraries: librariesTable,
  queries: queriesTable,
  'table:ns': () => metricTable('nsPerOp'),
  'table:allocs': () => metricTable('allocsPerOp'),
  'table:bytes': () => metricTable('bytesPerOp'),
  'table:summary': summaryTable,
};

const PLACEHOLDER = /\{\{bench:([a-z:]+)\}\}/g;

/** Replace every {{bench:...}} placeholder; unknown placeholders fail the build. */
export function expandBenchPlaceholders(markdown: string, source: string): string {
  return markdown.replace(PLACEHOLDER, (_m, key: string) => {
    const fn = EXPANSIONS[key];
    if (!fn) throw new Error(`${source}: unknown benchmark placeholder {{bench:${key}}}`);
    return fn();
  });
}
