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
 *   {{bench:vitess}}         one sentence on Vitess vs GoSQLX (wins and geometric mean)
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

/** Escape plain (non-code-span) text for a GFM table cell: backslashes first, then pipes. */
function escapeCell(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/**
 * Escape text placed inside a backtick code span in a GFM table cell. Only the
 * pipe needs escaping (GFM strips the backslash before '|'); doubling
 * backslashes here would change the SQL shown, since code spans are literal.
 */
function escapeCodeCell(s: string): string {
  return s.split('|').join('\\|');
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

/** Compare one library to GoSQLX over the queries both accept. */
function compareToBase(id: string): { name: string; faster: number; total: number; gm: number } | null {
  const parser = COMPETITOR_RUN.parsers.find((p) => p.id === id);
  if (!parser) return null;
  const ratios: number[] = [];
  let faster = 0;
  for (const q of COMPETITOR_RUN.queries) {
    const base = competitorResult(q.id, BASE_ID);
    const other = competitorResult(q.id, id);
    if (!base || !base.supported || base.nsPerOp === null) continue;
    if (!other || !other.supported || other.nsPerOp === null) continue;
    ratios.push(other.nsPerOp / base.nsPerOp);
    if (other.nsPerOp < base.nsPerOp) faster++;
  }
  if (ratios.length === 0) return null;
  return { name: parser.name, faster, total: ratios.length, gm: geometricMean(ratios) };
}

/** Plain, data-driven sentence so the prose cannot drift from the JSON. */
function vitessSentence(): string {
  const c = compareToBase('vitess');
  if (!c) throw new Error('bench:vitess requires vitess and gosqlx results in the committed JSON');
  const gm = c.gm.toFixed(2);
  const base = `In this run ${c.name} is faster than GoSQLX on ${c.faster} of ${c.total} queries compared`;
  if (c.gm < 1) {
    return `${base}, and its geometric-mean time is ${gm}x GoSQLX's, so it is faster on most queries and on average (see the summary table).`;
  }
  return `${base}, and its geometric-mean time is ${gm}x GoSQLX's (see the summary table).`;
}

/** v0.0.0-20261015143638-7193401b6746 -> v0.0.0-…7193401b (full version stays in go.mod). */
function shortVersion(v: string): string {
  const m = /^(v\d+\.\d+\.\d+)-(?:[0-9a-z.]+\.)?\d{14}-([0-9a-f]{12})$/.exec(v);
  return m ? `${m[1]}-…${m[2].slice(0, 8)}` : v;
}

/** Keep the dialect cell to one short line: drop long parenthetical notes. */
function shortDialect(d: string): string {
  const i = d.indexOf(' (');
  return i > 0 && d.length - i > 12 ? d.slice(0, i) : d;
}

function librariesTable(): string {
  const table = [
    '| Library | Version | Dialect | CGo |',
    '|---|---|---|---|',
    ...COMPETITOR_RUN.parsers.map(
      (p) => `| ${p.name} | \`${shortVersion(p.version)}\` | ${escapeCell(shortDialect(p.dialect))} | ${p.cgo ? 'yes' : 'no'} |`,
    ),
  ].join('\n');
  const modules = COMPETITOR_RUN.parsers.map((p) => `${p.name}: \`${p.module}\``).join('; ');
  return `${table}\n\nModules: ${modules}. Pseudo-versions are shortened here; the full versions are in the harness's \`go.mod\`.`;
}

function queriesTable(): string {
  return [
    '| Query | SQL |',
    '|---|---|',
    ...COMPETITOR_RUN.queries.map((q) => `| ${q.name} | \`${escapeCodeCell(q.sql)}\` |`),
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
  vitess: vitessSentence,
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
