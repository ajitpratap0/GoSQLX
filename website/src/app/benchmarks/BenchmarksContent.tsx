import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';
import { RawDataToggle } from '@/components/benchmarks/RawDataToggle';
import { ParseChart } from '@/components/benchmarks/ParseChart';
import {
  BENCH_ENV,
  PARSE_BENCHMARKS,
  formatOps,
  opsPerSec,
} from '@/data/metrics';
import { COMPETITOR_RUN, competitorResult } from '@/data/competitor-metrics';

const metrics = [
  {
    label: `Simple SELECT, parse stage (${BENCH_ENV.hardware})`,
    value: `${formatOps(opsPerSec(PARSE_BENCHMARKS[0].nsPerOp))} ops/sec`,
  },
  { label: 'Simple SELECT parse latency', value: `${PARSE_BENCHMARKS[0].nsPerOp} ns/op` },
  { label: 'Race detector in CI', value: 'Clean' },
];

const methodology = [
  `${BENCH_ENV.goVersion} on ${BENCH_ENV.hardware} (arm64); every figure is for the parse stage only (pre-tokenized input to AST), not tokenize or end-to-end`,
  `Source: ${BENCH_ENV.source}, run with -benchmem`,
  'Reproduce: go test -run ^$ -bench BenchmarkPerformanceBaseline -benchmem -count=10 ./pkg/sql/parser/',
  'Race detector disabled during benchmarks (adds 3\u20135x overhead)',
  'Object pooling enabled for all runs (production configuration)',
  'The CI regression baseline is a deliberately loose ceiling used with a tolerance on slower shared runners; it is not a measurement',
];

const measuredOn = COMPETITOR_RUN.generatedAt.slice(0, 10);

function formatNs(ns: number): string {
  return `${Math.round(ns).toLocaleString('en-US')} ns`;
}

/** Lowest median ns/op among the libraries that accept the query. */
function fastestNs(queryId: string): number | undefined {
  const values = COMPETITOR_RUN.results.flatMap((r) =>
    r.query === queryId && r.supported && r.nsPerOp !== null ? [r.nsPerOp] : [],
  );
  return values.length > 0 ? Math.min(...values) : undefined;
}

function renderMethodologyItem(item: string) {
  const FLAG = '-benchmem';
  const idx = item.indexOf(FLAG);
  if (idx === -1) return <>{item}</>;
  return (
    <>
      {item.slice(0, idx)}
      <code className="font-mono text-xs text-fg bg-fg/[0.06] px-1 py-0.5 rounded">{FLAG}</code>
      {item.slice(idx + FLAG.length)}
    </>
  );
}

export function BenchmarksContent() {
  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="section-padding pt-24 pb-16 text-center">
        <div className="container-width">
          <FadeIn>
            <h1 className="text-4xl font-bold tracking-tight text-white">
              Performance Benchmarks
            </h1>
            <p className="mt-4 text-lg text-zinc-400 max-w-2xl mx-auto">
              Parse-stage performance of the GoSQLX parser, re-measured with the in-repo benchmarks.
            </p>
            <p className="mt-3 text-xs text-fg-subtle">
              Measured 2026-10-13 &middot; Apple M4 &middot; Go 1.27 &middot; parse stage only
            </p>
          </FadeIn>
        </div>
      </section>

      {/* Metric Cards */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
            {metrics.map((m, i) => (
              <FadeIn key={m.label} delay={i * 0.1}>
                <GlassCard className="p-6 text-center">
                  <div className="text-3xl font-bold text-white">{m.value}</div>
                  <div className="mt-1 text-sm text-zinc-400">{m.label}</div>
                </GlassCard>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* Parse Benchmarks Chart + Table */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-4">Parse Benchmarks</h2>
            <GlassCard className="p-6" hover={false}>
              <ParseChart />
            </GlassCard>

            <RawDataToggle id="parse">
              <GlassCard className="p-0 overflow-hidden" hover={false}>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <caption className="sr-only">GoSQLX Parse Benchmarks</caption>
                    <thead>
                      <tr className="border-b border-white/[0.06]">
                        <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Benchmark</th>
                        <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Query Type</th>
                        <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Apple M4 (median)</th>
                        <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">CI tolerance baseline</th>
                      </tr>
                    </thead>
                    <tbody>
                      {PARSE_BENCHMARKS.map((b) => (
                        <tr
                          key={b.name}
                          className="border-b border-white/[0.04] hover:bg-white/[0.03] transition-colors"
                        >
                          <td className="px-3 py-3 sm:px-6 sm:py-4 text-white font-medium">{b.name}</td>
                          <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">{b.query}</td>
                          <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-300 font-mono">{b.nsPerOp} ns/op ({formatOps(opsPerSec(b.nsPerOp))} ops/sec)</td>
                          <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400 font-mono">&le; {b.ciBaselineNs} ns/op</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </GlassCard>
              <p className="text-xs text-fg-subtle mt-2 md:hidden">&larr; Swipe to see all columns &rarr;</p>
            </RawDataToggle>
          </FadeIn>
        </div>
      </section>

      {/* Competitor comparison: every number comes from the committed harness JSON (#673) */}
      <section className="section-padding pb-16" id="competitors">
        <div className="container-width">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-2">Competitor Comparison</h2>
            <p className="text-xs text-fg-subtle mb-4">
              End-to-end stage (SQL text to AST) &middot; {COMPETITOR_RUN.hardware.cpu} (
              {COMPETITOR_RUN.hardware.goos}/{COMPETITOR_RUN.hardware.goarch}) &middot;{' '}
              {COMPETITOR_RUN.goVersion} &middot; {COMPETITOR_RUN.method.statistic} of{' '}
              {COMPETITOR_RUN.method.count} runs &middot; measured {measuredOn} &middot; commit{' '}
              <code className="font-mono">{COMPETITOR_RUN.commit.slice(0, 7)}</code>
            </p>
            <GlassCard className="p-0 overflow-hidden" hover={false}>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <caption className="sr-only">
                    Median nanoseconds per statement, end-to-end, lower is faster
                  </caption>
                  <thead>
                    <tr className="border-b border-white/[0.06]">
                      <th scope="col" className="px-3 py-3 sm:px-4 sm:py-4 font-medium text-zinc-400">Query</th>
                      {COMPETITOR_RUN.parsers.map((p) => (
                        <th key={p.id} scope="col" className="px-3 py-3 sm:px-4 sm:py-4 font-medium text-zinc-400 whitespace-nowrap">
                          {p.name}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {COMPETITOR_RUN.queries.map((q) => {
                      const fastest = fastestNs(q.id);
                      return (
                        <tr key={q.id} className="border-b border-white/[0.04]">
                          <th scope="row" className="px-3 py-3 sm:px-4 sm:py-4 text-white font-medium" title={q.sql}>
                            {q.name}
                          </th>
                          {COMPETITOR_RUN.parsers.map((p) => {
                            const r = competitorResult(q.id, p.id);
                            if (!r || !r.supported || r.nsPerOp === null) {
                              return (
                                <td key={p.id} className="px-3 py-3 sm:px-4 sm:py-4 text-fg-subtle whitespace-nowrap">
                                  not supported
                                </td>
                              );
                            }
                            const isFastest = r.nsPerOp === fastest;
                            return (
                              <td
                                key={p.id}
                                className={`px-3 py-3 sm:px-4 sm:py-4 font-mono whitespace-nowrap ${isFastest ? 'text-white font-semibold' : 'text-zinc-300'}`}
                              >
                                {formatNs(r.nsPerOp)}
                              </td>
                            );
                          })}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </GlassCard>
            <p className="text-xs text-fg-subtle mt-2">
              Median ns per statement; lower is faster and the fastest library per query is in bold.
              Hover a query name to see its SQL.
            </p>
            <p className="text-xs text-fg-subtle mt-1 md:hidden">&larr; Swipe to see all columns &rarr;</p>

            <GlassCard className="p-6 mt-6" hover={false}>
              <p className="text-sm text-zinc-300">
                <strong className="text-white">Read with care.</strong> {COMPETITOR_RUN.caveat}
              </p>
              <ul className="mt-4 space-y-1 text-xs text-zinc-400">
                {COMPETITOR_RUN.parsers.map((p) => (
                  <li key={p.id}>
                    <span className="text-zinc-300">{p.name}</span>: <code className="font-mono">{p.module}</code>{' '}
                    {p.version} &middot; {p.dialect}
                  </li>
                ))}
              </ul>
              <p className="mt-4 text-sm text-zinc-300">
                Reproduce with <code className="font-mono text-xs text-fg bg-fg/[0.06] px-1 py-0.5 rounded">task bench:publish</code>{' '}
                using the{' '}
                <a
                  href="https://github.com/ajitpratap0/GoSQLX/tree/main/benchmarks/compare"
                  className="text-accent underline underline-offset-2"
                >
                  benchmark harness
                </a>
                , which pins every library version and keeps the raw output for benchstat. See also the{' '}
                <a href="/compare/" className="text-accent underline underline-offset-2">
                  feature comparison
                </a>
                .
              </p>
            </GlassCard>
          </FadeIn>
        </div>
      </section>

      {/* Methodology */}
      <section className="section-padding pb-8">
        <div className="container-width max-w-2xl">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-6">Methodology</h2>
            <ul className="space-y-3">
              {methodology.map((item) => (
                <li key={item} className="flex items-start gap-3 text-sm text-zinc-400">
                  <span aria-hidden="true" className="mt-1.5 block h-1.5 w-1.5 rounded-full bg-zinc-400 shrink-0" />
                  <span>{renderMethodologyItem(item)}</span>
                </li>
              ))}
            </ul>
          </FadeIn>
        </div>
      </section>

      {/* CTA */}
      <section className="section-padding pb-24">
        <div className="container-width">
          <FadeIn>
            <div className="text-center">
              <p className="text-zinc-400 mb-4">Ready to use GoSQLX in your project?</p>
              <div className="flex gap-3 justify-center">
                <Button href="/docs/getting-started/" variant="primary">
                  Get Started
                </Button>
                <Button href="/playground/" variant="ghost">
                  Try Playground
                </Button>
              </div>
            </div>
          </FadeIn>
        </div>
      </section>
    </div>
  );
}
