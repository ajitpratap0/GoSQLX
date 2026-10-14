import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';
import { RawDataToggle } from '@/components/benchmarks/RawDataToggle';
import { ParseChart } from '@/components/benchmarks/ParseChart';
import { BENCH_ENV, PARSE_BENCHMARKS, formatOps, opsPerSec } from '@/data/metrics';

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

function renderMethodologyItem(item: string) {
  const FLAG = '-benchmem';
  const idx = item.indexOf(FLAG);
  if (idx === -1) return <>{item}</>;
  return (
    <>
      {item.slice(0, idx)}
      <code className="font-mono text-xs bg-white/[0.06] px-1 py-0.5 rounded">{FLAG}</code>
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
            <p className="mt-3 text-xs text-zinc-500">
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
              <p className="text-xs text-zinc-500 mt-2 md:hidden">&larr; Swipe to see all columns &rarr;</p>
            </RawDataToggle>
          </FadeIn>
        </div>
      </section>

      {/* Competitor comparison: withheld until the reproducible harness (#673) lands */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-4">Competitor Comparison</h2>
            <GlassCard className="p-6" hover={false}>
              <p className="text-sm text-zinc-300">
                Head-to-head numbers against other Go SQL parsers are not published yet. They will
                return once a reproducible benchmark harness is committed to the repository, so every
                figure can be re-run by you. Until then, see the{' '}
                <a href="/compare/" className="text-indigo-300 underline underline-offset-2">
                  qualitative feature comparison
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
