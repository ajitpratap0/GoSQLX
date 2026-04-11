'use client';

import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';

const metrics = [
  { label: 'Sustained Ops/sec', value: '1.38M+' },
  { label: 'Tokens/sec', value: '8M+' },
  { label: 'Concurrent Ops Tested', value: '20K+' },
];

const benchmarks = [
  { name: 'Simple SELECT', query: 'SELECT *', m4: '1.40M ops/sec', baseline: '1.38M ops/sec' },
  { name: 'Complex Query', query: 'Multi-JOIN', m4: '376K ops/sec', baseline: '380K ops/sec' },
  { name: 'Window Function', query: 'ROW_NUMBER OVER', m4: '848K ops/sec', baseline: '350K ops/sec' },
  { name: 'CTE', query: 'WITH RECURSIVE', m4: '833K ops/sec', baseline: '310K ops/sec' },
  { name: 'INSERT', query: 'Multi-row', m4: '992K ops/sec', baseline: '820K ops/sec' },
];

const methodology = [
  'Go 1.26+ on Apple Silicon (local) and GitHub Actions runners (CI baseline)',
  'Each benchmark runs for a minimum of 1 second with -benchmem',
  'Race detector disabled during benchmarks (adds 3\u20135x overhead)',
  'Object pooling enabled for all runs (production configuration)',
  'Results averaged over 5 consecutive runs to reduce variance',
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
              Real-world performance data from the GoSQLX parser, measured on production-grade hardware.
            </p>
            <p className="mt-3 text-xs text-zinc-500">
              Last updated: April 2026 &middot; Based on v1.14.0
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

      {/* Benchmark Table */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-4">Parse Benchmarks</h2>
            <GlassCard className="p-0 overflow-hidden" hover={false}>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <caption className="sr-only">GoSQLX Parse Benchmarks</caption>
                  <thead>
                    <tr className="border-b border-white/[0.06]">
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Benchmark</th>
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Query Type</th>
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Apple M4</th>
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Baseline (CI)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {benchmarks.map((b) => (
                      <tr
                        key={b.name}
                        className="border-b border-white/[0.04] hover:bg-white/[0.03] transition-colors"
                      >
                        <td className="px-3 py-3 sm:px-6 sm:py-4 text-white font-medium">{b.name}</td>
                        <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">{b.query}</td>
                        <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-300 font-mono">{b.m4}</td>
                        <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400 font-mono">{b.baseline}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </GlassCard>
            <p className="text-xs text-zinc-500 mt-2 md:hidden">&larr; Swipe to see all columns &rarr;</p>
          </FadeIn>
        </div>
      </section>

      {/* Competitor Comparison */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-6">Competitor Comparison</h2>
            <GlassCard className="p-0 overflow-hidden" hover={false}>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <caption className="sr-only">Competitor Library Comparison</caption>
                  <thead>
                    <tr className="border-b border-white/[0.06]">
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Library</th>
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Language</th>
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Ops/sec</th>
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Memory/op</th>
                      <th scope="col" className="px-3 py-3 sm:px-6 sm:py-4 font-medium text-zinc-400">Zero-copy</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-white/[0.04] transition-colors bg-indigo-500/10 border-l-2 border-l-indigo-500">
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-white font-medium">
                        GoSQLX{' '}
                        <span className="ml-2 inline-block rounded-full bg-indigo-500/20 px-2 py-0.5 text-xs font-medium text-indigo-300">
                          This Library
                        </span>
                      </td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">Go</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-300 font-mono">1.38M+</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-300">Low</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-accent-green font-medium">
                        <span aria-label="Yes">✓</span>
                      </td>
                    </tr>
                    <tr className="border-b border-white/[0.04] hover:bg-white/[0.03] transition-colors">
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-300 font-medium">xwb1989/sqlparser</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">Go</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400 font-mono">~380K</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">Higher</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-500">
                        <span aria-label="No">✗</span>
                      </td>
                    </tr>
                    <tr className="border-b border-white/[0.04] hover:bg-white/[0.03] transition-colors">
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-300 font-medium">pg_query_go</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">Go</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400 font-mono">~220K</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">Higher (CGo)</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-500">
                        <span aria-label="No">✗</span>
                      </td>
                    </tr>
                    <tr className="border-b border-white/[0.04] hover:bg-white/[0.03] transition-colors">
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-300 font-medium">blastrain/sqlparser</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">Go</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400 font-mono">~290K</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-400">Medium</td>
                      <td className="px-3 py-3 sm:px-6 sm:py-4 text-zinc-500">
                        <span aria-label="No">✗</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </GlassCard>
            <p className="text-xs text-zinc-500 mt-2 md:hidden">&larr; Swipe to see all columns &rarr;</p>
            <p className="text-xs text-zinc-500 mt-2">* Competitor figures estimated from published benchmarks on equivalent hardware. Results may vary by query complexity.</p>
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
