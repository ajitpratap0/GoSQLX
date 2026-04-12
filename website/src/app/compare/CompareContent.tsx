'use client';

import Link from 'next/link';
import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';

/* ------------------------------------------------------------------ */
/*  Data                                                               */
/* ------------------------------------------------------------------ */

const LIBRARIES = ['GoSQLX', 'pg_query_go', 'vitess-sqlparser', 'sqlparser (xwb1989)'] as const;

type FeatureRow = {
  feature: string;
  values: [string | boolean, string | boolean, string | boolean, string | boolean];
};

const FEATURES: FeatureRow[] = [
  { feature: 'Language',              values: ['Go',     'Go (C via CGo)', 'Go',   'Go'] },
  { feature: 'Ops/sec',              values: ['1.38M+', '~340K',          '~560K', '~220K'] },
  { feature: 'Memory/op',            values: ['~800B',  '~12KB',          '~4KB',  '~2KB'] },
  { feature: 'Zero-copy',            values: [true,  false, false, false] },
  { feature: 'Dialects',             values: ['8',   '1 (PostgreSQL)', '1 (MySQL)', '1 (MySQL)'] },
  { feature: 'CGo required',         values: [false, true,  false, false] },
  { feature: 'WASM support',         values: [true,  false, false, false] },
  { feature: 'SQL injection detection', values: [true,  false, false, false] },
  { feature: 'MCP server',           values: [true,  false, false, false] },
  { feature: 'SQL formatting',       values: [true,  false, false, false] },
  { feature: 'SQL linting (30 rules)', values: [true,  false, false, false] },
  { feature: 'LSP server',           values: [true,  false, false, false] },
  { feature: 'Thread-safe',          values: [true,  true,  true,  true] },
  { feature: 'Active maintenance',   values: [true,  true,  true,  false] },
];

const PERF_BARS = [
  { name: 'GoSQLX',            ops: 1_380_000, label: '1.38M ops/sec', accent: true },
  { name: 'vitess-sqlparser',  ops: 560_000,   label: '560K ops/sec',  accent: false },
  { name: 'pg_query_go',       ops: 340_000,   label: '340K ops/sec',  accent: false },
  { name: 'sqlparser (xwb1989)', ops: 220_000, label: '220K ops/sec',  accent: false },
];

const MAX_OPS = PERF_BARS[0].ops;

/* ------------------------------------------------------------------ */
/*  Icons                                                              */
/* ------------------------------------------------------------------ */

function CheckIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="Yes"
      role="img"
    >
      <circle cx="10" cy="10" r="10" fill="rgba(34,197,94,0.15)" />
      <path
        d="M6 10.5L8.5 13L14 7.5"
        stroke="#22c55e"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function XIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="No"
      role="img"
    >
      <circle cx="10" cy="10" r="10" fill="rgba(113,113,122,0.15)" />
      <path
        d="M7 7L13 13M13 7L7 13"
        stroke="#71717a"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function CellValue({ value }: { value: string | boolean }) {
  if (typeof value === 'boolean') {
    return value ? <CheckIcon /> : <XIcon />;
  }
  return <span>{value}</span>;
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function CompareContent() {
  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="section-padding pt-24 pb-16 text-center">
        <div className="container-width">
          <FadeIn>
            <h1 className="text-4xl font-bold tracking-tight text-white">
              GoSQLX vs The Competition
            </h1>
            <p className="mt-4 text-lg text-zinc-400 max-w-2xl mx-auto">
              See how GoSQLX compares to other Go SQL parsing libraries
            </p>
          </FadeIn>
        </div>
      </section>

      {/* Feature Comparison Table */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <FadeIn delay={0.1}>
            <GlassCard className="p-0 overflow-x-auto" hover={false}>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/[0.06]">
                    <th className="text-left px-5 py-4 text-zinc-400 font-medium">Feature</th>
                    {LIBRARIES.map((lib) => (
                      <th
                        key={lib}
                        className={`px-5 py-4 text-center font-medium ${
                          lib === 'GoSQLX' ? 'text-white' : 'text-zinc-400'
                        }`}
                      >
                        {lib}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {FEATURES.map((row, i) => (
                    <tr
                      key={row.feature}
                      className={
                        i < FEATURES.length - 1 ? 'border-b border-white/[0.04]' : ''
                      }
                    >
                      <td className="px-5 py-3.5 text-zinc-300 font-medium whitespace-nowrap">
                        {row.feature}
                      </td>
                      {row.values.map((val, j) => (
                        <td
                          key={`${row.feature}-${j}`}
                          className={`px-5 py-3.5 text-center ${
                            j === 0 ? 'text-white' : 'text-zinc-400'
                          }`}
                        >
                          <span className="inline-flex justify-center">
                            <CellValue value={val} />
                          </span>
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </GlassCard>
          </FadeIn>
        </div>
      </section>

      {/* Performance Comparison */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <FadeIn delay={0.2}>
            <h2 className="text-2xl font-bold text-white mb-2">Performance Comparison</h2>
            <p className="text-sm text-zinc-400 mb-8">
              Operations per second parsing a standard SELECT query (higher is better)
            </p>
            <GlassCard className="p-6 sm:p-8" hover={false}>
              <div className="space-y-6">
                {PERF_BARS.map((bar) => {
                  const pct = Math.round((bar.ops / MAX_OPS) * 100);
                  return (
                    <div key={bar.name}>
                      <div className="flex items-baseline justify-between mb-2">
                        <span
                          className={`text-sm font-medium ${
                            bar.accent ? 'text-white' : 'text-zinc-400'
                          }`}
                        >
                          {bar.name}
                        </span>
                        <span
                          className={`text-sm font-mono ${
                            bar.accent ? 'text-green-400' : 'text-zinc-500'
                          }`}
                        >
                          {bar.label}
                        </span>
                      </div>
                      <div className="h-3 w-full rounded-full bg-white/[0.04]">
                        <div
                          className={`h-3 rounded-full transition-all duration-700 ${
                            bar.accent
                              ? 'bg-gradient-to-r from-green-500 to-emerald-400'
                              : 'bg-zinc-600'
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="mt-6 text-xs text-zinc-500">
                Benchmarked on Apple Silicon with Go 1.26+, object pooling enabled, race detector off.
                Results averaged over 5 runs.
              </p>
            </GlassCard>
          </FadeIn>
        </div>
      </section>

      {/* CTA */}
      <section className="section-padding pb-24">
        <div className="container-width text-center">
          <FadeIn delay={0.3}>
            <GlassCard className="p-10" hover={false}>
              <h2 className="text-2xl font-bold text-white">
                Ready to switch to the fastest Go SQL parser?
              </h2>
              <p className="mt-3 text-zinc-400 max-w-xl mx-auto">
                Get started in under a minute with a single{' '}
                <code className="font-mono text-xs bg-white/[0.06] px-1.5 py-0.5 rounded">
                  go get
                </code>{' '}
                command.
              </p>
              <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
                <Link href="/docs/getting-started">
                  <Button>Try GoSQLX</Button>
                </Link>
                <Link href="/benchmarks">
                  <Button variant="ghost">View Benchmarks</Button>
                </Link>
              </div>
            </GlassCard>
          </FadeIn>
        </div>
      </section>
    </div>
  );
}
