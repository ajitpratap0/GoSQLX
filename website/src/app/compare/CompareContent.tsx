import Link from 'next/link';
import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';
import { PROJECT } from '@/data/metrics';

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
  { feature: 'Zero-copy',            values: [true,  false, false, false] },
  { feature: 'Dialects',             values: [String(PROJECT.dialectCount),   '1 (PostgreSQL)', '1 (MySQL)', '1 (MySQL)'] },
  { feature: 'Pure Go (no CGo)',     values: [true,  false, true,  true] },
  { feature: 'WASM support',         values: [true,  false, false, false] },
  { feature: 'SQL injection detection', values: [true,  false, false, false] },
  { feature: 'MCP server',           values: [true,  false, false, false] },
  { feature: 'SQL formatting',       values: [true,  false, false, false] },
  { feature: `SQL linting (${PROJECT.lintRuleCount} rules)`, values: [true,  false, false, false] },
  { feature: 'LSP server',           values: [true,  false, false, false] },
  { feature: 'Thread-safe',          values: [true,  true,  true,  true] },
  { feature: 'Active maintenance',   values: [true,  true,  true,  false] },
];

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
    return (
      <span className="inline-flex items-center gap-1.5">
        {value ? <CheckIcon /> : <XIcon />}
        <span className="text-xs text-zinc-400">{value ? 'Yes' : 'No'}</span>
      </span>
    );
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

      {/* Performance comparison withheld until the reproducible harness (#673) lands */}
      <section className="section-padding pb-16">
        <div className="container-width">
          <p className="text-sm text-zinc-400">
            Performance comparisons are withheld until a reproducible benchmark harness is published.
            For GoSQLX measurements, see the{' '}
            <Link href="/benchmarks/" className="text-accent underline underline-offset-2">
              benchmarks page
            </Link>
            .
          </p>
        </div>
      </section>

      {/* CTA */}
      <section className="section-padding pb-24">
        <div className="container-width text-center">
          <FadeIn delay={0.3}>
            <GlassCard className="p-10" hover={false}>
              <h2 className="text-2xl font-bold text-white">
                Ready to try GoSQLX?
              </h2>
              <p className="mt-3 text-zinc-400 max-w-xl mx-auto">
                Get started in under a minute with a single{' '}
                <code className="font-mono text-xs text-fg bg-fg/[0.06] px-1.5 py-0.5 rounded">
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
