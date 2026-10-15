import Link from 'next/link';
import { FadeIn } from '@/components/ui/FadeIn';
import { formatStars } from '@/lib/github';
import { BENCH_ENV, PARSE_BENCHMARKS, PROJECT, formatCount } from '@/data/metrics';

/* ── Inline SVG glyphs (20x20, neutral: they inherit the text colour) ──── */

const glyph = {
  star: <path strokeLinecap="round" strokeLinejoin="round" d="M10 1.5l2.47 5.01 5.53.8-4 3.9.94 5.49L10 14.26 5.06 16.7 6 11.21l-4-3.9 5.53-.8L10 1.5z" />,
  check: <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 5.5L8 14l-4.5-4.5" />,
  bolt: <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 1.5L4 11.5h5.5L8.75 18.5 16 8.5h-5.5L11.25 1.5z" />,
  shield: <path strokeLinecap="round" strokeLinejoin="round" d="M10 1.75L3.5 4.5v5c0 4 2.8 7.3 6.5 8.75 3.7-1.45 6.5-4.75 6.5-8.75v-5L10 1.75zM7.25 10l2 2 3.5-3.75" />,
  globe: (
    <>
      <circle cx="10" cy="10" r="8" />
      <path strokeLinecap="round" d="M2 10h16M10 2c2.2 2.3 3.25 5 3.25 8S12.2 15.7 10 18M10 2C7.8 4.3 6.75 7 6.75 10S7.8 15.7 10 18" />
    </>
  ),
  plug: <path strokeLinecap="round" strokeLinejoin="round" d="M7 2v4m6-4v4M5 6h10v3a5 5 0 01-10 0V6zm5 8v4" />,
  editor: (
    <>
      <rect x="2.5" y="3.5" width="15" height="13" rx="1.5" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 8l2.5 2L6 12m4.5 0H14" />
    </>
  ),
} as const;

function Glyph({ name, className = 'text-fg-muted' }: { name: keyof typeof glyph; className?: string }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" className={className}>
      {glyph[name]}
    </svg>
  );
}

/* ── Metric cards (every figure comes from @/data/metrics or the live API) ─ */

interface Metric {
  id: string;
  icon: keyof typeof glyph;
  value: string;
  label: string;
}

const simpleSelect = PARSE_BENCHMARKS[0];

const latencyCard: Metric = {
  id: 'latency',
  icon: 'bolt',
  value: `~${(simpleSelect.nsPerOp / 1000).toFixed(2)} µs`,
  label: `to parse a simple SELECT (${BENCH_ENV.stage}, ${BENCH_ENV.hardware}, ${BENCH_ENV.goVersion})`,
};

const testsCard: Metric = {
  id: 'tests',
  icon: 'check',
  value: formatCount(PROJECT.testFunctions),
  label: 'Go test functions, race-detector clean in CI',
};

const dialectsCard: Metric = {
  id: 'dialects',
  icon: 'globe',
  value: String(PROJECT.dialectCount),
  label: 'SQL dialects, one parser',
};

/** Shown in place of the stars card when the live count is unavailable, so the grid stays 4-up. */
const raceCard: Metric = {
  id: 'race',
  icon: 'shield',
  value: 'Zero',
  label: 'race-detector failures in CI',
};

function buildMetrics(stars: number | null): Metric[] {
  const first: Metric =
    stars !== null
      ? { id: 'stars', icon: 'star', value: formatStars(stars), label: 'GitHub stars' }
      : raceCard;
  return [first, testsCard, latencyCard, dialectsCard];
}

/* ── Integrations (plain names plus neutral glyphs: no third-party logos) ─ */

interface Integration {
  name: string;
  detail: string;
  href: string;
  icon: keyof typeof glyph;
}

const integrations: Integration[] = [
  { name: 'Claude', detail: 'MCP server', href: '/docs/mcp-guide/', icon: 'plug' },
  { name: 'Cursor', detail: 'MCP server', href: '/docs/mcp-guide/', icon: 'plug' },
  { name: 'VS Code', detail: 'Extension', href: '/vscode/', icon: 'editor' },
  { name: 'Neovim', detail: 'Language server', href: '/docs/editors/neovim/', icon: 'editor' },
  { name: 'JetBrains', detail: 'Language server', href: '/docs/editors/jetbrains/', icon: 'editor' },
];

/* ── Component ─────────────────────────────────────────────────────────── */

export function ProofStrip({ stars }: { stars: number | null }) {
  const metrics = buildMetrics(stars);

  return (
    <section aria-labelledby="proof-heading" className="py-16 border-t border-fg/[0.06]">
      <div className="max-w-5xl mx-auto px-4">
        <FadeIn viewport>
          <h2
            id="proof-heading"
            className="text-center text-sm font-semibold uppercase tracking-widest text-fg-muted mb-10"
          >
            Built for production
          </h2>
        </FadeIn>

        {/* Exactly four cards: 2x2 on small screens, 4x1 from lg, so no orphan at any breakpoint. */}
        <ul className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {metrics.map((m, i) => (
            <li key={m.id}>
              <FadeIn viewport delay={i * 0.07} className="h-full">
                <div className="glass h-full text-center px-4 py-5 flex flex-col items-center gap-2">
                  <Glyph name={m.icon} />
                  <span className="text-xl font-bold text-fg tabular-nums">{m.value}</span>
                  <span className="text-xs text-fg-muted">{m.label}</span>
                </div>
              </FadeIn>
            </li>
          ))}
        </ul>

        {/* Integration strip */}
        <FadeIn viewport delay={0.2}>
          <p className="text-center text-sm font-medium text-fg-muted mt-12 mb-5">
            Works with
          </p>
          <ul className="flex flex-wrap justify-center gap-2 sm:gap-3">
            {integrations.map((item) => (
              <li key={item.name}>
                <Link
                  href={item.href}
                  className="glass glass-hover inline-flex min-h-11 items-center gap-2 px-4 py-2 rounded-full text-sm transition-colors"
                >
                  <Glyph name={item.icon} />
                  <span className="font-semibold text-fg">{item.name}</span>
                  <span className="text-xs text-fg-muted">{item.detail}</span>
                </Link>
              </li>
            ))}
          </ul>
        </FadeIn>
      </div>
    </section>
  );
}
