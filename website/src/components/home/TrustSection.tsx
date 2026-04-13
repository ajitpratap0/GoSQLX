import { FadeInCSS } from '@/components/ui/FadeInCSS';
import { GitHubStarCount } from './GitHubStarCount';

/* ── Inline SVG icons (Heroicons-style, 20x20) ────────────────────────── */

function StarIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" className="text-yellow-400">
      <path strokeLinecap="round" strokeLinejoin="round" d="M10 1.5l2.47 5.01 5.53.8-4 3.9.94 5.49L10 14.26 5.06 16.7 6 11.21l-4-3.9 5.53-.8L10 1.5z" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" className="text-emerald-400">
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 5.5L8 14l-4.5-4.5" />
    </svg>
  );
}

function BoltIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" className="text-amber-400">
      <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 1.5L4 11.5h5.5L8.75 18.5 16 8.5h-5.5L11.25 1.5z" />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" className="text-indigo-400">
      <rect x="4.5" y="8.5" width="11" height="8" rx="1.5" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M7 8.5V6a3 3 0 016 0v2.5" />
    </svg>
  );
}

function PackageIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" className="text-cyan-400">
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.5 5.5L10 1.5l7.5 4M2.5 5.5v9l7.5 4m-7.5-13L10 9.5m0 9V9.5m0 0l7.5-4m0 0v9l-7.5 4" />
    </svg>
  );
}

/* ── Metric data ───────────────────────────────────────────────────────── */

const metrics = [
  {
    id: 'stars',
    icon: <StarIcon />,
    value: null, // rendered via client component
    label: 'GitHub Stars',
  },
  {
    id: 'tests',
    icon: <CheckIcon />,
    value: '800+',
    label: 'Tests Passing',
  },
  {
    id: 'perf',
    icon: <BoltIcon />,
    value: '1.38M',
    label: 'ops/sec',
  },
  {
    id: 'race',
    icon: <LockIcon />,
    value: 'Zero',
    label: 'Race Conditions',
  },
  {
    id: 'go',
    icon: <PackageIcon />,
    value: 'Go 1.26+',
    label: 'Minimum Version',
  },
] as const;

/* ── Integration data ──────────────────────────────────────────────────── */

const integrations = [
  { name: 'Claude', detail: 'MCP Server' },
  { name: 'VS Code', detail: 'Extension' },
  { name: 'Cursor', detail: 'MCP Server' },
] as const;

/* ── Component ─────────────────────────────────────────────────────────── */

export function TrustSection() {
  return (
    <section className="py-16 border-t border-white/[0.06]">
      <div className="max-w-5xl mx-auto px-4">
        {/* Heading */}
        <FadeInCSS>
          <h2 className="text-center text-sm font-semibold uppercase tracking-widest text-zinc-300 mb-10">
            Trusted by Developers
          </h2>
        </FadeInCSS>

        {/* Metric cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {metrics.map((m, i) => (
            <FadeInCSS key={m.id} delay={i * 0.07}>
              <div className="glass text-center px-4 py-5 flex flex-col items-center gap-2">
                {m.icon}
                <span className="text-lg font-bold text-zinc-100">
                  {m.id === 'stars' ? <GitHubStarCount /> : m.value}
                </span>
                <span className="text-xs text-zinc-300">{m.label}</span>
              </div>
            </FadeInCSS>
          ))}
        </div>

        {/* Integrations */}
        <FadeInCSS delay={0.4}>
          <p className="text-center text-sm font-medium text-zinc-300 mt-12 mb-5">
            Integrates with
          </p>
        </FadeInCSS>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 max-w-xl mx-auto">
          {integrations.map((item, i) => (
            <FadeInCSS key={item.name} delay={0.5 + i * 0.07}>
              <div className="glass text-center px-5 py-4">
                <span className="block text-base font-semibold text-zinc-100">
                  {item.name}
                </span>
                <span className="block text-xs text-zinc-300 mt-1">
                  {item.detail}
                </span>
              </div>
            </FadeInCSS>
          ))}
        </div>
      </div>
    </section>
  );
}
