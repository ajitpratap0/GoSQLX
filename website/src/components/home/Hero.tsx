import Link from 'next/link';
import {
  PROJECT,
  HEADLINE_OPS_PER_SEC,
  HEADLINE_CAPTION,
  formatOps,
  formatCount,
} from '@/data/metrics';
import { GlassCard } from '@/components/ui/GlassCard';
import { GradientText } from '@/components/ui/GradientText';
import { VersionBadge } from '@/components/ui/VersionBadge';
import { Button } from '@/components/ui/Button';
import { GitHubStarButton } from '@/components/home/GitHubStarButton';
import { MiniPlayground } from '@/components/home/MiniPlayground';

export function Hero({ stars }: { stars: number | null }) {
  return (
    // Fill the viewport below the fixed 4rem navbar, but top-align content so
    // the live demo starts above the fold instead of being centred below it.
    <section className="relative min-h-[calc(100svh-4rem)] overflow-clip">
      {/* Background gradient mesh */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden" aria-hidden="true">
        {/* Glows: single gradient background, no blur filter */}
        <div
          className="absolute inset-0"
          style={{
            background:
              'radial-gradient(circle at 90% 0%, color-mix(in srgb, var(--accent) calc(15% * var(--hero-glow-strength)), transparent) 0%, transparent 45%), radial-gradient(circle at 5% 100%, color-mix(in srgb, var(--accent-warm-decor) calc(8% * var(--hero-glow-strength)), transparent) 0%, transparent 40%)',
          }}
        />
        {/* Dot grid overlay */}
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: 'radial-gradient(color-mix(in srgb, var(--fg) var(--hero-dot-strength), transparent) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 pt-10 sm:pt-14 pb-16 text-center">
        {/* Version badge */}
        <div className="mb-5">
          <VersionBadge version={`${PROJECT.version} - Multi-Dialect SQL Parser`} />
        </div>

        {/* Headline: solid text, brand gradient only on the key phrase */}
        <h1
          className="text-display font-bold mb-5 text-fg text-balance break-words w-full max-w-full px-4 sm:px-0"
          style={{ letterSpacing: '-0.03em' }}
        >
          Parse SQL at the <GradientText>speed of Go</GradientText>
        </h1>

        {/* Subtitle */}
        <p className="text-base sm:text-lg md:text-xl max-w-2xl mx-auto mb-7 text-fg-muted text-pretty">
          Production-ready SQL parsing with zero-copy tokenization, object pooling, and multi-dialect support
        </p>

        {/* Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-3 mb-5">
          <Button variant="primary" href="/docs/getting-started">
            Get Started
          </Button>
          <Button variant="ghost" href="/playground">
            Try Playground
          </Button>
          <GitHubStarButton stars={stars} />
        </div>

        {/* Proof line: every figure comes from src/data/metrics.ts */}
        <ul
          aria-label="Project facts"
          className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-xs sm:text-sm text-fg-subtle mb-8 sm:mb-10"
        >
          <li>
            <Link href="/benchmarks" className="hover:text-fg underline-offset-4 hover:underline">
              <span className="font-mono text-fg-muted">{formatOps(HEADLINE_OPS_PER_SEC)} ops/sec</span>{' '}
              ({HEADLINE_CAPTION})
            </Link>
          </li>
          {[
            `${PROJECT.dialectCount} dialects`,
            `${PROJECT.lintRuleCount} lint rules`,
            `${formatCount(PROJECT.testFunctions)} tests`,
          ].map((fact) => (
            <li key={fact} className="flex items-center gap-x-3">
              <span aria-hidden="true" className="hidden sm:inline">&middot;</span>
              {fact}
            </li>
          ))}
        </ul>

        {/* Live mini playground */}
        <GlassCard hover={false} className="p-0 overflow-hidden shadow-2xl shadow-accent/5">
          <MiniPlayground />
        </GlassCard>
      </div>
    </section>
  );
}
