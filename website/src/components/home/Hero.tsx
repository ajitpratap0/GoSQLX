import { PROJECT } from '@/data/metrics';
import { GlassCard } from '@/components/ui/GlassCard';
import { GradientText } from '@/components/ui/GradientText';
import { VersionBadge } from '@/components/ui/VersionBadge';
import { Button } from '@/components/ui/Button';
import { GitHubStarButton } from '@/components/home/GitHubStarButton';
import { MiniPlayground } from '@/components/home/MiniPlayground';

export function Hero({ stars }: { stars: number | null }) {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-clip">
      {/* Background gradient mesh */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden" aria-hidden="true">
        {/* Top-right indigo glow */}
        <div
          className="absolute top-[-20%] right-[-10%] w-[60%] h-[60%]"
          style={{
            background: 'radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 60%)',
            filter: 'blur(80px)',
          }}
        />
        {/* Bottom-left orange glow */}
        <div
          className="absolute bottom-[-10%] left-[-10%] w-[50%] h-[50%]"
          style={{
            background: 'radial-gradient(circle, rgba(249,115,22,0.08) 0%, transparent 60%)',
            filter: 'blur(60px)',
          }}
        />
        {/* Dot grid overlay */}
        <div
          className="absolute inset-0 opacity-5"
          style={{
            backgroundImage: 'radial-gradient(rgba(255,255,255,0.5) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-5xl mx-auto px-6 py-24 text-center">
        {/* Version badge */}
        <div className="mb-6">
          <VersionBadge version={`${PROJECT.version} - Multi-Dialect SQL Parser`} />
        </div>

        {/* Headline */}
        <h1
          className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold mb-6 break-words hyphens-auto w-full max-w-full px-4 sm:px-0"
          style={{ letterSpacing: '-0.03em' }}
        >
          <GradientText>Parse SQL at the speed of Go</GradientText>
        </h1>

        {/* Subtitle */}
        <p className="text-base sm:text-lg md:text-xl max-w-2xl mx-auto mb-10 text-zinc-300">
          Production-ready SQL parsing with zero-copy tokenization, object pooling, and multi-dialect support
        </p>

        {/* Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-3 mb-14">
          <Button variant="primary" href="/docs/getting-started">
            Get Started
          </Button>
          <Button variant="ghost" href="/playground">
            Try Playground
          </Button>
          <GitHubStarButton stars={stars} />
        </div>

        {/* Live mini playground */}
        <GlassCard hover={false} className="p-0 overflow-hidden shadow-2xl shadow-indigo-500/5">
          <MiniPlayground />
        </GlassCard>

      </div>
    </section>
  );
}
