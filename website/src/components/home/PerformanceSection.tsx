import { GlassCard } from '@/components/ui/GlassCard';
import { FadeIn } from '@/components/ui/FadeIn';
import { AnimatedCounter } from '@/components/ui/AnimatedCounter';
import { BENCH_ENV, HEADLINE_OPS_PER_SEC, PARSE_BENCHMARKS, PROJECT, formatOps, opsPerSec } from '@/data/metrics';
import { AnimatedBars } from './AnimatedBars';

interface Stat {
  /** Animated numeric value; omit when `text` is shown instead. */
  value?: number;
  /** Static text for figures that are ranges or estimates. */
  text?: string;
  suffix?: string;
  label: string;
  color: string;
  prefix?: string;
}

const stats: Stat[] = [
  { value: HEADLINE_OPS_PER_SEC, suffix: '', label: `parses/sec (simple SELECT, parse stage, ${BENCH_ENV.hardware})`, color: 'text-accent-orange', prefix: '~' },
  { value: PARSE_BENCHMARKS[0].nsPerOp, suffix: 'ns', label: 'parse latency (simple SELECT, parse stage)', color: 'text-accent-indigo' },
  { text: PROJECT.sql99, label: 'SQL-99 compliance (estimated)', color: 'text-accent-green' },
  { value: PROJECT.dialectCount, suffix: '', label: 'Dialects', color: 'text-accent-purple' },
];

const benchmarks = PARSE_BENCHMARKS.map((b) => ({
  name: b.name,
  ops: opsPerSec(b.nsPerOp),
  label: `${formatOps(opsPerSec(b.nsPerOp))} ops/sec`,
  highlight: true,
}));

const maxOps = Math.max(...benchmarks.map((b) => b.ops));

export function PerformanceSection() {
  return (
    <section className="py-20">
      <div className="max-w-6xl mx-auto px-4">
        <FadeIn viewport>
          <h2 className="text-2xl sm:text-3xl font-bold text-center text-white mb-12">
            Performance That Speaks for Itself
          </h2>
        </FadeIn>

        {/* Stat cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 md:gap-8">
          {stats.map((stat, i) => (
            <FadeIn viewport key={stat.label} delay={i * 0.1}>
              <GlassCard className="p-6 text-center w-full">
                <div className="flex items-baseline justify-center gap-0.5">
                  {stat.prefix && (
                    <span className={`text-3xl sm:text-4xl font-bold ${stat.color}`}>{stat.prefix}</span>
                  )}
                  {stat.value !== undefined ? (
                    <AnimatedCounter value={stat.value} suffix={stat.suffix} color={stat.color} />
                  ) : (
                    <span className={`text-3xl sm:text-4xl font-bold tabular-nums ${stat.color}`}>{stat.text}</span>
                  )}
                </div>
                <p className="text-sm text-zinc-200 mt-1">{stat.label}</p>
              </GlassCard>
            </FadeIn>
          ))}
        </div>

        {/* Bar chart */}
        <FadeIn viewport delay={0.5}>
          <GlassCard className="mt-12 p-6 sm:p-8" hover={false}>
            <AnimatedBars benchmarks={benchmarks} maxOps={maxOps} />
            <p className="text-xs text-zinc-400 mt-6 text-center">
              Parse stage only (not tokenize or end-to-end), {BENCH_ENV.hardware}, {BENCH_ENV.goVersion}.
              Source: BenchmarkPerformanceBaseline, median of 10 runs.
            </p>
          </GlassCard>
        </FadeIn>
      </div>
    </section>
  );
}
