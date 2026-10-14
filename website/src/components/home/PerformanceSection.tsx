import { GlassCard } from '@/components/ui/GlassCard';
import { FadeIn } from '@/components/ui/FadeIn';
import { AnimatedCounter } from '@/components/ui/AnimatedCounter';
import { BENCH_ENV, HEADLINE_OPS_PER_SEC, PARSE_BENCHMARKS, formatOps, opsPerSec } from '@/data/metrics';
import { AnimatedBars } from './AnimatedBars';
import { ReproduceSnippet } from './ReproduceSnippet';

interface Stat {
  /** Animated numeric value. */
  value: number;
  suffix?: string;
  prefix?: string;
  label: string;
}

const [simpleSelect] = PARSE_BENCHMARKS;
const complexQuery = PARSE_BENCHMARKS.find((b) => b.name === 'Complex Query') ?? PARSE_BENCHMARKS[PARSE_BENCHMARKS.length - 1];

/* Every figure is parse stage only (pre-tokenized input -> AST); hardware and Go version are in the caption. */
const stats: Stat[] = [
  { value: HEADLINE_OPS_PER_SEC, prefix: '~', label: 'parses/sec, simple SELECT (parse stage)' },
  { value: simpleSelect.nsPerOp, suffix: 'ns', label: 'latency, simple SELECT (parse stage)' },
  { value: opsPerSec(complexQuery.nsPerOp), prefix: '~', label: 'parses/sec, complex query (parse stage)' },
  { value: complexQuery.nsPerOp, suffix: 'ns', label: 'latency, complex query (parse stage)' },
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
            <FadeIn viewport key={stat.label} delay={i * 0.1} className="h-full">
              <GlassCard className="p-6 text-center w-full h-full">
                <div className="flex items-baseline justify-center gap-0.5">
                  {stat.prefix && (
                    <span className="text-3xl sm:text-4xl font-bold text-fg">{stat.prefix}</span>
                  )}
                  <AnimatedCounter value={stat.value} suffix={stat.suffix} color="text-fg" />
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
              Source: {BENCH_ENV.source}.
            </p>
            <div className="mt-6">
              <h3 className="text-sm font-semibold text-zinc-200 mb-2">Reproduce</h3>
              <ReproduceSnippet command={BENCH_ENV.command} />
            </div>
          </GlassCard>
        </FadeIn>
      </div>
    </section>
  );
}
