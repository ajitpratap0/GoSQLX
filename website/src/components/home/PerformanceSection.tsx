import { GlassCard } from '@/components/ui/GlassCard';
import { FadeIn } from '@/components/ui/FadeIn';
import { BENCH_ENV, HEADLINE_OPS_PER_SEC, PARSE_BENCHMARKS, formatOps, opsPerSec } from '@/data/metrics';
import { AnimatedBars } from './AnimatedBars';
import { ReproduceSnippet } from './ReproduceSnippet';

interface Stat {
  /** Compact display string, short enough to fit a narrow card. */
  display: string;
  label: string;
}

const [simpleSelect] = PARSE_BENCHMARKS;
const complexQuery = PARSE_BENCHMARKS.find((b) => b.name === 'Complex Query') ?? PARSE_BENCHMARKS[PARSE_BENCHMARKS.length - 1];

/* Every figure is parse stage only (pre-tokenized input -> AST); hardware and Go version are in the caption. */
const stats: Stat[] = [
  { display: `~${formatOps(HEADLINE_OPS_PER_SEC)}`, label: 'parses/sec, simple SELECT (parse stage)' },
  { display: `${simpleSelect.nsPerOp.toLocaleString('en-US')}ns`, label: 'latency, simple SELECT (parse stage)' },
  { display: `~${formatOps(opsPerSec(complexQuery.nsPerOp))}`, label: 'parses/sec, complex query (parse stage)' },
  { display: `${complexQuery.nsPerOp.toLocaleString('en-US')}ns`, label: 'latency, complex query (parse stage)' },
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
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6">
          {stats.map((stat, i) => (
            <FadeIn viewport key={stat.label} delay={i * 0.1} className="h-full">
              <GlassCard className="p-4 sm:p-6 text-center w-full h-full">
                <div className="text-2xl sm:text-3xl xl:text-4xl font-bold tabular-nums text-fg whitespace-nowrap">
                  {stat.display}
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
