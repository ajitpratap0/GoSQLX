import { GlassCard } from '@/components/ui/GlassCard';
import { FadeInCSS } from '@/components/ui/FadeInCSS';
import { AnimatedCounter } from '@/components/ui/AnimatedCounter';
import { AnimatedBars } from './AnimatedBars';

const stats = [
  { value: 1380000, suffix: '+', label: 'ops/sec', color: 'text-accent-orange' },
  { value: 1, suffix: '\u00B5s', label: 'latency', color: 'text-accent-indigo', prefix: '<' },
  { value: 85, suffix: '%', label: 'SQL-99', color: 'text-accent-green' },
  { value: 8, suffix: '', label: 'Dialects', color: 'text-accent-purple' },
];

const benchmarks = [
  { name: 'GoSQLX', ops: 1380000, label: '1.38M ops/sec', highlight: true },
  { name: 'vitess', ops: 560000, label: '560K ops/sec', highlight: false },
  { name: 'pg_query', ops: 340000, label: '340K ops/sec', highlight: false },
  { name: 'sqlparser', ops: 220000, label: '220K ops/sec', highlight: false },
];

const maxOps = Math.max(...benchmarks.map((b) => b.ops));

export function PerformanceSection() {
  return (
    <section className="py-20">
      <div className="max-w-6xl mx-auto px-4">
        <FadeInCSS>
          <h2 className="text-2xl sm:text-3xl font-bold text-center text-white mb-12">
            Performance That Speaks for Itself
          </h2>
        </FadeInCSS>

        {/* Stat cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 md:gap-8">
          {stats.map((stat, i) => (
            <FadeInCSS key={stat.label} delay={i * 0.1}>
              <GlassCard className="p-6 text-center w-full">
                <div className="flex items-baseline justify-center gap-0.5">
                  {stat.prefix && (
                    <span className={`text-3xl sm:text-4xl font-bold ${stat.color}`}>{stat.prefix}</span>
                  )}
                  <AnimatedCounter value={stat.value} suffix={stat.suffix} color={stat.color} />
                </div>
                <p className="text-sm text-zinc-200 mt-1">{stat.label}</p>
              </GlassCard>
            </FadeInCSS>
          ))}
        </div>

        {/* Bar chart */}
        <FadeInCSS delay={0.5}>
          <GlassCard className="mt-12 p-6 sm:p-8" hover={false}>
            <AnimatedBars benchmarks={benchmarks} maxOps={maxOps} />
            <p className="text-xs text-zinc-400 mt-6 text-center">
              Based on BenchmarkParse, Apple M4, Go 1.26
            </p>
          </GlassCard>
        </FadeInCSS>
      </div>
    </section>
  );
}
