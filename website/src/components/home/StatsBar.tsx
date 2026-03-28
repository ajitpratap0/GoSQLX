'use client';

import { GlassCard } from '@/components/ui/GlassCard';
import { FadeIn } from '@/components/ui/FadeIn';
import { AnimatedCounter } from '@/components/ui/AnimatedCounter';

const stats = [
  { value: 1380000, suffix: '+', label: 'ops/sec', color: 'text-accent-orange' },
  { value: 1, suffix: 'μs', label: 'latency', color: 'text-accent-indigo', prefix: '<' },
  { value: 85, suffix: '%', label: 'SQL-99', color: 'text-accent-green' },
  { value: 7, suffix: '', label: 'Dialects', color: 'text-accent-purple' },
];

export function StatsBar() {
  return (
    <section className="py-20">
      <div className="max-w-6xl mx-auto px-4">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 md:gap-8">
          {stats.map((stat, i) => (
            <FadeIn key={stat.label} delay={i * 0.1}>
              <GlassCard className="p-6 text-center w-full">
                <div className="flex items-baseline justify-center gap-0.5">
                  {stat.prefix && (
                    <span className={`text-3xl sm:text-4xl font-bold ${stat.color}`}>{stat.prefix}</span>
                  )}
                  <AnimatedCounter value={stat.value} suffix={stat.suffix} color={stat.color} />
                </div>
                <p className="text-sm text-zinc-300 mt-1">{stat.label}</p>
              </GlassCard>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}
