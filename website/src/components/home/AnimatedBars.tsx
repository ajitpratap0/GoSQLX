'use client';

import { useRef, useEffect, useState } from 'react';

interface Benchmark {
  name: string;
  ops: number;
  label: string;
  highlight: boolean;
}

export function AnimatedBars({ benchmarks, maxOps }: { benchmarks: Benchmark[]; maxOps: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setVisible(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.unobserve(el);
        }
      },
      { threshold: 0.2 },
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={ref} className="space-y-4" role="img" aria-label="Performance comparison bar chart">
      {benchmarks.map((b, i) => {
        const widthPercent = (b.ops / maxOps) * 100;
        return (
          <div key={b.name} className="flex items-center gap-4">
            <span className="w-20 sm:w-24 text-sm text-zinc-300 text-right shrink-0 font-mono">
              {b.name}
            </span>
            <div className="flex-1 h-8 rounded-md bg-zinc-800/50 overflow-hidden relative">
              <div
                className={`h-full rounded-md ${
                  b.highlight
                    ? 'bg-gradient-to-r from-green-500 to-emerald-400'
                    : 'bg-zinc-700'
                }`}
                style={{
                  width: visible ? `${widthPercent}%` : '0%',
                  transition: `width 1s cubic-bezier(0.22,1,0.36,1) ${i * 0.15}s`,
                }}
              />
            </div>
            <span className="w-28 sm:w-32 text-sm text-zinc-300 shrink-0 font-mono">
              {b.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}
