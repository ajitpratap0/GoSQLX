'use client';

import { useEffect, useRef, useState } from 'react';

export interface BarChartItem {
  label: string;
  value: number;
  color?: string;
  highlight?: boolean;
}

interface BarChartProps {
  data: BarChartItem[];
  unit?: string;
}

function formatValue(value: number): string {
  if (value >= 1_000_000) {
    const m = value / 1_000_000;
    return m % 1 === 0 ? `${m}M` : `${m.toFixed(2)}M`;
  }
  if (value >= 1_000) {
    const k = value / 1_000;
    return k % 1 === 0 ? `${k}K` : `${k.toFixed(0)}K`;
  }
  return String(value);
}

export function BarChart({ data, unit = 'ops/sec' }: BarChartProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 },
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const maxValue = Math.max(...data.map((d) => d.value));

  return (
    <div ref={containerRef} className="space-y-3">
      {data.map((item) => {
        const pct = maxValue > 0 ? (item.value / maxValue) * 100 : 0;

        return (
          <div key={item.label} className="group">
            {/* Label row */}
            <div className="flex items-center justify-between mb-1">
              <span className={`text-sm font-medium ${item.highlight ? 'text-white' : 'text-zinc-400'}`}>
                {item.label}
                {item.highlight && (
                  <span className="ml-2 inline-block rounded-full bg-green-500/20 px-2 py-0.5 text-xs font-medium text-green-300">
                    GoSQLX
                  </span>
                )}
              </span>
              <span className={`text-sm font-mono ${item.highlight ? 'text-white' : 'text-zinc-400'}`}>
                {formatValue(item.value)} {unit}
              </span>
            </div>

            {/* Bar */}
            <div className="h-7 w-full rounded bg-white/[0.04] overflow-hidden">
              <div
                className={`h-full rounded transition-all duration-1000 ease-out ${
                  item.highlight
                    ? 'bg-gradient-to-r from-green-500 to-green-400'
                    : item.color ?? 'bg-zinc-700'
                }`}
                style={{ width: visible ? `${pct}%` : '0%' }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
