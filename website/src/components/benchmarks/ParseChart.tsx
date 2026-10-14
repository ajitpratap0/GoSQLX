'use client';

import { BarChart, type BarChartItem } from './BarChart';
import { BENCH_ENV, PARSE_BENCHMARKS, opsPerSec } from '@/lib/benchmark-data';

const parseData: BarChartItem[] = PARSE_BENCHMARKS.map((b) => ({
  label: b.name,
  value: opsPerSec(b.nsPerOp),
  highlight: true,
}));

export function ParseChart() {
  return (
    <div>
      <h3 className="text-lg font-semibold text-white mb-4">
        Parse-stage throughput ({BENCH_ENV.hardware}, {BENCH_ENV.goVersion})
      </h3>
      <BarChart data={parseData} />
    </div>
  );
}
