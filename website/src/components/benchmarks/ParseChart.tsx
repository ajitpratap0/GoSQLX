'use client';

import { BarChart, type BarChartItem } from './BarChart';

const parseData: BarChartItem[] = [
  { label: 'Simple SELECT', value: 1_400_000, highlight: true },
  { label: 'Multi-row INSERT', value: 992_000, highlight: true },
  { label: 'Window Function', value: 848_000, highlight: true },
  { label: 'CTE (WITH RECURSIVE)', value: 833_000, highlight: true },
  { label: 'Complex Multi-JOIN', value: 574_000, highlight: true },
];

export function ParseChart() {
  return (
    <div>
      <h3 className="text-lg font-semibold text-white mb-4">Parse Performance (Apple M4)</h3>
      <BarChart data={parseData} />
    </div>
  );
}
