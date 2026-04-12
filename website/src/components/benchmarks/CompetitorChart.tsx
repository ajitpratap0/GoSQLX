'use client';

import { BarChart, type BarChartItem } from './BarChart';

const competitorData: BarChartItem[] = [
  { label: 'GoSQLX', value: 1_380_000, highlight: true },
  { label: 'vitess-sqlparser', value: 560_000 },
  { label: 'pg_query_go', value: 340_000 },
  { label: 'sqlparser', value: 220_000 },
];

export function CompetitorChart() {
  return (
    <div>
      <h3 className="text-lg font-semibold text-white mb-4">Competitor Comparison</h3>
      <BarChart data={competitorData} />
      <p className="text-xs text-zinc-500 mt-3">
        * Competitor figures estimated from published benchmarks on equivalent hardware.
      </p>
    </div>
  );
}
