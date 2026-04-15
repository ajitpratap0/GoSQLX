import { GlassCard } from '@/components/ui/GlassCard';
import { FadeIn } from '@/components/ui/FadeIn';

interface Dialect {
  name: string;
  abbr: string;
  color: string;
  bgColor: string;
  compliance: number;
  detail?: string;
  status: 'Excellent' | 'Very Good' | 'Good' | 'In Progress';
}

const DIALECTS: Dialect[] = [
  { name: 'PostgreSQL', abbr: 'PG', color: 'text-blue-400', bgColor: 'bg-blue-500/20', compliance: 95, status: 'Excellent' },
  { name: 'MySQL', abbr: 'My', color: 'text-orange-400', bgColor: 'bg-orange-500/20', compliance: 95, status: 'Excellent' },
  { name: 'MariaDB', abbr: 'Ma', color: 'text-sky-400', bgColor: 'bg-sky-500/20', compliance: 95, status: 'Excellent' },
  { name: 'SQL Server', abbr: 'MS', color: 'text-red-400', bgColor: 'bg-red-500/20', compliance: 85, status: 'Very Good' },
  { name: 'Oracle', abbr: 'Or', color: 'text-rose-400', bgColor: 'bg-rose-500/20', compliance: 80, status: 'Good' },
  { name: 'SQLite', abbr: 'SL', color: 'text-emerald-400', bgColor: 'bg-emerald-500/20', compliance: 85, status: 'Very Good' },
  { name: 'Snowflake', abbr: 'SF', color: 'text-cyan-400', bgColor: 'bg-cyan-500/20', compliance: 100, detail: '87/87 QA', status: 'Excellent' },
  { name: 'ClickHouse', abbr: 'CH', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20', compliance: 83, detail: '69/83 QA', status: 'Good' },
];

const statusColors: Record<Dialect['status'], string> = {
  'Excellent': 'bg-green-500/15 text-green-400 border-green-500/20',
  'Very Good': 'bg-blue-500/15 text-blue-400 border-blue-500/20',
  'Good': 'bg-yellow-500/15 text-yellow-400 border-yellow-500/20',
  'In Progress': 'bg-zinc-500/15 text-zinc-400 border-zinc-500/20',
};

function complianceColor(pct: number): string {
  if (pct >= 95) return 'text-green-400';
  if (pct >= 85) return 'text-blue-400';
  if (pct >= 80) return 'text-yellow-400';
  return 'text-zinc-400';
}

export function DialectShowcase() {
  return (
    <section className="py-20 border-t border-white/[0.06]">
      <div className="max-w-6xl mx-auto px-4">
        <FadeIn viewport>
          <h2 className="text-3xl font-bold text-white text-center mb-2">
            8 SQL Dialects, One Parser
          </h2>
          <p className="text-zinc-300 text-center mb-12 text-lg">
            From PostgreSQL to ClickHouse — parse them all
          </p>
        </FadeIn>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {DIALECTS.map((dialect, i) => (
            <FadeIn viewport key={dialect.name} delay={i * 0.08}>
              <GlassCard className="p-5 h-full text-center">
                <div
                  className={`w-11 h-11 rounded-full ${dialect.bgColor} ${dialect.color} flex items-center justify-center mx-auto mb-3 text-sm font-bold`}
                >
                  {dialect.abbr}
                </div>
                <h3 className="text-sm font-semibold text-white mb-2">
                  {dialect.name}
                </h3>
                <p className={`text-2xl font-bold mb-1 ${complianceColor(dialect.compliance)}`}>
                  {dialect.compliance}%
                </p>
                {dialect.detail && (
                  <p className="text-xs text-zinc-500 mb-2">{dialect.detail}</p>
                )}
                <span
                  className={`inline-block text-xs font-medium px-2.5 py-0.5 rounded-full border ${statusColors[dialect.status]}`}
                >
                  {dialect.status}
                </span>
              </GlassCard>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}
