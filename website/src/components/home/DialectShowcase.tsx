import { PROJECT, QA_CORPUS } from '@/data/metrics';
import { GlassCard } from '@/components/ui/GlassCard';
import { FadeIn } from '@/components/ui/FadeIn';

interface Dialect {
  name: string;
  abbr: string;
  bgColor: string;
  compliance: number;
  detail?: string;
  status: 'Excellent' | 'Very Good' | 'Good' | 'In Progress';
}

const DIALECTS: Dialect[] = [
  { name: 'PostgreSQL', abbr: 'PG', bgColor: 'bg-blue-500/20', compliance: 95, status: 'Excellent' },
  { name: 'MySQL', abbr: 'My', bgColor: 'bg-orange-500/20', compliance: 95, status: 'Excellent' },
  { name: 'MariaDB', abbr: 'Ma', bgColor: 'bg-sky-500/20', compliance: 95, status: 'Excellent' },
  { name: 'SQL Server', abbr: 'MS', bgColor: 'bg-red-500/20', compliance: 85, status: 'Very Good' },
  { name: 'Oracle', abbr: 'Or', bgColor: 'bg-rose-500/20', compliance: 80, status: 'Good' },
  { name: 'SQLite', abbr: 'SL', bgColor: 'bg-emerald-500/20', compliance: 85, status: 'Very Good' },
  { name: 'Snowflake', abbr: 'SF', bgColor: 'bg-cyan-500/20', compliance: Math.round((QA_CORPUS.snowflake.pass / QA_CORPUS.snowflake.total) * 100), detail: `${QA_CORPUS.snowflake.pass}/${QA_CORPUS.snowflake.total} QA`, status: 'Excellent' },
  { name: 'ClickHouse', abbr: 'CH', bgColor: 'bg-yellow-500/20', compliance: Math.round((QA_CORPUS.clickhouse.pass / QA_CORPUS.clickhouse.total) * 100), detail: `${QA_CORPUS.clickhouse.pass}/${QA_CORPUS.clickhouse.total} QA`, status: 'Good' },
];

const statusColors: Record<Dialect['status'], string> = {
  'Excellent': 'bg-ok/10 text-ok border-ok/20',
  'Very Good': 'bg-accent/10 text-accent border-accent/20',
  'Good': 'bg-accent-warm/10 text-accent-warm border-accent-warm/20',
  'In Progress': 'bg-fg-subtle/10 text-fg-subtle border-border',
};

function complianceColor(pct: number): string {
  if (pct >= 95) return 'text-ok';
  if (pct >= 85) return 'text-accent';
  if (pct >= 80) return 'text-accent-warm';
  return 'text-fg-subtle';
}

export function DialectShowcase() {
  return (
    <section className="py-20 border-t border-white/[0.06]">
      <div className="max-w-6xl mx-auto px-4">
        <FadeIn viewport>
          <h2 className="text-3xl font-bold text-white text-center mb-2">
            {PROJECT.dialectCount} SQL Dialects, One Parser
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
                  className={`w-11 h-11 rounded-full ${dialect.bgColor} text-fg flex items-center justify-center mx-auto mb-3 text-sm font-bold`}
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
                  <p className="text-xs text-fg-subtle mb-2">{dialect.detail}</p>
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
