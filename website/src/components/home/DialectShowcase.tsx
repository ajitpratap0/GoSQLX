import Link from 'next/link';
import { PROJECT, QA_CORPUS } from '@/data/metrics';
import { FadeIn } from '@/components/ui/FadeIn';

const COMPAT_HREF = '/docs/sql-compatibility/#supported-dialects';

interface Dialect {
  name: string;
  /** The dialect string passed to the parser (docs/SQL_COMPATIBILITY.md, "Supported Dialects"). */
  key: string;
  /** QA-corpus result, only where a corpus run is recorded. No unsourced percentages. */
  qa?: { pass: number; total: number };
}

const DIALECTS: Dialect[] = [
  { name: 'PostgreSQL', key: 'postgresql' },
  { name: 'MySQL', key: 'mysql' },
  { name: 'MariaDB', key: 'mariadb' },
  { name: 'SQL Server', key: 'sqlserver' },
  { name: 'Oracle', key: 'oracle' },
  { name: 'SQLite', key: 'sqlite' },
  { name: 'Snowflake', key: 'snowflake', qa: QA_CORPUS.snowflake },
  { name: 'ClickHouse', key: 'clickhouse', qa: QA_CORPUS.clickhouse },
];

/** Neutral database glyph shared by every dialect (no vendor marks). */
function DatabaseGlyph() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <ellipse cx="12" cy="5.5" rx="7.5" ry="2.75" />
      <path d="M4.5 5.5v13c0 1.5 3.4 2.75 7.5 2.75s7.5-1.25 7.5-2.75v-13M4.5 12c0 1.5 3.4 2.75 7.5 2.75s7.5-1.25 7.5-2.75" />
    </svg>
  );
}

export function DialectShowcase() {
  return (
    <section className="py-20 border-t border-fg/[0.06]">
      <div className="max-w-6xl mx-auto px-4">
        <FadeIn viewport>
          <h2 className="text-3xl font-bold text-fg text-center mb-2">
            {PROJECT.dialectCount} SQL Dialects, One Parser
          </h2>
          <p className="text-fg-muted text-center mb-12 text-lg">
            From PostgreSQL to ClickHouse, selected with a single dialect string
          </p>
        </FadeIn>
        {/* 8 cards: 2 columns on phones, 4 from md, so every row is full. */}
        <ul className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {DIALECTS.map((dialect, i) => (
            <li key={dialect.key}>
              <FadeIn viewport delay={i * 0.05} className="h-full">
                <Link
                  href={COMPAT_HREF}
                  className="glass glass-hover flex h-full flex-col items-center p-5 text-center transition-colors"
                >
                  <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-accent/10 text-accent">
                    <DatabaseGlyph />
                  </span>
                  <h3 className="text-sm font-semibold text-fg">{dialect.name}</h3>
                  <code className="mt-1 text-xs text-fg-subtle">&quot;{dialect.key}&quot;</code>
                  <span className="mt-3 text-xs text-accent">
                    {dialect.qa
                      ? `QA corpus pass ${dialect.qa.pass}/${dialect.qa.total} (${QA_CORPUS.release})`
                      : 'Coverage notes'}
                    <span aria-hidden="true"> →</span>
                  </span>
                </Link>
              </FadeIn>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
