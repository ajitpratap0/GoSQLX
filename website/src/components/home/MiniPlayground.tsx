'use client';
import { useState, useEffect, useCallback, useRef } from 'react';
import Link from 'next/link';
import { useWasm, type GoSQLXApi } from '@/components/playground/WasmLoader';

const SAMPLE_SQL = `SELECT
  u.name,
  u.email,
  COUNT(o.id) AS order_count,
  SUM(o.total) AS lifetime_value
FROM users u
LEFT JOIN orders o ON o.user_id = u.id
WHERE u.created_at > '2024-01-01'
GROUP BY u.name, u.email
HAVING COUNT(o.id) > 5
ORDER BY lifetime_value DESC
LIMIT 20;`;

const DIALECTS = [
  { value: 'generic', label: 'Generic' },
  { value: 'postgresql', label: 'PostgreSQL' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'sqlserver', label: 'SQL Server' },
  { value: 'snowflake', label: 'Snowflake' },
  { value: 'clickhouse', label: 'ClickHouse' },
];

type TabId = 'ast' | 'format' | 'lint';

function formatDuration(us: number): string {
  if (us < 1000) return `${us.toFixed(1)}\u00B5s`;
  return `${(us / 1000).toFixed(2)}ms`;
}

function runParse(api: GoSQLXApi, sql: string, dialect: string, tab: TabId) {
  const start = performance.now();
  let result: unknown;
  let error: string | null = null;
  try {
    if (tab === 'ast') {
      result = api.parse(sql, dialect);
    } else if (tab === 'format') {
      const f = api.format(sql, dialect);
      result = typeof f === 'string' ? f : (f as { result?: string }).result ?? JSON.stringify(f, null, 2);
    } else {
      result = api.lint(sql, dialect);
    }
  } catch (e: unknown) {
    error = e instanceof Error ? e.message : String(e);
  }
  const elapsed = (performance.now() - start) * 1000; // to microseconds
  return { result, error, elapsed };
}

function formatOutput(result: unknown, tab: TabId): string {
  if (tab === 'format') return typeof result === 'string' ? result : '';
  if (tab === 'lint') {
    const violations = Array.isArray(result)
      ? result
      : (result as { violations?: unknown[] })?.violations ?? [];
    if (Array.isArray(violations) && violations.length === 0) return 'No lint violations found.';
    return JSON.stringify(violations, null, 2);
  }
  return JSON.stringify(result, null, 2);
}

export function MiniPlayground() {
  const { loading, ready, api, progress } = useWasm();
  const [sql, setSql] = useState(SAMPLE_SQL);
  const [dialect, setDialect] = useState('generic');
  const [activeTab, setActiveTab] = useState<TabId>('ast');
  const [output, setOutput] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(null);

  const parse = useCallback(
    (query: string, dial: string, tab: TabId) => {
      if (!api || !query.trim()) {
        setOutput('');
        setParseError(null);
        setElapsed(null);
        return;
      }
      const { result, error, elapsed: us } = runParse(api, query, dial, tab);
      setElapsed(us);
      if (error) {
        setParseError(error);
        setOutput('');
      } else {
        setParseError(null);
        setOutput(formatOutput(result, tab));
      }
    },
    [api],
  );

  // Parse on ready
  useEffect(() => {
    if (ready && api) parse(sql, dialect, activeTab);
  }, [ready, api]); // eslint-disable-line react-hooks/exhaustive-deps

  // Re-parse on tab/dialect change (immediate)
  useEffect(() => {
    if (ready && api) parse(sql, dialect, activeTab);
  }, [dialect, activeTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // Debounced parse on SQL change
  const handleSqlChange = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      const value = e.target.value;
      setSql(value);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        parse(value, dialect, activeTab);
      }, 50);
    },
    [parse, dialect, activeTab],
  );

  const tabLabel = activeTab === 'ast' ? 'AST Output' : activeTab === 'format' ? 'Formatted' : 'Lint';

  return (
    <div className="grid md:grid-cols-2 divide-y md:divide-y-0 divide-x-0 md:divide-x divide-white/[0.06]">
      {/* Left: SQL input */}
      <div className="text-left min-w-0">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.06]">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
          </div>
          <span className="text-xs text-zinc-300 font-mono ml-2">query.sql</span>
          <div className="ml-auto flex items-center gap-1.5">
            <label htmlFor="mini-dialect" className="text-xs text-zinc-300 font-mono">Dialect:</label>
            <select
              id="mini-dialect"
              value={dialect}
              onChange={(e) => setDialect(e.target.value)}
              aria-label="SQL dialect"
              className="bg-zinc-800/80 text-zinc-300 text-xs rounded px-1.5 py-0.5 border border-white/[0.06] focus:outline-none focus:border-indigo-500/50 appearance-none cursor-pointer"
            >
              {DIALECTS.map((d) => (
                <option key={d.value} value={d.value}>{d.label}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="relative">
          <textarea
            value={sql}
            onChange={handleSqlChange}
            spellCheck={false}
            aria-label="SQL query input"
            className="w-full p-4 text-[14px] leading-relaxed font-mono bg-transparent resize-none max-h-[320px] min-h-[200px] focus:outline-none focus:ring-2 focus:ring-accent-indigo/50 overflow-auto"
            style={{ color: '#D4D4D8' }}
            rows={12}
          />
          <div
            className="absolute right-0 top-0 bottom-0 w-8 bg-gradient-to-l from-zinc-950/60 to-transparent pointer-events-none md:hidden"
            aria-hidden="true"
          />
        </div>
      </div>

      {/* Right: output */}
      <div className="text-left min-w-0 flex flex-col">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.06]">
          <div className="flex gap-1" role="tablist" aria-label="Output format">
            {(['ast', 'format', 'lint'] as TabId[]).map((tab) => (
              <button
                key={tab}
                role="tab"
                aria-selected={activeTab === tab}
                onClick={() => setActiveTab(tab)}
                className={`px-2 py-0.5 text-xs font-mono rounded transition-colors ${
                  activeTab === tab
                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {tab === 'ast' ? 'AST' : tab === 'format' ? 'Format' : 'Lint'}
              </button>
            ))}
          </div>
          <span className="ml-auto text-xs font-mono text-emerald-400">
            {loading
              ? progress < 1
                ? `Loading... ${Math.round(progress * 100)}%`
                : 'Initializing...'
              : elapsed !== null
                ? `Parsed in ${formatDuration(elapsed)}`
                : ''}
          </span>
        </div>
        <div
          role="tabpanel"
          aria-label={tabLabel}
          className="flex-1 overflow-auto max-h-[320px]"
        >
          {parseError ? (
            <pre className="p-4 text-[14px] leading-relaxed font-mono whitespace-pre-wrap" style={{ color: '#F87171' }}>
              {parseError}
            </pre>
          ) : (
            <pre className="p-4 text-[14px] leading-relaxed font-mono whitespace-pre-wrap" style={{ color: '#D4D4D8' }}>
              <code>{output || (loading ? SAMPLE_AST_PLACEHOLDER : '')}</code>
            </pre>
          )}
        </div>
        <div className="px-4 py-2 border-t border-white/[0.06]">
          <Link
            href="/playground"
            className="text-xs text-indigo-400 hover:text-indigo-300 transition-colors font-medium"
          >
            Open Full Playground &rarr;
          </Link>
        </div>
      </div>
    </div>
  );
}

// Static placeholder shown while WASM loads
const SAMPLE_AST_PLACEHOLDER = `{
  "type": "Query",
  "body": {
    "type": "Select",
    "projection": [
      { "type": "CompoundIdentifier", "value": "u.name" },
      { "type": "CompoundIdentifier", "value": "u.email" },
      { "type": "Function", "name": "COUNT", "alias": "order_count" },
      { "type": "Function", "name": "SUM", "alias": "lifetime_value" }
    ],
    "from": { "type": "Join", "join_type": "LEFT" },
    "group_by": ["u.name", "u.email"],
    "order_by": [{ "expr": "lifetime_value", "asc": false }],
    "limit": 20
  }
}`;
