'use client';
import { useState, useEffect, useCallback, useRef } from 'react';
import Link from 'next/link';
import sample from '@/generated/sample-ast.json';
import { useWasm, type GoSQLXApi } from '@/components/playground/WasmLoader';
import type { LintData } from '@/components/playground/bridgeTypes';

// Query, formatted SQL and AST are generated from sample.sql by the real
// parser and formatter (scripts/gen-sample-ast), so the demo shows real output
// before WASM loads.
const SAMPLE_SQL = sample.sql;
const SAMPLE_FORMATTED = sample.formatted;

const DIALECTS = [
  { value: 'generic', label: 'Generic' },
  { value: 'postgresql', label: 'PostgreSQL' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'sqlserver', label: 'SQL Server' },
  { value: 'snowflake', label: 'Snowflake' },
  { value: 'clickhouse', label: 'ClickHouse' },
];

type TabId = 'format' | 'tree' | 'lint';

const TABS: { id: TabId; label: string }[] = [
  { id: 'format', label: 'Formatted' },
  { id: 'tree', label: 'Tree' },
  { id: 'lint', label: 'Lint' },
];

function formatDuration(us: number): string {
  if (us < 1000) return `${us.toFixed(1)}\u00B5s`;
  return `${(us / 1000).toFixed(2)}ms`;
}

/**
 * Drops null, false, empty-string, empty-array and empty-object fields so the
 * Tree tab shows the shape of the query rather than every unset struct field.
 * Returns undefined when the value itself is empty.
 */
function pruneTree(value: unknown): unknown {
  if (value === null || value === false || value === '' || value === undefined) return undefined;
  if (Array.isArray(value)) {
    const items = value.map(pruneTree).filter((v) => v !== undefined);
    return items.length > 0 ? items : undefined;
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const pruned = pruneTree(v);
      if (pruned !== undefined) out[k] = pruned;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }
  return value;
}

function treeText(ast: unknown): string {
  return JSON.stringify(pruneTree(ast) ?? {}, null, 2);
}

const STATEMENT_KEYWORDS = [
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'CREATE', 'ALTER', 'DROP',
  'TRUNCATE', 'WITH', 'VALUES', 'EXPLAIN', 'SHOW', 'DESCRIBE', 'GRANT', 'REVOKE',
];

/** Statement-type chip for a query the parser accepted, e.g. "SELECT" or "3 statements". */
function statementLabel(sql: string, ast: unknown): string | null {
  const stmts = (ast as { Statements?: unknown[] } | null)?.Statements;
  const count = Array.isArray(stmts) ? stmts.length : 0;
  if (count === 0) return null;
  if (count > 1) return `${count} statements`;
  const stripped = sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, ' ').trimStart();
  const first = stripped.match(/^[A-Za-z]+/)?.[0]?.toUpperCase();
  if (!first || !STATEMENT_KEYWORDS.includes(first)) return 'statement';
  return first === 'WITH' ? 'WITH (CTE)' : first;
}

const SAMPLE_TREE = treeText(sample.ast);
const SAMPLE_STATEMENT = statementLabel(SAMPLE_SQL, sample.ast);

interface DemoResult {
  output: string;
  error: string | null;
  /** Time spent in the WASM parse call only, in microseconds. */
  parseUs: number | null;
  statement: string | null;
}

function runDemo(api: GoSQLXApi, sql: string, dialect: string, tab: TabId): DemoResult {
  let ast: unknown;
  const start = performance.now();
  try {
    ast = api.parse(sql, dialect);
  } catch (e: unknown) {
    return { output: '', error: e instanceof Error ? e.message : String(e), parseUs: null, statement: null };
  }
  const parseUs = (performance.now() - start) * 1000;
  const statement = statementLabel(sql, ast);
  try {
    if (tab === 'tree') return { output: treeText(ast), error: null, parseUs, statement };
    if (tab === 'format') {
      const f = api.format(sql, dialect);
      const text = typeof f === 'string' ? f : (f as { result?: string }).result ?? '';
      return { output: text, error: null, parseUs, statement };
    }
    const lint = api.lint(sql, dialect) as LintData;
    if (lint?.error) return { output: '', error: lint.error, parseUs, statement };
    const violations = lint?.violations ?? [];
    const output = violations.length === 0
      ? 'No lint violations found.'
      : violations
          .map((v) => `${v.rule} ${v.severity.toUpperCase()}${v.line > 0 ? ` ${v.line}:${v.column}` : ''}  ${v.message}`)
          .join('\n');
    return { output, error: null, parseUs, statement };
  } catch (e: unknown) {
    return { output: '', error: e instanceof Error ? e.message : String(e), parseUs, statement };
  }
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center rounded-full border border-fg/[0.08] bg-fg/[0.04] px-2 py-0.5 text-[11px] font-mono text-fg-muted whitespace-nowrap">
      {children}
    </span>
  );
}

export function MiniPlayground() {
  // WASM is deferred until the user shows intent (focus, click, or tab/dialect change).
  const [wasmRequested, setWasmRequested] = useState(false);
  const requestWasm = useCallback(() => setWasmRequested(true), []);
  const { loading, ready, api, progress } = useWasm(wasmRequested);
  const [sql, setSql] = useState(SAMPLE_SQL);
  const [dialect, setDialect] = useState('generic');
  const [activeTab, setActiveTab] = useState<TabId>('format');
  const [output, setOutput] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const [statement, setStatement] = useState<string | null>(SAMPLE_STATEMENT);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(null);

  const parse = useCallback(
    (query: string, dial: string, tab: TabId) => {
      if (!api || !query.trim()) {
        setOutput('');
        setParseError(null);
        setElapsed(null);
        setStatement(null);
        return;
      }
      const res = runDemo(api, query, dial, tab);
      setElapsed(res.parseUs);
      setStatement(res.statement);
      setParseError(res.error);
      setOutput(res.error ? '' : res.output);
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

  const tabLabel = TABS.find((t) => t.id === activeTab)?.label ?? '';
  const dialectLabel = DIALECTS.find((d) => d.value === dialect)?.label ?? dialect;
  // Before WASM is ready, show the precomputed output for the untouched sample.
  const precomputed = activeTab === 'format' ? SAMPLE_FORMATTED : activeTab === 'tree' ? SAMPLE_TREE : '';
  const shown = output || (!ready && sql === SAMPLE_SQL ? precomputed : '');
  const status = !wasmRequested
    ? 'Precomputed sample'
    : loading
      ? progress < 1
        ? `Loading... ${Math.round(progress * 100)}%`
        : 'Initializing...'
      : '';

  return (
    <div
      className="grid md:grid-cols-2 divide-y md:divide-y-0 divide-x-0 md:divide-x divide-fg/[0.06]"
      onFocusCapture={requestWasm}
      onPointerDownCapture={requestWasm}
    >
      {/* Left: SQL input */}
      <div className="text-left min-w-0">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-fg/[0.06]">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-danger/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-warn/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-ok/60" />
          </div>
          <span className="text-xs text-fg-muted font-mono ml-2">query.sql</span>
          <div className="ml-auto flex items-center gap-1.5">
            <label htmlFor="mini-dialect" className="text-xs text-fg-muted font-mono">Dialect:</label>
            <select
              id="mini-dialect"
              value={dialect}
              onChange={(e) => setDialect(e.target.value)}
              aria-label="SQL dialect"
              className="bg-bg-overlay text-fg-muted text-xs rounded px-1.5 py-0.5 border border-fg/[0.06] focus:outline-none focus:border-accent/50 appearance-none cursor-pointer"
            >
              {DIALECTS.map((d) => (
                <option key={d.value} value={d.value}>{d.label}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="code-surface relative">
          <textarea
            value={sql}
            onChange={handleSqlChange}
            spellCheck={false}
            aria-label="SQL query input"
            className="w-full p-4 text-[14px] leading-relaxed font-mono bg-transparent resize-none max-h-[180px] min-h-[160px] md:max-h-[320px] md:min-h-[200px] focus:outline-none focus:ring-2 focus:ring-accent/50 overflow-auto"
            style={{ color: '#D4D4D8' }}
            rows={12}
          />
          <div
            className="absolute right-0 top-0 bottom-0 w-8 bg-gradient-to-l from-bg-raised to-transparent pointer-events-none md:hidden"
            aria-hidden="true"
          />
        </div>
      </div>

      {/* Right: output */}
      <div className="text-left min-w-0 flex flex-col">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-fg/[0.06]">
          <div className="flex gap-1" role="tablist" aria-label="Output format">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-2 py-0.5 text-xs font-mono rounded transition-colors ${
                  activeTab === tab.id
                    ? 'bg-accent/20 text-accent border border-accent/30'
                    : 'text-fg-muted hover:text-fg'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
          {status && <span className="ml-auto text-xs font-mono text-fg-muted">{status}</span>}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 px-4 py-2 border-b border-fg/[0.06]">
          {elapsed !== null && !parseError && (
            <Chip>
              <span className="text-brand">parsed in {formatDuration(elapsed)}</span>
            </Chip>
          )}
          <Chip>{dialectLabel}</Chip>
          {statement && !parseError && (ready || sql === SAMPLE_SQL) && <Chip>{statement}</Chip>}
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
              <code>{shown}</code>
            </pre>
          )}
        </div>
        <div className="px-4 py-2 border-t border-fg/[0.06]">
          <Link
            href="/playground"
            className="text-xs text-accent hover:underline font-medium"
          >
            Open Full Playground &rarr;
          </Link>
        </div>
      </div>
    </div>
  );
}
