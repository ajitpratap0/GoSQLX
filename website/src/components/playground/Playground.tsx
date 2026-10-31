'use client';
import { useCopyFeedback } from "./useCopyFeedback";
import React, { useState, useEffect, useCallback, useMemo, useRef, Suspense } from "react";
import { useWasm, type GoSQLXApi } from "./WasmLoader";
import SqlEditor from "./SqlEditor";
import AstTab from "./AstTab";
import FormatTab, { type SqlOutputData } from "./FormatTab";
import LintTab from "./LintTab";
import TranspileTab, { type DialectOption } from "./TranspileTab";
import type { AnalysisData, LintData } from "./bridgeTypes";
import type { EditorErrorMarker } from "./editorDiagnostics";
import type { HighlightSource } from "./editorHighlight";
const AnalyzeTab = React.lazy(() => import("./AnalyzeTab"));

// The comment shows that Format keeps comments.
const DEFAULT_SQL = `-- Active users with more than five orders
SELECT u.id, u.name, COUNT(o.id) AS order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.active = true
GROUP BY u.id, u.name
HAVING COUNT(o.id) > 5
ORDER BY order_count DESC
LIMIT 10;`;

const DIALECTS: DialectOption[] = [
  { value: "generic", label: "Generic" },
  { value: "postgresql", label: "PostgreSQL" },
  { value: "mysql", label: "MySQL" },
  { value: "mariadb", label: "MariaDB" },
  { value: "sqlite", label: "SQLite" },
  { value: "sqlserver", label: "SQL Server" },
  { value: "oracle", label: "Oracle" },
  { value: "snowflake", label: "Snowflake" },
  { value: "clickhouse", label: "ClickHouse" },
];

type TabId = "ast" | "format" | "transpile" | "lint" | "analyze";

const TABS: { id: TabId; label: string }[] = [
  { id: "ast", label: "AST" },
  { id: "format", label: "Format" },
  { id: "transpile", label: "Transpile" },
  { id: "lint", label: "Lint" },
  { id: "analyze", label: "Analyze" },
];

interface Results {
  /** The SQL these results were computed for. */
  source: string | null;
  /** SQL, dialect and transpile target these results were computed for. */
  inputKey: string | null;
  ast: (Record<string, unknown> & { error?: string }) | null;
  format: SqlOutputData;
  transpile: SqlOutputData;
  lint: LintData | null;
  analyze: AnalysisData | null;
}

type ResultKey = TabId;

const EMPTY_RESULTS: Results = {
  source: null,
  inputKey: null,
  ast: null,
  format: null,
  transpile: null,
  lint: null,
  analyze: null,
};

function callFor(api: GoSQLXApi, key: ResultKey, query: string, dial: string, target: string): Promise<unknown> {
  switch (key) {
    case "ast":
      return api.parse(query, dial);
    case "format":
      return api.format(query, dial);
    case "transpile":
      return api.transpile(query, dial, target);
    case "lint":
      return api.lint(query, dial);
    case "analyze":
      return api.analyze(query, dial);
  }
}

/** The result for key, or { error } when the call fails. */
async function computeResult(api: GoSQLXApi, key: ResultKey, query: string, dial: string, target: string): Promise<unknown> {
  try {
    return await callFor(api, key, query, dial, target);
  } catch (e: unknown) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

export default function Playground() {
  const { loading, ready, error, api, progress } = useWasm();
  const [sql, setSql] = useState(DEFAULT_SQL);
  const [dialect, setDialect] = useState("generic");
  const [transpileTarget, setTranspileTarget] = useState("postgresql");
  const [activeTab, setActiveTab] = useState<TabId>("ast");
  const [computedResults, setResults] = useState<Results>(EMPTY_RESULTS);
  const resultsRef = useRef(computedResults);
  useEffect(() => {
    resultsRef.current = computedResults;
  }, [computedResults]);
  const results = sql.trim() ? computedResults : EMPTY_RESULTS;

  // The parser runs in a Web Worker (see WasmLoader). Compute only what is on
  // screen: the active tab, plus lint, whose parse error span marks the
  // editor; other tabs are computed when opened. New results are committed
  // together, so the previous output stays visible until they are ready, and
  // results for input that changed meanwhile are dropped.
  useEffect(() => {
    if (!ready || !api || !sql.trim()) return;

    const inputKey = JSON.stringify([sql, dialect, transpileTarget]);
    const current = resultsRef.current;
    const base = current.inputKey === inputKey ? current : { ...EMPTY_RESULTS, source: sql, inputKey };
    const wanted: ResultKey[] = activeTab === "lint" ? ["lint"] : [activeTab, "lint"];
    const pending = wanted.filter((key) => base[key] === null);
    if (pending.length === 0) return;

    let cancelled = false;
    (async () => {
      const computed: Partial<Record<ResultKey, unknown>> = {};
      for (const key of pending) {
        computed[key] = await computeResult(api, key, sql, dialect, transpileTarget);
        if (cancelled) return;
      }
      setResults((prev) => ({
        ...(prev.inputKey === inputKey ? prev : base),
        ...(computed as Partial<Results>),
      }));
    })();
    return () => {
      cancelled = true;
    };
  }, [ready, api, sql, dialect, transpileTarget, activeTab]);

  const handleSqlChange = useCallback(
    (value: string) => {
      setSql(value);
    },
    []
  );

  // Lint and Analyze both parse the SQL and locate a parse error the same way.
  const errorSpan = results.lint?.parse_error_span ?? results.analyze?.parse_error_span;
  const errorMarker = useMemo<EditorErrorMarker | null>(
    () => (results.source !== null && errorSpan ? { source: results.source, span: errorSpan } : null),
    [results.source, errorSpan],
  );

  // GoSQLX highlighting in the selected dialect once the parser is loaded.
  const highlighter = useMemo<HighlightSource | null>(
    () => (api ? async (text: string) => (await api.highlight(text, dialect)).spans : null),
    [api, dialect],
  );

  const { copied, flash } = useCopyFeedback();

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText('go get github.com/ajitpratap0/GoSQLX').then(() => {
      flash("copied");
    }).catch(() => {
      flash("failed");
    });
  }, [flash]);

  if (loading) {
    return (
      <div className="flex flex-col h-full bg-bg" aria-busy="true" aria-label="Loading SQL parser">
        {/* Skeleton toolbar */}
        <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-fg/[0.03]">
          <div className="flex items-center gap-3">
            <div className="animate-pulse bg-bg-overlay rounded h-4 w-28" />
            <div className="h-4 w-px bg-bg-overlay" />
            <div className="animate-pulse bg-bg-overlay rounded h-6 w-36" />
          </div>
          <div className="animate-pulse bg-bg-overlay rounded h-4 w-20" />
        </div>
        {/* Skeleton panels */}
        <div className="flex flex-col lg:flex-row flex-1 min-h-0 border-x border-b border-pane-border">
          {/* Left: editor skeleton */}
          <div className="w-full lg:w-1/2 border-r border-border bg-pane-bg flex flex-col min-h-[240px] lg:min-h-0 p-4 gap-3">
            <div className="animate-pulse bg-bg-overlay rounded h-3 w-3/4" />
            <div className="animate-pulse bg-bg-overlay rounded h-3 w-full" />
            <div className="animate-pulse bg-bg-overlay rounded h-3 w-5/6" />
            <div className="animate-pulse bg-bg-overlay rounded h-3 w-2/3" />
            <div className="animate-pulse bg-bg-overlay rounded h-3 w-4/5" />
          </div>
          {/* Right: tab + content skeleton */}
          <div className="w-full lg:w-1/2 bg-pane-bg flex flex-col min-h-0">
            <div className="flex border-b border-border bg-fg/[0.03] gap-2 px-2 py-1">
              {[80, 72, 88, 60, 88].map((w, i) => (
                <div key={i} className={`animate-pulse bg-bg-overlay rounded h-6`} style={{ width: w }} />
              ))}
            </div>
            <div className="flex-1 p-4 flex flex-col gap-3">
              <div className="animate-pulse bg-bg-overlay rounded h-3 w-1/2" />
              <div className="animate-pulse bg-bg-overlay rounded h-3 w-3/4" />
              <div className="animate-pulse bg-bg-overlay rounded h-3 w-2/3" />
            </div>
          </div>
        </div>
        {/* Progress overlay at bottom */}
        <div className="px-4 py-2 border-t border-border bg-fg/[0.03] flex items-center gap-3">
          <div className="inline-block w-4 h-4 border-2 border-info border-t-transparent rounded-full animate-spin flex-shrink-0" role="status" />
          <p className="text-fg-muted text-xs">
            {progress < 1
              ? `Downloading SQL parser… ${Math.round(progress * 100)}%`
              : "Initializing…"}
          </p>
          {progress > 0 && progress < 1 && (
            <div
              className="flex-1 bg-bg-overlay rounded-full h-1"
              role="progressbar"
              aria-valuenow={Math.round(progress * 100)}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Download progress"
            >
              <div
                className="bg-info h-1 rounded-full transition-all duration-300"
                style={{ width: `${progress * 100}%` }}
              />
            </div>
          )}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full bg-bg">
        <div className="max-w-md text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-danger/20 flex items-center justify-center mx-auto">
            <svg className="w-6 h-6 text-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-danger font-medium">Failed to load SQL parser</p>
          <p className="text-fg-muted text-sm">{error.message}</p>
          <p className="text-fg-muted text-xs">Try refreshing the page to retry.</p>
        </div>
      </div>
    );
  }

  const hasResults = results.source !== null;

  return (
    <div className="flex flex-col h-full bg-bg">
      {/* Top toolbar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-fg/[0.03] min-h-[44px]">
        <div className="flex items-center gap-3">
          <span className="hidden sm:block text-sm font-semibold text-fg" aria-hidden="true">SQL Playground</span>
          <div className="hidden sm:block h-4 w-px bg-bg-overlay" />
          <label htmlFor="dialect-select" className="flex items-center gap-2 text-sm text-fg-muted">
            Dialect:
            <select
              id="dialect-select"
              value={dialect}
              onChange={(e) => setDialect(e.target.value)}
              className="bg-bg-overlay text-fg text-sm rounded px-2 py-1 border border-border focus:outline-none focus:border-info appearance-none cursor-pointer"
            >
              {DIALECTS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-ok" aria-hidden="true" />
          <span className="text-xs text-fg-muted">Parser ready</span>
        </div>
      </div>

      {/* Main content: split panels */}
      <div className="flex flex-col lg:flex-row flex-1 min-h-0 border-x border-b border-pane-border">
        {/* Left panel - SQL Editor */}
        <div className="w-full lg:w-1/2 border-r border-border bg-pane-bg flex flex-col min-h-[240px] lg:min-h-0">
          <div className="px-4 py-2 border-b border-border bg-pane-band">
            <span className="text-xs text-fg-muted uppercase tracking-wider font-medium">Input</span>
          </div>
          <div className="flex-1 overflow-hidden p-2">
            <SqlEditor
              value={sql}
              onChange={handleSqlChange}
              placeholder="Enter your SQL query here..."
              minHeight="200px"
              errorMarker={errorMarker}
              highlighter={highlighter}
            />
          </div>
        </div>

        {/* Right panel - Tabs + Content */}
        <div className="w-full lg:w-1/2 bg-pane-bg flex flex-col min-h-[240px] lg:min-h-0">
          {/* Tab bar with animated underline */}
          <div className="flex overflow-x-auto border-b border-border bg-pane-band" role="tablist" aria-label="Output format">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                role="tab"
                aria-selected={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`shrink-0 whitespace-nowrap px-3 sm:px-4 py-3 text-sm font-medium transition-colors relative ${
                  activeTab === tab.id
                    ? "text-info"
                    : "text-fg-muted hover:text-fg"
                }`}
              >
                {tab.label}
                <span
                  aria-hidden="true"
                  className={`absolute bottom-0 left-0 right-0 h-0.5 bg-info origin-left ${
                    activeTab === tab.id
                      ? "scale-x-100 transition-transform duration-300 ease-out motion-reduce:transition-none"
                      : "hidden"
                  }`}
                />
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-auto min-h-0" role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={`tab-${activeTab}`} aria-live="polite">
            {activeTab === "ast" && <AstTab data={results.ast} />}
            {activeTab === "format" && <FormatTab data={results.format} />}
            {activeTab === "transpile" && (
              <TranspileTab
                data={results.transpile}
                dialects={DIALECTS}
                from={dialect}
                to={transpileTarget}
                onFromChange={setDialect}
                onToChange={setTranspileTarget}
              />
            )}
            {activeTab === "lint" && <LintTab data={results.lint} />}
            {activeTab === "analyze" && (
              <Suspense fallback={<div className="flex items-center justify-center h-full text-fg-muted text-sm">Loading analyzer...</div>}>
                <AnalyzeTab data={results.analyze} />
              </Suspense>
            )}
          </div>
        </div>
      </div>
      {/* Post-use CTA — appears after first successful parse */}
      {hasResults && (
        <div className="flex items-center justify-between gap-4 px-4 py-2.5 border-t border-border bg-fg/[0.03]">
          <span className="text-xs text-fg-muted hidden sm:block">Ready to use this in your project?</span>
          <div className="flex items-center gap-2 flex-1 sm:flex-none">
            <code className="text-xs font-mono text-brand bg-bg-overlay px-2.5 py-1 rounded">
              go get github.com/ajitpratap0/GoSQLX
            </code>
            <button
              onClick={handleCopy}
              className="text-xs text-fg-muted hover:text-fg border border-border hover:border-fg-subtle rounded px-3 py-2 transition-colors flex-shrink-0 min-h-[36px]"
              aria-label="Copy install command"
            >
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <a
            href="https://github.com/ajitpratap0/GoSQLX"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-fg-muted hover:text-fg transition-colors flex-shrink-0"
          >
            GitHub →
          </a>
        </div>
      )}
    </div>
  );
}
