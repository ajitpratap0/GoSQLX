'use client';
import React, { useState, useEffect, useCallback, useRef, Suspense } from "react";
import { motion } from "framer-motion";
import { useWasm } from "./WasmLoader";
import SqlEditor from "./SqlEditor";
import AstTab from "./AstTab";
import FormatTab from "./FormatTab";
import LintTab, { type LintViolation } from "./LintTab";
import type { AnalysisData } from "./AnalyzeTab";
const AnalyzeTab = React.lazy(() => import("./AnalyzeTab"));

const DEFAULT_SQL = `SELECT u.id, u.name, COUNT(o.id) AS order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.active = true
GROUP BY u.id, u.name
HAVING COUNT(o.id) > 5
ORDER BY order_count DESC
LIMIT 10;`;

const DIALECTS = [
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

type TabId = "ast" | "format" | "lint" | "analyze";

const TABS: { id: TabId; label: string }[] = [
  { id: "ast", label: "AST" },
  { id: "format", label: "Format" },
  { id: "lint", label: "Lint" },
  { id: "analyze", label: "Analyze" },
];

interface Results {
  ast: (Record<string, unknown> & { error?: string }) | null;
  format: string | { result?: string; formatted?: string; error?: string } | null;
  lint: { error?: string; violations?: LintViolation[]; results?: LintViolation[] } | LintViolation[] | null;
  analyze: AnalysisData | null;
}

export default function Playground() {
  const { loading, ready, error, api, progress } = useWasm();
  const [sql, setSql] = useState(DEFAULT_SQL);
  const [dialect, setDialect] = useState("generic");
  const [activeTab, setActiveTab] = useState<TabId>("ast");
  const [results, setResults] = useState<Results>({
    ast: null,
    format: null,
    lint: null,
    analyze: null,
  });
  const runIdRef = useRef(0);

  const runAll = useCallback(
    (query: string, dial: string) => {
      if (!api || !query.trim()) {
        setResults({ ast: null, format: null, lint: null, analyze: null });
        return;
      }

      const runId = ++runIdRef.current;

      const safeCall = (fn: () => unknown) => {
        try {
          return fn();
        } catch (e: unknown) {
          const message = e instanceof Error ? e.message : String(e);
          return { error: message };
        }
      };

      Promise.resolve().then(() => {
        if (runId !== runIdRef.current) return;

        const astResult = safeCall(() => api.parse(query, dial)) as Results['ast'];
        const formatResult = safeCall(() => api.format(query, dial)) as Results['format'];
        const lintResult = safeCall(() => api.lint(query, dial)) as Results['lint'];
        const analyzeResult = safeCall(() => api.analyze(query, dial)) as Results['analyze'];

        if (runId === runIdRef.current) {
          setResults({
            ast: astResult,
            format: formatResult,
            lint: lintResult,
            analyze: analyzeResult,
          });
        }
      });
    },
    [api]
  );

  useEffect(() => {
    if (ready && api) {
      runAll(sql, dialect);
    }
  }, [ready, api, sql, dialect, runAll]);

  const handleSqlChange = useCallback(
    (value: string) => {
      setSql(value);
    },
    []
  );

  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText('go get github.com/ajitpratap0/GoSQLX').then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col h-full bg-[#09090b]" aria-busy="true" aria-label="Loading SQL parser">
        {/* Skeleton toolbar */}
        <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="animate-pulse bg-zinc-800 rounded h-4 w-28" />
            <div className="h-4 w-px bg-slate-700" />
            <div className="animate-pulse bg-zinc-800 rounded h-6 w-36" />
          </div>
          <div className="animate-pulse bg-zinc-800 rounded h-4 w-20" />
        </div>
        {/* Skeleton panels */}
        <div className="flex flex-col lg:flex-row flex-1 min-h-0">
          {/* Left: editor skeleton */}
          <div className="w-full lg:w-1/2 border-r border-slate-800 flex flex-col min-h-[240px] lg:min-h-0 p-4 gap-3">
            <div className="animate-pulse bg-zinc-800 rounded h-3 w-3/4" />
            <div className="animate-pulse bg-zinc-800 rounded h-3 w-full" />
            <div className="animate-pulse bg-zinc-800 rounded h-3 w-5/6" />
            <div className="animate-pulse bg-zinc-800 rounded h-3 w-2/3" />
            <div className="animate-pulse bg-zinc-800 rounded h-3 w-4/5" />
          </div>
          {/* Right: tab + content skeleton */}
          <div className="w-full lg:w-1/2 flex flex-col min-h-0">
            <div className="flex border-b border-slate-800 bg-slate-900/30 gap-2 px-2 py-1">
              {[80, 72, 60, 88].map((w, i) => (
                <div key={i} className={`animate-pulse bg-zinc-800 rounded h-6`} style={{ width: w }} />
              ))}
            </div>
            <div className="flex-1 p-4 flex flex-col gap-3">
              <div className="animate-pulse bg-zinc-800 rounded h-3 w-1/2" />
              <div className="animate-pulse bg-zinc-800 rounded h-3 w-3/4" />
              <div className="animate-pulse bg-zinc-800 rounded h-3 w-2/3" />
            </div>
          </div>
        </div>
        {/* Progress overlay at bottom */}
        <div className="px-4 py-2 border-t border-slate-800 bg-slate-900/50 flex items-center gap-3">
          <div className="inline-block w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin flex-shrink-0" role="status" />
          <p className="text-slate-400 text-xs">
            {progress < 1
              ? `Downloading SQL parser… ${Math.round(progress * 100)}%`
              : "Initializing…"}
          </p>
          {progress > 0 && progress < 1 && (
            <div
              className="flex-1 bg-slate-700 rounded-full h-1"
              role="progressbar"
              aria-valuenow={Math.round(progress * 100)}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Download progress"
            >
              <div
                className="bg-blue-500 h-1 rounded-full transition-all duration-300"
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
      <div className="flex items-center justify-center h-full bg-[#09090b]">
        <div className="max-w-md text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-red-500/20 flex items-center justify-center mx-auto">
            <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-red-400 font-medium">Failed to load SQL parser</p>
          <p className="text-slate-400 text-sm">{error.message}</p>
          <p className="text-slate-400 text-xs">Try refreshing the page to retry.</p>
        </div>
      </div>
    );
  }

  const hasResults = results.ast !== null;

  return (
    <div className="flex flex-col h-full bg-[#09090b]">
      {/* Top toolbar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-900/50 min-h-[44px]">
        <div className="flex items-center gap-3">
          <h1 className="sr-only">SQL Playground</h1>
          <span className="hidden sm:block text-sm font-semibold text-slate-200" aria-hidden="true">SQL Playground</span>
          <div className="hidden sm:block h-4 w-px bg-slate-700" />
          <label htmlFor="dialect-select" className="flex items-center gap-2 text-sm text-slate-400">
            Dialect:
            <select
              id="dialect-select"
              value={dialect}
              onChange={(e) => setDialect(e.target.value)}
              className="bg-slate-800 text-slate-200 text-sm rounded px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 appearance-none cursor-pointer"
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
          <span className="w-2 h-2 rounded-full bg-green-500" aria-hidden="true" />
          <span className="text-xs text-slate-400">Parser ready</span>
        </div>
      </div>

      {/* Main content: split panels */}
      <div className="flex flex-col lg:flex-row flex-1 min-h-0">
        {/* Left panel - SQL Editor */}
        <div className="w-full lg:w-1/2 border-r border-slate-800 flex flex-col min-h-[240px] lg:min-h-0">
          <div className="px-4 py-2 border-b border-slate-800 bg-slate-900/30">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-medium">Input</span>
          </div>
          <div className="flex-1 overflow-hidden p-2">
            <SqlEditor
              value={sql}
              onChange={handleSqlChange}
              placeholder="Enter your SQL query here..."
              minHeight="200px"
            />
          </div>
        </div>

        {/* Right panel - Tabs + Content */}
        <div className="w-full lg:w-1/2 flex flex-col min-h-[240px] lg:min-h-0">
          {/* Tab bar with animated underline */}
          <div className="flex border-b border-slate-800 bg-slate-900/30" role="tablist" aria-label="Output format">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                role="tab"
                aria-selected={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 text-sm font-medium transition-colors relative ${
                  activeTab === tab.id
                    ? "text-blue-400"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {tab.label}
                {activeTab === tab.id && (
                  <motion.div
                    layoutId="playgroundActiveTab"
                    className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500"
                    transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                  />
                )}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-auto min-h-0" role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={`tab-${activeTab}`} aria-live="polite">
            {activeTab === "ast" && <AstTab data={results.ast} />}
            {activeTab === "format" && <FormatTab data={results.format} />}
            {activeTab === "lint" && <LintTab data={results.lint} />}
            {activeTab === "analyze" && (
              <Suspense fallback={<div className="flex items-center justify-center h-full text-slate-400 text-sm">Loading analyzer...</div>}>
                <AnalyzeTab data={results.analyze} />
              </Suspense>
            )}
          </div>
        </div>
      </div>
      {/* Post-use CTA — appears after first successful parse */}
      {hasResults && (
        <div className="flex items-center justify-between gap-4 px-4 py-2.5 border-t border-slate-800 bg-slate-900/50">
          <span className="text-xs text-slate-400 hidden sm:block">Ready to use this in your project?</span>
          <div className="flex items-center gap-2 flex-1 sm:flex-none">
            <code className="text-xs font-mono text-emerald-400 bg-slate-800 px-2.5 py-1 rounded">
              go get github.com/ajitpratap0/GoSQLX
            </code>
            <button
              onClick={handleCopy}
              className="text-xs text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 rounded px-3 py-2 transition-colors flex-shrink-0 min-h-[36px]"
              aria-label="Copy install command"
            >
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <a
            href="https://github.com/ajitpratap0/GoSQLX"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-slate-400 hover:text-white transition-colors flex-shrink-0"
          >
            GitHub →
          </a>
        </div>
      )}
    </div>
  );
}
