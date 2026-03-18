'use client';
import { useState, useCallback } from "react";

export interface LintViolation {
  severity?: string;
  level?: string;
  rule?: string;
  code?: string;
  rule_code?: string;
  line?: number;
  column?: number;
  location?: { line: number; column: number };
  message?: string;
  description?: string;
  msg?: string;
  suggestion?: string;
  fix?: string;
  hint?: string;
}

interface LintTabProps {
  data: { error?: string; violations?: LintViolation[]; results?: LintViolation[] } | LintViolation[] | null;
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase() || "info";
  const styles: Record<string, string> = {
    error: "bg-red-500/20 text-red-400 border-red-500/30",
    warning: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  const cls = styles[s] || styles.info;

  return (
    <span className={`inline-block px-2 py-0.5 text-xs font-medium rounded border ${cls} uppercase`}>
      {severity}
    </span>
  );
}

export default function LintTab({ data }: LintTabProps) {
  const [copied, setCopied] = useState(false);

  const violations = Array.isArray(data)
    ? data
    : data && !Array.isArray(data) && Array.isArray(data.violations)
      ? data.violations
      : data && !Array.isArray(data) && Array.isArray(data.results)
        ? data.results
        : [];

  const handleCopy = useCallback(() => {
    const text = violations.map((v: LintViolation) =>
      `[${(v.severity || v.level || 'info').toUpperCase()}] ${v.rule || v.code || v.rule_code || ''} ${v.message || v.description || v.msg || ''}`
    ).join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [violations]);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400 text-sm">
        No data available. Enter a SQL query to run the linter.
      </div>
    );
  }

  if (!Array.isArray(data) && data.error) {
    return (
      <div className="p-4">
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400 font-medium mb-1">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Lint Error
          </div>
          <p className="text-red-300 text-sm font-mono">{data.error}</p>
        </div>
      </div>
    );
  }

  if (violations.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3">
        <div className="w-12 h-12 rounded-full bg-green-500/20 flex items-center justify-center">
          <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <p className="text-green-400 font-medium">No violations found</p>
        <p className="text-slate-400 text-sm">Your SQL looks clean!</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-900/30">
        <span className="text-xs text-slate-400">{violations.length} violation{violations.length !== 1 ? "s" : ""} found</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded hover:bg-slate-700/50"
          aria-label="Copy lint violations to clipboard"
        >
          {copied ? (
            <>
              <svg className="w-3.5 h-3.5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-green-400">Copied!</span>
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
              Copy
            </>
          )}
        </button>
      </div>
      <div className="p-4 overflow-auto flex-1 space-y-3">
        {violations.map((v: LintViolation, i: number) => (
          <div
            key={i}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-3 space-y-2"
          >
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={v.severity || v.level || "info"} />
              {(v.rule || v.code || v.rule_code) && (
                <span className="text-xs font-mono text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded">
                  {v.rule || v.code || v.rule_code}
                </span>
              )}
              {(v.line !== undefined || v.location) && (
                <span className="text-xs text-slate-400 font-mono">
                  {v.location
                    ? `${v.location.line}:${v.location.column}`
                    : `${v.line}:${v.column ?? 0}`}
                </span>
              )}
            </div>
            <p className="text-sm text-slate-300">
              {v.message || v.description || v.msg}
            </p>
            {(v.suggestion || v.fix || v.hint) && (
              <p className="text-xs text-blue-400 flex items-center gap-1">
                <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {v.suggestion || v.fix || v.hint}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
