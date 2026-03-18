'use client';
import { useState, useCallback } from "react";
import SqlEditor from "./SqlEditor";

interface FormatTabProps {
  data: string | { result?: string; formatted?: string; error?: string } | null;
}

export default function FormatTab({ data }: FormatTabProps) {
  const [copied, setCopied] = useState(false);

  const formatted = data
    ? typeof data === "string"
      ? data
      : (data as { result?: string; formatted?: string }).result || (data as { formatted?: string }).formatted || JSON.stringify(data, null, 2)
    : null;

  const handleCopy = useCallback(() => {
    if (!formatted) return;
    navigator.clipboard.writeText(formatted).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [formatted]);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400 text-sm" aria-live="polite">
        No data available. Enter a SQL query to see formatted output.
      </div>
    );
  }

  if (typeof data !== "string" && data.error) {
    return (
      <div className="p-4">
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400 font-medium mb-1">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Format Error
          </div>
          <p className="text-red-300 text-sm font-mono">{data.error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-900/30">
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 uppercase tracking-wider font-medium">Formatted SQL</span>
          <span className="text-xs text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded">read-only</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded hover:bg-slate-700/50"
          aria-label="Copy formatted SQL to clipboard"
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
      <div className="flex-1 overflow-hidden p-2">
        <SqlEditor
          value={formatted || ""}
          onChange={() => {}}
          readOnly={true}
          minHeight="200px"
          placeholder="Formatted SQL will appear here..."
        />
      </div>
    </div>
  );
}
