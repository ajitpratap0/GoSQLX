'use client';
import { useState, useCallback } from "react";
import SqlEditor from "./SqlEditor";
import { ErrorNotice } from "./ResultParts";

interface FormatTabProps {
  data: string | { result?: string; formatted?: string; error?: string } | null;
}

export default function FormatTab({ data }: FormatTabProps) {
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

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
    }).catch(() => {
      setCopyFailed(true);
      setTimeout(() => setCopyFailed(false), 2000);
    });
  }, [formatted]);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-fg-muted text-sm" aria-live="polite">
        No data available. Enter a SQL query to see formatted output.
      </div>
    );
  }

  if (typeof data !== "string" && data.error) {
    return (
      <div className="p-4">
        <ErrorNotice title="Format Error" message={data.error} polite />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-fg/[0.03]">
        <div className="flex items-center gap-2">
          <span className="text-xs text-fg-muted uppercase tracking-wider font-medium">Formatted SQL</span>
          <span className="text-xs text-fg-subtle bg-bg-overlay px-1.5 py-0.5 rounded">read-only</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 text-xs text-fg-muted hover:text-fg transition-colors px-2 py-1 rounded hover:bg-bg-overlay"
          aria-label="Copy formatted SQL to clipboard"
        >
          {copied ? (
            <>
              <svg className="w-3.5 h-3.5 text-ok" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-ok">Copied!</span>
            </>
          ) : copyFailed ? (
            <span className="text-danger">Failed</span>
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
