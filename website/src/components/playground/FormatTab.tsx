'use client';
import { useState, useCallback, type ReactNode } from "react";
import SqlEditor from "./SqlEditor";
import { ErrorNotice } from "./ResultParts";
import type { TextData } from "./bridgeTypes";

/** Format or Transpile output: SQL text from the bridge, or the call's error. */
export type SqlOutputData = string | TextData | null;

interface SqlOutputProps {
  data: SqlOutputData;
  /** Heading of the output pane, for example "Formatted SQL". */
  label: string;
  /** Title of the error notice, for example "Format Error". */
  errorTitle: string;
  /** Shown when there is no result yet. */
  emptyText: string;
  /** Optional controls above the output, such as dialect selects. */
  toolbar?: ReactNode;
}

/** Read-only SQL output with a copy button, shared by the Format and Transpile tabs. */
export function SqlOutput({ data, label, errorTitle, emptyText, toolbar }: SqlOutputProps) {
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

  const text = data ? (typeof data === "string" ? data : data.result ?? null) : null;
  const error = data && typeof data !== "string" ? data.error : undefined;

  const handleCopy = useCallback(() => {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      setCopyFailed(true);
      setTimeout(() => setCopyFailed(false), 2000);
    });
  }, [text]);

  let body: ReactNode;
  if (!data) {
    body = (
      <div className="flex items-center justify-center h-full p-4 text-fg-muted text-sm" aria-live="polite">
        {emptyText}
      </div>
    );
  } else if (error) {
    body = (
      <div className="p-4">
        <ErrorNotice title={errorTitle} message={error} polite />
      </div>
    );
  } else {
    body = (
      <>
        <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-fg/[0.03]">
          <div className="flex items-center gap-2">
            <span className="text-xs text-fg-muted uppercase tracking-wider font-medium">{label}</span>
            <span className="text-xs text-fg-subtle bg-bg-overlay px-1.5 py-0.5 rounded">read-only</span>
          </div>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 text-xs text-fg-muted hover:text-fg transition-colors px-2 py-1 rounded hover:bg-bg-overlay"
            aria-label={`Copy ${label.toLowerCase()} to clipboard`}
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
            value={text ?? ""}
            onChange={() => {}}
            readOnly={true}
            minHeight="200px"
            placeholder={`${label} will appear here...`}
          />
        </div>
      </>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {toolbar}
      {body}
    </div>
  );
}

interface FormatTabProps {
  data: SqlOutputData;
}

/**
 * Formatted SQL for the selected dialect. Comments and optimizer hints are
 * kept; SQL whose comments cannot be placed faithfully is reported as an error.
 */
export default function FormatTab({ data }: FormatTabProps) {
  return (
    <SqlOutput
      data={data}
      label="Formatted SQL"
      errorTitle="Format Error"
      emptyText="No data available. Enter a SQL query to see formatted output."
    />
  );
}
