'use client';
import { useCopyFeedback } from "./useCopyFeedback";
import { useCallback } from "react";
import { formatPosition, type LintData, type LintViolation } from "./bridgeTypes";
import { ErrorNotice, Position, SeverityBadge } from "./ResultParts";

export type { LintViolation, LintData } from "./bridgeTypes";

const NO_VIOLATIONS: LintViolation[] = [];

interface LintTabProps {
  data: LintData | null;
}

export default function LintTab({ data }: LintTabProps) {
  const { copied, copyFailed, flash } = useCopyFeedback();

  const violations = data?.violations ?? NO_VIOLATIONS;

  const handleCopy = useCallback(() => {
    const text = violations.map((v: LintViolation) =>
      `[${(v.severity || 'info').toUpperCase()}] ${v.rule} ${formatPosition(v.line, v.column) ?? ''} ${v.message}`.replace(/\s+/g, ' ')
    ).join('\n');
    navigator.clipboard.writeText(text).then(() => {
      flash("copied");
    }).catch(() => {
      flash("failed");
    });
  }, [violations, flash]);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-fg-muted text-sm">
        No data available. Enter a SQL query to run the linter.
      </div>
    );
  }

  if (data.error) {
    return (
      <div className="p-4">
        <ErrorNotice title="Lint error" message={data.error} />
      </div>
    );
  }

  const parseNotice = data.parse_error ? (
    <ErrorNotice title="Parse error" message={data.parse_error} polite>
      <p className="text-fg-muted text-xs mt-3">
        Rules that need a parsed statement could not run. Fix the error above to lint the full query.
      </p>
    </ErrorNotice>
  ) : null;

  if (violations.length === 0) {
    if (parseNotice) {
      return <div className="p-4">{parseNotice}</div>;
    }
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3">
        <div className="w-12 h-12 rounded-full bg-ok/20 flex items-center justify-center">
          <svg className="w-6 h-6 text-ok" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <p className="text-ok font-medium">No violations found</p>
        <p className="text-fg-muted text-sm">Your SQL looks clean!</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-fg/[0.03]">
        <span className="text-xs text-fg-muted">{violations.length} violation{violations.length !== 1 ? "s" : ""} found</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 text-xs text-fg-muted hover:text-fg transition-colors px-2 py-1 rounded hover:bg-bg-overlay"
          aria-label="Copy lint violations to clipboard"
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
      <div className="p-4 overflow-auto flex-1 space-y-3">
        {parseNotice}
        {violations.map((v: LintViolation, i: number) => (
          <div
            key={i}
            className="bg-bg-overlay border border-border rounded-lg p-3 space-y-2"
          >
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={v.severity} />
              <span className="text-xs font-mono text-violet bg-violet/10 px-1.5 py-0.5 rounded" title={v.rule_name}>
                {v.rule}
              </span>
              {v.rule_name && <span className="text-xs text-fg-muted">{v.rule_name}</span>}
              <Position line={v.line} column={v.column} />
            </div>
            <p className="text-sm text-fg">{v.message}</p>
            {v.suggestion && (
              <p className="text-xs text-info flex items-center gap-1">
                <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {v.suggestion}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
