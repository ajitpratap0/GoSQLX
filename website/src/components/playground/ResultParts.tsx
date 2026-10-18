// Small presentational pieces shared by the Lint and Analyze tabs.
import type { ReactNode } from "react";
import { formatPosition } from "./bridgeTypes";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-danger/10 text-danger border-danger/30",
  high: "bg-danger/10 text-danger border-danger/30",
  error: "bg-danger/10 text-danger border-danger/30",
  medium: "bg-warn/10 text-warn border-warn/30",
  warning: "bg-warn/10 text-warn border-warn/30",
  low: "bg-info/10 text-info border-info/30",
  info: "bg-info/10 text-info border-info/30",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const label = severity || "info";
  const cls = SEVERITY_STYLES[label.toLowerCase()] ?? SEVERITY_STYLES.info;
  return (
    <span className={`inline-block px-2 py-0.5 text-xs font-medium rounded border ${cls} uppercase`}>
      {label}
    </span>
  );
}

function AlertIcon() {
  return (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}

/** A 1-based "line:column" position, or nothing when the position is unknown. */
export function Position({ line, column }: { line?: number; column?: number }) {
  const pos = formatPosition(line, column);
  return pos ? <span className="text-xs text-fg-muted font-mono">{pos}</span> : null;
}

export interface ParsedError {
  summary: string;
  hint?: string;
  help?: string;
}

/**
 * Splits a GoSQLX error string of the form
 * "<summary> Hint: <hint> Help: <url>" into its parts. Missing parts are
 * omitted; unrecognised text is returned unchanged as the summary.
 */
export function parseErrorMessage(message: string): ParsedError {
  const text = message.trim().replace(/\n{3,}/g, "\n\n");
  const m = /^([\s\S]*?)(?:\s+Hint:\s*([\s\S]*?))?(?:\s+Help:\s*(\S+))?\s*$/.exec(text);
  if (!m) return { summary: text };
  const hint = m[2]?.trim();
  const help = m[3]?.trim();
  return {
    summary: m[1].trim() || text,
    hint: hint || undefined,
    help: help && /^https?:\/\//i.test(help) ? help : undefined,
  };
}

/**
 * A danger-styled notice for a parse failure or a failed WASM call.
 *
 * `polite` uses a polite status region instead of an assertive alert. Use it for
 * parse errors: the playground re-runs on every edit, so transient parse errors
 * while typing must not interrupt screen-reader users.
 */
export function ErrorNotice({
  title,
  message,
  polite = false,
  children,
}: {
  title: string;
  message: string;
  polite?: boolean;
  children?: ReactNode;
}) {
  const parsed = parseErrorMessage(message);
  return (
    <div
      role={polite ? "status" : "alert"}
      aria-live={polite ? "polite" : "assertive"}
      className="bg-danger/10 border border-danger/30 rounded-lg p-4"
    >
      <div className="flex items-center gap-2 text-danger font-medium mb-1">
        <AlertIcon />
        {title}
      </div>
      <p className="text-danger text-sm font-mono whitespace-pre-wrap break-words">{parsed.summary}</p>
      {parsed.hint && (
        <p className="mt-2 text-sm text-fg">
          <span className="font-medium text-fg-muted">Hint: </span>
          {parsed.hint}
        </p>
      )}
      {parsed.help && (
        <p className="mt-2 text-sm">
          <a
            href={parsed.help}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent underline underline-offset-2 hover:text-fg"
          >
            Error code help (opens in a new tab)
          </a>
        </p>
      )}
      {children}
    </div>
  );
}
