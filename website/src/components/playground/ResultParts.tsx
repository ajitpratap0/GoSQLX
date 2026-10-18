// Small presentational pieces shared by the Lint and Analyze tabs.
import type { ReactNode } from "react";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-danger/20 text-danger border-danger/30",
  high: "bg-danger/20 text-danger border-danger/30",
  error: "bg-danger/20 text-danger border-danger/30",
  medium: "bg-warn/20 text-warn border-warn/30",
  warning: "bg-warn/20 text-warn border-warn/30",
  low: "bg-info/20 text-info border-info/30",
  info: "bg-info/20 text-info border-info/30",
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

/** A danger-styled notice for a parse failure or a failed WASM call. */
export function ErrorNotice({ title, message, children }: { title: string; message: string; children?: ReactNode }) {
  return (
    <div role="alert" className="bg-danger/10 border border-danger/30 rounded-lg p-4">
      <div className="flex items-center gap-2 text-danger font-medium mb-1">
        <AlertIcon />
        {title}
      </div>
      <p className="text-danger text-sm font-mono whitespace-pre-wrap break-words">{message.trim().replace(/\n{3,}/g, "\n\n")}</p>
      {children}
    </div>
  );
}
