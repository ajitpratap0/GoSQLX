'use client';
import { useState, useCallback } from "react";

interface AstNodeProps {
  data: unknown;
  depth?: number;
  label?: string;
  showEmpty?: boolean;
}

function isEmptyValue(v: unknown): boolean {
  if (v === null || v === undefined || v === "") return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === "object") return Object.keys(v as object).length === 0;
  return false;
}

function TypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    Select: "bg-info/20 text-info border-info/30",
    Insert: "bg-ok/20 text-ok border-ok/30",
    Update: "bg-accent-warm/20 text-accent-warm border-accent-warm/30",
    Delete: "bg-danger/20 text-danger border-danger/30",
    Create: "bg-violet/20 text-violet border-violet/30",
    From: "bg-cyan/20 text-cyan border-cyan/30",
    Where: "bg-warn/20 text-warn border-warn/30",
    Join: "bg-pink-500/20 text-pink-400 border-pink-500/30",
  };

  const match = Object.keys(colors).find((k) => type.includes(k));
  const colorClass = match
    ? colors[match]
    : "bg-fg/10 text-fg-muted border-fg-subtle";

  return (
    <span
      className={`inline-block px-1.5 py-0.5 text-xs font-mono rounded border ${colorClass}`}
    >
      {type}
    </span>
  );
}

function AstNode({ data, depth = 0, label, showEmpty }: AstNodeProps) {
  const [collapsed, setCollapsed] = useState(depth > 3);

  if (data === null || data === undefined) {
    return (
      <div className="pl-5 text-fg-muted italic text-sm">
        {label && <span className="text-fg-muted mr-1">{label}:</span>}
        null
      </div>
    );
  }

  if (typeof data === "string" || typeof data === "number" || typeof data === "boolean") {
    return (
      <div className="pl-5 text-sm">
        {label && <span className="text-fg-muted mr-1">{label}:</span>}
        <span className="text-ok font-mono">
          {typeof data === "string" ? `"${data}"` : String(data)}
        </span>
      </div>
    );
  }

  if (Array.isArray(data)) {
    if (data.length === 0) {
      return (
        <div className="pl-5 text-sm">
          {label && <span className="text-fg-muted mr-1">{label}:</span>}
          <span className="text-fg-muted">[]</span>
        </div>
      );
    }

    return (
      <div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center gap-1 hover:bg-bg-overlay rounded px-1 -ml-1 text-sm min-h-[44px] py-2"
        >
          <span className="text-fg-muted w-4 text-center">
            {collapsed ? "+" : "-"}
          </span>
          {label && <span className="text-fg-muted">{label}:</span>}
          <span className="text-fg-muted">[{data.length}]</span>
        </button>
        {!collapsed && (
          <div className="ml-4 border-l border-border pl-3 mt-0.5 space-y-1">
            {data.map((item, i) => (
              <AstNode key={i} data={item} depth={depth + 1} label={String(i)} showEmpty={showEmpty} />
            ))}
          </div>
        )}
      </div>
    );
  }

  if (typeof data === "object") {
    const obj = data as Record<string, unknown>;
    const keys = Object.keys(obj);
    const nodeType =
      typeof obj.type === "string"
        ? obj.type
        : typeof obj.node_type === "string"
          ? obj.node_type
          : null;

    const visibleKeys = showEmpty ? keys : keys.filter((k) => !isEmptyValue(obj[k]));

    if (keys.length === 0) {
      return (
        <div className="pl-5 text-sm">
          {label && <span className="text-fg-muted mr-1">{label}:</span>}
          <span className="text-fg-muted">{"{}"}</span>
        </div>
      );
    }

    return (
      <div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center gap-1.5 hover:bg-bg-overlay rounded px-1 -ml-1 text-sm min-h-[44px] py-2"
        >
          <span className="text-fg-muted w-4 text-center">
            {collapsed ? "+" : "-"}
          </span>
          {label && <span className="text-fg-muted">{label}:</span>}
          {nodeType && <TypeBadge type={nodeType} />}
          {collapsed && (
            <span className="text-fg-muted">{`{${visibleKeys.length} keys}`}</span>
          )}
        </button>
        {!collapsed && (
          <div className="ml-4 border-l border-border pl-3 mt-0.5 space-y-1">
            {visibleKeys.map((key) => (
              <AstNode key={key} data={obj[key]} depth={depth + 1} label={key} showEmpty={showEmpty} />
            ))}
          </div>
        )}
      </div>
    );
  }

  return null;
}

interface AstTabProps {
  data: (Record<string, unknown> & { error?: string }) | null;
}

export default function AstTab({ data }: AstTabProps) {
  const [showEmpty, setShowEmpty] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const handleCopy = useCallback(() => {
    if (!data) return;
    navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      setCopyFailed(true);
      setTimeout(() => setCopyFailed(false), 2000);
    });
  }, [data]);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-fg-muted text-sm" aria-live="polite">
        No data available. Enter a SQL query to see the AST.
      </div>
    );
  }

  if (data.error) {
    return (
      <div className="p-4">
        <div className="bg-danger/10 border border-danger/30 rounded-lg p-4">
          <div className="flex items-center gap-2 text-danger font-medium mb-1">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Parse Error
          </div>
          <p className="text-danger text-sm font-mono">{data.error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-fg/[0.03]">
        <span className="text-xs text-fg-muted uppercase tracking-wider font-medium">AST</span>
        <label className="flex items-center gap-1.5 text-xs text-fg-muted cursor-pointer ml-auto mr-3">
          <input
            type="checkbox"
            checked={showEmpty}
            onChange={(e) => setShowEmpty(e.target.checked)}
          />
          Show empty fields
        </label>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 text-xs text-fg-muted hover:text-fg transition-colors px-2 py-1 rounded hover:bg-bg-overlay"
          aria-label="Copy AST JSON to clipboard"
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
      <div className="flex-1 overflow-auto p-4">
        <AstNode data={data} showEmpty={showEmpty} />
      </div>
    </div>
  );
}
