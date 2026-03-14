import { useState } from "react";

interface AstNodeProps {
  data: unknown;
  depth?: number;
  label?: string;
}

function TypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    Select: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    Insert: "bg-green-500/20 text-green-400 border-green-500/30",
    Update: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    Delete: "bg-red-500/20 text-red-400 border-red-500/30",
    Create: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    From: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    Where: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    Join: "bg-pink-500/20 text-pink-400 border-pink-500/30",
  };

  const match = Object.keys(colors).find((k) => type.includes(k));
  const colorClass = match
    ? colors[match]
    : "bg-slate-500/20 text-slate-400 border-slate-500/30";

  return (
    <span
      className={`inline-block px-1.5 py-0.5 text-xs font-mono rounded border ${colorClass}`}
    >
      {type}
    </span>
  );
}

function AstNode({ data, depth = 0, label }: AstNodeProps) {
  const [collapsed, setCollapsed] = useState(depth > 3);

  if (data === null || data === undefined) {
    return (
      <span className="text-slate-500 italic text-sm">
        {label && <span className="text-slate-400 mr-1">{label}:</span>}
        null
      </span>
    );
  }

  if (typeof data === "string" || typeof data === "number" || typeof data === "boolean") {
    return (
      <span className="text-sm">
        {label && <span className="text-slate-400 mr-1">{label}:</span>}
        <span className="text-green-400 font-mono">
          {typeof data === "string" ? `"${data}"` : String(data)}
        </span>
      </span>
    );
  }

  if (Array.isArray(data)) {
    if (data.length === 0) {
      return (
        <span className="text-sm">
          {label && <span className="text-slate-400 mr-1">{label}:</span>}
          <span className="text-slate-500">[]</span>
        </span>
      );
    }

    return (
      <div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center gap-1 hover:bg-slate-700/50 rounded px-1 -ml-1 text-sm"
        >
          <span className="text-slate-500 w-4 text-center">
            {collapsed ? "+" : "-"}
          </span>
          {label && <span className="text-slate-400">{label}:</span>}
          <span className="text-slate-500">[{data.length}]</span>
        </button>
        {!collapsed && (
          <div className="ml-4 border-l border-slate-700 pl-3 mt-0.5 space-y-1">
            {data.map((item, i) => (
              <AstNode key={i} data={item} depth={depth + 1} label={String(i)} />
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

    if (keys.length === 0) {
      return (
        <span className="text-sm">
          {label && <span className="text-slate-400 mr-1">{label}:</span>}
          <span className="text-slate-500">{"{}"}</span>
        </span>
      );
    }

    return (
      <div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center gap-1.5 hover:bg-slate-700/50 rounded px-1 -ml-1 text-sm"
        >
          <span className="text-slate-500 w-4 text-center">
            {collapsed ? "+" : "-"}
          </span>
          {label && <span className="text-slate-400">{label}:</span>}
          {nodeType && <TypeBadge type={nodeType} />}
          {collapsed && (
            <span className="text-slate-600">{`{${keys.length} keys}`}</span>
          )}
        </button>
        {!collapsed && (
          <div className="ml-4 border-l border-slate-700 pl-3 mt-0.5 space-y-1">
            {keys.map((key) => (
              <AstNode key={key} data={obj[key]} depth={depth + 1} label={key} />
            ))}
          </div>
        )}
      </div>
    );
  }

  return null;
}

interface AstTabProps {
  data: any;
}

export default function AstTab({ data }: AstTabProps) {
  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500 text-sm">
        No data available. Enter a SQL query to see the AST.
      </div>
    );
  }

  if (data.error) {
    return (
      <div className="p-4">
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400 font-medium mb-1">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Parse Error
          </div>
          <p className="text-red-300 text-sm font-mono">{data.error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 overflow-auto h-full">
      <AstNode data={data} />
    </div>
  );
}
