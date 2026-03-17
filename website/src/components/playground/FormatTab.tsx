'use client';
import SqlEditor from "./SqlEditor";

interface FormatTabProps {
  data: string | { result?: string; formatted?: string; error?: string } | null;
}

export default function FormatTab({ data }: FormatTabProps) {
  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400 text-sm">
        No data available. Enter a SQL query to see formatted output.
      </div>
    );
  }

  if (typeof data !== "string" && data.error) {
    return (
      <div className="p-4">
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400 font-medium mb-1">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Format Error
          </div>
          <p className="text-red-300 text-sm font-mono">{data.error}</p>
        </div>
      </div>
    );
  }

  const formatted = typeof data === "string" ? data : data.result || data.formatted || JSON.stringify(data, null, 2);

  return (
    <div className="p-2 h-full overflow-hidden">
      <SqlEditor
        value={formatted}
        onChange={() => {}}
        readOnly={true}
        minHeight="200px"
        placeholder="Formatted SQL will appear here..."
      />
    </div>
  );
}
