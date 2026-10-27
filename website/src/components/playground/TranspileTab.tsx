'use client';
import { SqlOutput, type SqlOutputData } from "./FormatTab";

export interface DialectOption {
  value: string;
  label: string;
}

interface TranspileTabProps {
  data: SqlOutputData;
  dialects: DialectOption[];
  /** Source dialect: the editor's dialect, so parse errors are marked in the editor too. */
  from: string;
  to: string;
  onFromChange: (value: string) => void;
  onToChange: (value: string) => void;
}

const SELECT_CLASS =
  "bg-bg-overlay text-fg text-sm rounded px-2 py-1 border border-border focus:outline-none focus:border-info appearance-none cursor-pointer";

/**
 * Rewrites the editor's SQL from one dialect to another with gosqlx.Transpile:
 * identifier quotes, string escapes and operators such as ^ are retargeted,
 * and SQL the target cannot express is reported as an error.
 */
export default function TranspileTab({ data, dialects, from, to, onFromChange, onToChange }: TranspileTabProps) {
  const toolbar = (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2 border-b border-border">
      <label htmlFor="transpile-from" className="flex items-center gap-2 text-sm text-fg-muted">
        From
        <select id="transpile-from" value={from} onChange={(e) => onFromChange(e.target.value)} className={SELECT_CLASS}>
          {dialects.map((d) => (
            <option key={d.value} value={d.value}>
              {d.label}
            </option>
          ))}
        </select>
      </label>
      <span className="text-fg-subtle" aria-hidden="true">→</span>
      <label htmlFor="transpile-to" className="flex items-center gap-2 text-sm text-fg-muted">
        To
        <select id="transpile-to" value={to} onChange={(e) => onToChange(e.target.value)} className={SELECT_CLASS}>
          {dialects.map((d) => (
            <option key={d.value} value={d.value}>
              {d.label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );

  return (
    <SqlOutput
      data={data}
      label="Transpiled SQL"
      errorTitle="Transpile Error"
      emptyText="No data available. Enter a SQL query to transpile it."
      toolbar={toolbar}
    />
  );
}
