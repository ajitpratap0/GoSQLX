// JSON contract of the playground WASM bridge (wasm/internal/bridge/bridge.go).
// Keep these shapes in step with the Go response types' JSON tags.

export interface LintViolation {
  rule: string;
  rule_name: string;
  severity: string;
  message: string;
  /** 1-based; 0 when the rule could not attribute a position. */
  line: number;
  column: number;
  suggestion?: string;
}

export interface LintData {
  /** Set when the SQL does not parse in the selected dialect. */
  parse_error?: string;
  /** Set when the linter itself failed, or when the WASM call threw. */
  error?: string;
  violations?: LintViolation[];
}

export interface SecurityFinding {
  severity: string;
  pattern: string;
  description: string;
  risk?: string;
  line?: number;
  column?: number;
  sql?: string;
  suggestion?: string;
}

export interface SecurityReport {
  findings: SecurityFinding[];
  total_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface OptimizationSuggestion {
  rule_id: string;
  severity: string;
  message: string;
  detail?: string;
  line?: number;
  column?: number;
  original_sql?: string;
  suggested_sql?: string;
}

export interface OptimizationReport {
  score: number;
  complexity: string;
  suggestions: OptimizationSuggestion[];
}

export interface AnalysisData {
  /** Set when the SQL does not parse; no scores are computed then. */
  parse_error?: string;
  /** Set when the WASM call threw. */
  error?: string;
  security?: SecurityReport;
  optimization?: OptimizationReport;
}

/** Formats a 1-based position, or returns null when the position is unknown. */
export function formatPosition(line?: number, column?: number): string | null {
  if (!line || line < 1) return null;
  return column && column > 0 ? `${line}:${column}` : `line ${line}`;
}
