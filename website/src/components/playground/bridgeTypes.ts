// JSON contract of the playground WASM bridge (wasm/internal/bridge/bridge.go).
// Keep these shapes in step with the Go response types' JSON tags.

/**
 * Where a parse error sits in the submitted SQL. Lines and columns are 1-based;
 * columns count UTF-16 code units, like JavaScript string indices. The end is
 * exclusive and equals the start when the error sits between characters (for
 * example at the end of the input).
 */
export interface ErrorSpan {
  code?: string;
  message: string;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
}

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
  /** Locates parse_error when the parser reported a position. */
  parse_error_span?: ErrorSpan;
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
  /** Locates parse_error when the parser reported a position. */
  parse_error_span?: ErrorSpan;
  /** Set when the WASM call threw. */
  error?: string;
  security?: SecurityReport;
  optimization?: OptimizationReport;
}

/**
 * Syntactic class of a highlighted span (highlight.Category names in
 * pkg/highlight). New categories may be added; unknown ones render as plain.
 */
export type HighlightCategory =
  | "keyword"
  | "function"
  | "type"
  | "identifier"
  | "quoted-identifier"
  | "string"
  | "number"
  | "constant"
  | "operator"
  | "punctuation"
  | "comment"
  | "placeholder"
  | "error";

/**
 * One classified range of the SQL. Offsets are 0-based and end-exclusive,
 * counted in UTF-16 code units like JavaScript string indices and CodeMirror
 * document positions.
 */
export interface HighlightSpan {
  start: number;
  end: number;
  category: string;
}

export interface HighlightData {
  /** Sorted and non-overlapping; text between spans is plain. */
  spans: HighlightSpan[];
}

/**
 * Result of Format and Transpile (bridge.TextResponse). On success `result`
 * holds the SQL; on failure `error` says why. The loader turns a set `error`
 * into an exception, so the tabs receive `{ error }` from the playground's
 * safe call wrapper instead.
 */
export interface TextData {
  result?: string;
  error?: string;
}

/** Formats a 1-based position, or returns null when the position is unknown. */
export function formatPosition(line?: number, column?: number): string | null {
  if (!line || line < 1) return null;
  return column && column > 0 ? `${line}:${column}` : `line ${line}`;
}
