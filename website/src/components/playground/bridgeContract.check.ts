// Compile-time guard for the playground WASM bridge's JSON contract.
//
// bridgeContract.fixture.json is generated from the Go response types by
// TestContractFixture (wasm/internal/bridge/contract_test.go) with every field
// set. `npm run typecheck` fails here if a key exists on one side only, which
// is the field-name drift that broke the Analyze and Lint tabs before.
// This module has no runtime use and is never imported by the app.
import fixture from "./bridgeContract.fixture.json";
import type {
  AnalysisData,
  ErrorSpan,
  HighlightData,
  HighlightSpan,
  LintData,
  LintViolation,
  OptimizationReport,
  OptimizationSuggestion,
  SecurityFinding,
  SecurityReport,
  TextData,
} from "./bridgeTypes";

type SameKeys<A, B> = [Exclude<keyof A, keyof B>, Exclude<keyof B, keyof A>] extends [never, never] ? true : false;

type GoLint = typeof fixture.lint;
type GoAnalyze = typeof fixture.analyze;
type GoHighlight = typeof fixture.highlight;
type GoFormat = typeof fixture.format;
type GoTranspile = typeof fixture.transpile;

// `error` on AnalysisData is set by wasm/main.go when the call throws, not by
// the bridge's AnalyzeResponse, so it is excluded from that comparison.
export const contractChecks: Record<string, true> = {
  lint: true satisfies SameKeys<GoLint, LintData>,
  lintErrorSpan: true satisfies SameKeys<GoLint["parse_error_span"], ErrorSpan>,
  analyzeErrorSpan: true satisfies SameKeys<GoAnalyze["parse_error_span"], ErrorSpan>,
  lintViolation: true satisfies SameKeys<GoLint["violations"][number], LintViolation>,
  analyze: true satisfies SameKeys<GoAnalyze, Omit<AnalysisData, "error">>,
  security: true satisfies SameKeys<GoAnalyze["security"], SecurityReport>,
  securityFinding: true satisfies SameKeys<GoAnalyze["security"]["findings"][number], SecurityFinding>,
  optimization: true satisfies SameKeys<GoAnalyze["optimization"], OptimizationReport>,
  optimizationSuggestion: true satisfies SameKeys<GoAnalyze["optimization"]["suggestions"][number], OptimizationSuggestion>,
  highlight: true satisfies SameKeys<GoHighlight, HighlightData>,
  highlightSpan: true satisfies SameKeys<GoHighlight["spans"][number], HighlightSpan>,
  format: true satisfies SameKeys<GoFormat, TextData>,
  transpile: true satisfies SameKeys<GoTranspile, TextData>,
};

// Values must also be assignable, not just share key names.
export const lintSample: LintData = fixture.lint;
export const analyzeSample: AnalysisData = fixture.analyze;
export const highlightSample: HighlightData = fixture.highlight;
export const formatSample: TextData = fixture.format;
export const transpileSample: TextData = fixture.transpile;
