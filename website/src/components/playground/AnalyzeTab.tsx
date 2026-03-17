'use client';

interface SecurityAnalysis {
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  total_count?: number;
  findings?: unknown[];
}

interface OptimizationResult {
  Score?: number;
  QueryComplexity?: string;
  Suggestions?: unknown[];
}

interface Suggestion {
  message?: string;
  description?: string;
  text?: string;
}

export interface AnalysisData {
  error?: string;
  security?: SecurityAnalysis;
  optimization?: OptimizationResult | number;
}

interface AnalyzeTabProps {
  data: AnalysisData | null;
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 50) return "text-yellow-400";
  return "text-red-400";
}

function scoreBg(score: number): string {
  if (score >= 80) return "bg-green-500/10 border-green-500/30";
  if (score >= 50) return "bg-yellow-500/10 border-yellow-500/30";
  return "bg-red-500/10 border-red-500/30";
}

function scoreRing(score: number): string {
  if (score >= 80) return "ring-green-500/30";
  if (score >= 50) return "ring-yellow-500/30";
  return "ring-red-500/30";
}

function ScoreCard({ title, score, subtitle }: { title: string; score: number | string; subtitle?: string }) {
  const numScore = typeof score === "number" ? score : NaN;
  const displayScore = typeof score === "string" ? score : String(score);
  const isNumeric = !isNaN(numScore);

  return (
    <div className={`rounded-lg border p-4 text-center ${isNumeric ? scoreBg(numScore) : "bg-slate-800/50 border-slate-700"}`}>
      <div className="text-xs uppercase tracking-wider text-slate-400 mb-2">{title}</div>
      <div
        className={`text-3xl font-bold mb-1 ${isNumeric ? scoreColor(numScore) : "text-purple-400"} ${isNumeric ? `ring-2 ${scoreRing(numScore)}` : ""} rounded-full w-16 h-16 flex items-center justify-center mx-auto`}
      >
        {displayScore}
      </div>
      {subtitle && <div className="text-xs text-slate-400 mt-1">{subtitle}</div>}
    </div>
  );
}

export default function AnalyzeTab({ data }: AnalyzeTabProps) {
  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400 text-sm">
        No data available. Enter a SQL query to analyze it.
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
            Analysis Error
          </div>
          <p className="text-red-300 text-sm font-mono">{data.error}</p>
        </div>
      </div>
    );
  }

  // Derive security score
  const security = (data.security || {}) as SecurityAnalysis;
  const critical = security.critical_count || 0;
  const high = security.high_count || 0;
  const medium = security.medium_count || 0;
  const low = security.low_count || 0;
  const securityScore = Math.max(0, 100 - (critical * 25 + high * 10 + medium * 5 + low * 1));

  // Optimization score
  const optimization = data.optimization;
  const optimizationScore = typeof optimization === "number"
    ? optimization
    : typeof (optimization as OptimizationResult)?.Score === "number"
      ? (optimization as OptimizationResult).Score!
      : 100;

  // Complexity (nested inside optimization object)
  const complexityRaw = typeof optimization === "object" && optimization !== null
    ? (optimization as OptimizationResult).QueryComplexity
    : undefined;
  const complexityLevel = complexityRaw || "N/A";

  // Suggestions (nested inside optimization object)
  const rawSuggestions = typeof optimization === "object" && optimization !== null
    ? (optimization as OptimizationResult).Suggestions
    : undefined;
  const allSuggestions = Array.isArray(rawSuggestions) ? rawSuggestions : [];

  return (
    <div className="p-4 overflow-auto h-full space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <ScoreCard
          title="Security"
          score={securityScore}
          subtitle={`${critical}C ${high}H ${medium}M ${low}L`}
        />
        <ScoreCard
          title="Optimization"
          score={optimizationScore}
          subtitle="Performance score"
        />
        <ScoreCard
          title="Complexity"
          score={complexityLevel}
          subtitle="Query complexity"
        />
      </div>

      {allSuggestions.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-slate-300 mb-3">Suggestions</h3>
          <div className="space-y-2">
            {allSuggestions.map((s: unknown, i: number) => {
              const suggestion = s as string | Suggestion;
              const text = typeof suggestion === "string" ? suggestion : suggestion.message || suggestion.description || suggestion.text || JSON.stringify(suggestion);
              return (
                <div
                  key={i}
                  className="flex items-start gap-2 bg-slate-800/50 border border-slate-700 rounded-lg p-3"
                >
                  <svg className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                  <span className="text-sm text-slate-300">{text}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
