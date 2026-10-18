'use client';
import { type AnalysisData, type OptimizationSuggestion, type SecurityFinding } from "./bridgeTypes";
import { ErrorNotice, Position, SeverityBadge } from "./ResultParts";

interface AnalyzeTabProps {
  data: AnalysisData | null;
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-ok";
  if (score >= 50) return "text-warn";
  return "text-danger";
}

function scoreBg(score: number): string {
  if (score >= 80) return "bg-ok/10 border-ok/30";
  if (score >= 50) return "bg-warn/10 border-warn/30";
  return "bg-danger/10 border-danger/30";
}

function scoreRing(score: number): string {
  if (score >= 80) return "ring-ok/30";
  if (score >= 50) return "ring-warn/30";
  return "ring-danger/30";
}

function ScoreCard({ title, score, subtitle, subtitleTitle }: { title: string; score: number | string; subtitle?: string; subtitleTitle?: string }) {
  const numScore = typeof score === "number" ? score : NaN;
  const displayScore = typeof score === "string" ? score : String(score);
  const isNumeric = !isNaN(numScore);

  return (
    <div className={`rounded-lg border p-4 text-center ${isNumeric ? scoreBg(numScore) : "bg-bg-overlay border-border"}`}>
      <div className="text-xs uppercase tracking-wider text-fg-muted mb-2">{title}</div>
      <div
        className={`text-3xl font-bold mb-1 ${isNumeric ? scoreColor(numScore) : "text-violet"} ${isNumeric ? `ring-2 ${scoreRing(numScore)}` : ""} rounded-full w-16 h-16 flex items-center justify-center mx-auto`}
      >
        {displayScore}
      </div>
      {subtitle && <div className="text-xs text-fg-muted mt-1" title={subtitleTitle}>{subtitle}</div>}
    </div>
  );
}

function SecurityFindingCard({ finding }: { finding: SecurityFinding }) {
  return (
    <li className="bg-bg-overlay border border-border rounded-lg p-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <SeverityBadge severity={finding.severity} />
        {finding.pattern && (
          <span className="text-xs font-mono text-violet bg-violet/10 px-1.5 py-0.5 rounded">{finding.pattern}</span>
        )}
        <Position line={finding.line} column={finding.column} />
      </div>
      <p className="text-sm text-fg">{finding.description}</p>
      {finding.risk && <p className="text-xs text-fg-muted">Risk: {finding.risk}</p>}
      {finding.suggestion && <p className="text-xs text-info">{finding.suggestion}</p>}
    </li>
  );
}

function SuggestionCard({ suggestion }: { suggestion: OptimizationSuggestion }) {
  return (
    <li className="bg-bg-overlay border border-border rounded-lg p-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <SeverityBadge severity={suggestion.severity} />
        <span className="text-xs font-mono text-violet bg-violet/10 px-1.5 py-0.5 rounded">{suggestion.rule_id}</span>
        <Position line={suggestion.line} column={suggestion.column} />
      </div>
      <p className="text-sm text-fg">{suggestion.message}</p>
      {suggestion.detail && <p className="text-xs text-fg-muted">{suggestion.detail}</p>}
      {suggestion.suggested_sql && (
        <div className="text-xs">
          <div className="text-fg-subtle mb-1">Suggested</div>
          <code className="block font-mono text-info bg-bg border border-border rounded px-2 py-1.5 whitespace-pre-wrap break-words">
            {suggestion.suggested_sql}
          </code>
        </div>
      )}
    </li>
  );
}

export default function AnalyzeTab({ data }: AnalyzeTabProps) {
  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-fg-muted text-sm">
        No data available. Enter a SQL query to analyze it.
      </div>
    );
  }

  if (data.parse_error) {
    return (
      <div className="p-4">
        <ErrorNotice title="Parse error" message={data.parse_error} polite>
          <p className="text-fg-muted text-xs mt-3">
            Analysis runs only on SQL that parses. Fix the error above to see security and optimization results.
          </p>
        </ErrorNotice>
      </div>
    );
  }

  if (data.error || !data.security || !data.optimization) {
    return (
      <div className="p-4">
        <ErrorNotice title="Analysis error" message={data.error || "The analyzer returned no result."} />
      </div>
    );
  }

  // Derive security score
  const security = data.security;
  const { critical_count: critical, high_count: high, medium_count: medium, low_count: low } = security;
  const securityScore = Math.max(0, 100 - (critical * 25 + high * 10 + medium * 5 + low * 1));
  const findings = security.findings ?? [];

  const optimization = data.optimization;
  const suggestions = optimization.suggestions ?? [];

  return (
    <div className="p-4 overflow-auto h-full space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <ScoreCard
          title="Security"
          score={securityScore}
          subtitle={`C:${critical} H:${high} M:${medium} L:${low}`}
          subtitleTitle="Critical / High / Medium / Low severity findings"
        />
        <ScoreCard
          title="Optimization"
          score={optimization.score}
          subtitle="Performance score"
        />
        <ScoreCard
          title="Complexity"
          score={optimization.complexity || "N/A"}
          subtitle="simple → moderate → complex"
        />
      </div>

      <section aria-labelledby="analyze-security-heading">
        <h3 id="analyze-security-heading" className="text-sm font-medium text-fg-muted mb-3">
          Security findings ({findings.length})
        </h3>
        {findings.length > 0 ? (
          <ul className="space-y-2">
            {findings.map((f, i) => (
              <SecurityFindingCard key={`${f.pattern}-${i}`} finding={f} />
            ))}
          </ul>
        ) : (
          <p className="text-sm text-fg-muted">No security issues detected.</p>
        )}
      </section>

      <section aria-labelledby="analyze-suggestions-heading">
        <h3 id="analyze-suggestions-heading" className="text-sm font-medium text-fg-muted mb-3">
          Optimization suggestions ({suggestions.length})
        </h3>
        {suggestions.length > 0 ? (
          <ul className="space-y-2">
            {suggestions.map((s, i) => (
              <SuggestionCard key={`${s.rule_id}-${i}`} suggestion={s} />
            ))}
          </ul>
        ) : (
          <p className="text-sm text-fg-muted">No optimization suggestions.</p>
        )}
      </section>
    </div>
  );
}
