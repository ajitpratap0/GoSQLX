import { useState, useEffect, useCallback, useRef } from "react";
import { useWasm } from "./WasmLoader";
import SqlEditor from "./SqlEditor";
import AstTab from "./playground/AstTab";
import FormatTab from "./playground/FormatTab";
import LintTab from "./playground/LintTab";
import AnalyzeTab from "./playground/AnalyzeTab";

const HERO_SQL = `SELECT u.name, COUNT(o.id) AS orders
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.active = true
GROUP BY u.name
ORDER BY orders DESC;`;

type TabId = "ast" | "format" | "lint" | "analyze";

const TABS: { id: TabId; label: string }[] = [
  { id: "ast", label: "AST" },
  { id: "format", label: "Format" },
  { id: "lint", label: "Lint" },
  { id: "analyze", label: "Analyze" },
];

interface Results {
  ast: any;
  format: any;
  lint: any;
  analyze: any;
}

export default function HeroPlayground() {
  const { loading, ready, error, api } = useWasm();
  const [sql, setSql] = useState(HERO_SQL);
  const [activeTab, setActiveTab] = useState<TabId>("ast");
  const [results, setResults] = useState<Results>({
    ast: null,
    format: null,
    lint: null,
    analyze: null,
  });
  const runIdRef = useRef(0);

  const runAll = useCallback(
    (query: string) => {
      if (!api || !query.trim()) {
        setResults({ ast: null, format: null, lint: null, analyze: null });
        return;
      }

      const runId = ++runIdRef.current;

      const safeCall = (fn: () => unknown) => {
        try {
          return fn();
        } catch (e: any) {
          return { error: e.message || String(e) };
        }
      };

      Promise.resolve().then(() => {
        if (runId !== runIdRef.current) return;

        const astResult = safeCall(() => api.parse(query, "generic"));
        const formatResult = safeCall(() => api.format(query, "generic"));
        const lintResult = safeCall(() => api.lint(query, "generic"));
        const analyzeResult = safeCall(() => api.analyze(query, "generic"));

        if (runId === runIdRef.current) {
          setResults({
            ast: astResult,
            format: formatResult,
            lint: lintResult,
            analyze: analyzeResult,
          });
        }
      });
    },
    [api]
  );

  useEffect(() => {
    if (ready && api) {
      runAll(sql);
    }
  }, [ready, api, sql, runAll]);

  const handleSqlChange = useCallback((value: string) => {
    setSql(value);
  }, []);

  return (
    <section className="relative overflow-hidden">
      {/* Grid background */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(148,163,184,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.08) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      {/* Radial glow effects */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[600px] pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse at center, rgba(59,130,246,0.08) 0%, rgba(249,115,22,0.04) 40%, transparent 70%)',
        }}
      />

      <div className="relative container mx-auto px-4 pt-20 pb-16">
        {/* Headlines */}
        <div className="text-center mb-10">
          <h1 className="text-5xl md:text-6xl font-extrabold mb-4 bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
            Parse SQL at the speed of Go
          </h1>
          <p className="text-lg text-slate-400">
            Try it now — paste SQL and see results in real time
          </p>
        </div>

        {/* Compact playground */}
        <div className="max-w-5xl mx-auto rounded-xl border border-slate-700 overflow-hidden bg-slate-900 shadow-2xl shadow-blue-500/10">
          {loading && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center space-y-3">
                <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-slate-400 text-sm">Loading SQL parser...</p>
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center justify-center h-64">
              <p className="text-red-400 text-sm">
                Failed to load parser: {error.message}
              </p>
            </div>
          )}

          {!loading && !error && (
            <div className="flex flex-col md:flex-row min-h-0">
              {/* Editor */}
              <div className="md:w-1/2 border-b md:border-b-0 md:border-r border-slate-700">
                <div className="px-3 py-1.5 border-b border-slate-700 bg-slate-800/30">
                  <span className="text-xs text-slate-500 uppercase tracking-wider font-medium">
                    SQL Input
                  </span>
                </div>
                <div className="p-2">
                  <SqlEditor
                    value={sql}
                    onChange={handleSqlChange}
                    placeholder="Enter SQL..."
                    minHeight="180px"
                  />
                </div>
              </div>

              {/* Output */}
              <div className="md:w-1/2 flex flex-col min-h-0">
                <div className="flex border-b border-slate-700 bg-slate-800/30">
                  {TABS.map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`px-3 py-1.5 text-xs font-medium transition-colors relative ${
                        activeTab === tab.id
                          ? "text-blue-400"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {tab.label}
                      {activeTab === tab.id && (
                        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
                      )}
                    </button>
                  ))}
                </div>
                <div className="overflow-auto" style={{ height: "210px" }}>
                  {activeTab === "ast" && <AstTab data={results.ast} />}
                  {activeTab === "format" && <FormatTab data={results.format} />}
                  {activeTab === "lint" && <LintTab data={results.lint} />}
                  {activeTab === "analyze" && (
                    <AnalyzeTab data={results.analyze} />
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Link to full playground */}
        <div className="text-center mt-6">
          <a
            href="/GoSQLX/playground/"
            className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors text-sm font-medium"
          >
            Open Full Playground
            <span aria-hidden="true">&rarr;</span>
          </a>
        </div>
      </div>
    </section>
  );
}
