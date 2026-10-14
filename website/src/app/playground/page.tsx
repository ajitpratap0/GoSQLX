import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import PlaygroundLoader from './PlaygroundLoader';

export const metadata: Metadata = pageMeta({
  title: 'SQL Playground',
  description:
    'Try GoSQLX in your browser: paste SQL to parse it into an AST, format, lint and analyze it across dialects, with no install and no server round trip.',
  path: '/playground/',
});

export default function PlaygroundPage() {
  return (
    <>
      {/* Preload WASM binary to start download before JS hydration */}
      <link
        rel="preload"
        href="/wasm/gosqlx.wasm"
        as="fetch"
        crossOrigin="anonymous"
      />
      <div className="border-b border-slate-800 bg-slate-900/50 px-4 py-3">
        <h1 className="text-lg font-semibold text-slate-100">
          Online Go SQL Parser Playground
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">
          Parse, format, lint, and analyze SQL right in your browser with
          GoSQLX compiled to WebAssembly. Pick a dialect (PostgreSQL, MySQL,
          SQL Server, Oracle, SQLite, Snowflake, ClickHouse), paste a query, and
          inspect the tokens and AST. Nothing leaves your machine.
        </p>
        <noscript>
          <p className="mt-2 text-sm text-amber-400">
            The playground runs GoSQLX as WebAssembly and needs JavaScript
            enabled. Without it, see the documentation at /docs/ for usage
            examples.
          </p>
        </noscript>
      </div>
      <div className="h-[calc(100vh-64px-96px)] min-h-[480px]">
        <PlaygroundLoader />
      </div>
    </>
  );
}
