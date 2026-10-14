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
      <div className="h-[calc(100vh-64px)]">
        <PlaygroundLoader />
      </div>
    </>
  );
}
