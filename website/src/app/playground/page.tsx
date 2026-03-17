import type { Metadata } from 'next';
import PlaygroundLoader from './PlaygroundLoader';

export const metadata: Metadata = {
  title: 'SQL Playground',
  description: 'Interactive SQL playground - parse, format, lint, and analyze SQL in the browser',
};

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
