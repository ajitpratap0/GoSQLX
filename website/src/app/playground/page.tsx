import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import PlaygroundLoader from './PlaygroundLoader';
import { ServiceWorkerRegister } from '@/components/ServiceWorkerRegister';
import { JsonLd } from '@/components/JsonLd';
import { pageJsonLd } from '@/lib/jsonld';
import { PROJECT } from '@/data/metrics';

export const metadata: Metadata = pageMeta({
  title: 'SQL Playground',
  description:
    'Try GoSQLX in your browser: paste SQL to parse it into an AST, format, lint and analyze it across dialects, with no install and no server round trip.',
  path: '/playground/',
});

const jsonLd = pageJsonLd({
  name: 'GoSQLX SQL Playground',
  description: metadata.description as string,
  path: '/playground/',
  crumbs: [{ name: 'Playground', path: '/playground/' }],
  extra: [
    {
      '@context': 'https://schema.org',
      '@type': 'WebApplication',
      name: 'GoSQLX SQL Playground',
      url: 'https://gosqlx.dev/playground/',
      applicationCategory: 'DeveloperApplication',
      operatingSystem: 'Any (WebAssembly-capable browser)',
      browserRequirements: 'Requires JavaScript and WebAssembly',
      softwareVersion: PROJECT.version.replace(/^v/, ''),
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      isAccessibleForFree: true,
    },
  ],
});

export default function PlaygroundPage() {
  return (
    <>
      <JsonLd data={jsonLd} />
      {/* Preload WASM binary to start download before JS hydration */}
      <link
        rel="preload"
        href="/wasm/gosqlx.wasm"
        as="fetch"
        crossOrigin="anonymous"
      />
      <ServiceWorkerRegister />
      <div className="border-b border-border bg-bg-raised">
       <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-3">
        <h1 className="text-lg font-semibold text-fg">
          Online Go SQL Parser Playground
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-fg-muted">
          Parse, format, lint, and analyze SQL right in your browser with
          GoSQLX compiled to WebAssembly. Pick a dialect (PostgreSQL, MySQL,
          SQL Server, Oracle, SQLite, Snowflake, ClickHouse), paste a query, and
          inspect the tokens and AST. Nothing leaves your machine.
        </p>
        <noscript>
          <p className="mt-2 text-sm text-warn">
            The playground runs GoSQLX as WebAssembly and needs JavaScript
            enabled. Without it, see the documentation at /docs/ for usage
            examples.
          </p>
        </noscript>
       </div>
      </div>
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 h-[calc(100vh-64px-96px)] min-h-[480px]">
        <PlaygroundLoader />
      </div>
    </>
  );
}
