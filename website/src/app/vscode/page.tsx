import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { VscodeContent } from './VscodeContent';
import { JsonLd } from '@/components/JsonLd';
import { pageJsonLd } from '@/lib/jsonld';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX VS Code Extension: SQL Linting & Formatting',
  description:
    'Real-time SQL validation, formatting and linting for VS Code. GoSQLX powers instant diagnostics, auto-formatting and 30 built-in lint rules across dialects.',
  path: '/vscode/',
  absolute: true,
});

const jsonLd = pageJsonLd({
  name: 'GoSQLX VS Code Extension',
  description: metadata.description as string,
  path: '/vscode/',
  crumbs: [{ name: 'VS Code Extension', path: '/vscode/' }],
  extra: [
    {
      '@context': 'https://schema.org',
      '@type': 'SoftwareApplication',
      name: 'GoSQLX for VS Code',
      url: 'https://gosqlx.dev/vscode/',
      downloadUrl: 'https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx',
      applicationCategory: 'DeveloperApplication',
      operatingSystem: 'Windows, macOS, Linux',
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      isAccessibleForFree: true,
    },
  ],
});

export default function VscodePage() {
  return (
    <>
      <JsonLd data={jsonLd} />
      <VscodeContent />
    </>
  );
}
