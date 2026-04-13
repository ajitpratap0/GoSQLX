import type { Metadata } from 'next';
import { CompareContent } from './CompareContent';

export const metadata: Metadata = {
  title: { absolute: 'GoSQLX vs pg_query vs vitess-sqlparser — Go SQL Parser Comparison' },
  description:
    'Compare GoSQLX against pg_query_go, vitess-sqlparser, and xwb1989/sqlparser. Feature matrix, performance benchmarks, dialect support, and more for Go SQL parsing libraries.',
  alternates: {
    canonical: '/compare/',
  },
  openGraph: {
    title: 'GoSQLX vs pg_query vs vitess-sqlparser — Go SQL Parser Comparison',
    description:
      'Compare GoSQLX against pg_query_go, vitess-sqlparser, and xwb1989/sqlparser. Feature matrix, performance benchmarks, and dialect support.',
    url: '/compare/',
  },
};

// Structured data is static and hardcoded (no user input), safe for JSON serialization.
const structuredData = JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'GoSQLX',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Any',
  url: 'https://gosqlx.dev/compare/',
  programmingLanguage: 'Go',
  description:
    'High-performance, zero-copy SQL parsing SDK for Go with 8-dialect support, 1.38M+ ops/sec.',
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
});

export default function ComparePage() {
  return (
    <>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: structuredData }}
      />
      <CompareContent />
    </>
  );
}
