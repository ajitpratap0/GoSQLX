import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { CompareContent } from './CompareContent';
import { JsonLd } from '@/components/JsonLd';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX vs pg_query vs Vitess: Go SQL Parser Comparison',
  description:
    'Compare GoSQLX against pg_query_go, vitess-sqlparser, and xwb1989/sqlparser. Feature matrix, dialect support, and more for Go SQL parsing libraries.',
  path: '/compare/',
  absolute: true,
});

const LIBRARIES = [
  { name: 'GoSQLX', url: 'https://gosqlx.dev/' },
  { name: 'pg_query_go', url: 'https://github.com/pganalyze/pg_query_go' },
  { name: 'vitess-sqlparser', url: 'https://github.com/vitessio/vitess' },
  { name: 'sqlparser (xwb1989)', url: 'https://github.com/xwb1989/sqlparser' },
];

// Structured data is static and hardcoded (no user input), safe for JSON serialization.
const structuredData = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'WebPage',
      '@id': 'https://gosqlx.dev/compare/#webpage',
      url: 'https://gosqlx.dev/compare/',
      name: 'GoSQLX vs pg_query vs vitess-sqlparser: Go SQL Parser Comparison',
      isPartOf: { '@id': 'https://gosqlx.dev/#website' },
      mainEntity: { '@id': 'https://gosqlx.dev/compare/#libraries' },
    },
    {
      '@type': 'ItemList',
      '@id': 'https://gosqlx.dev/compare/#libraries',
      name: 'Go SQL parsing libraries compared',
      itemListElement: LIBRARIES.map((lib, i) => ({
        '@type': 'ListItem',
        position: i + 1,
        name: lib.name,
        url: lib.url,
      })),
    },
    {
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://gosqlx.dev/' },
        { '@type': 'ListItem', position: 2, name: 'Compare', item: 'https://gosqlx.dev/compare/' },
      ],
    },
  ],
};

export default function ComparePage() {
  return (
    <>
      <JsonLd data={structuredData} />
      <CompareContent />
    </>
  );
}
