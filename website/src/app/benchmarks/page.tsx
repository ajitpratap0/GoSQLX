import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { JsonLd } from '@/components/JsonLd';
import { pageJsonLd } from '@/lib/jsonld';
import { BenchmarksContent } from './BenchmarksContent';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX Benchmarks: Reproducible Go SQL Parser Numbers',
  description:
    'GoSQLX benchmarks: parse-stage ns/op per query shape and a reproducible end-to-end comparison with pg_query_go, Vitess, TiDB and xwb1989, with commands.',
  path: '/benchmarks/',
  absolute: true,
});

const jsonLd = pageJsonLd({
  name: 'GoSQLX Benchmarks',
  description: metadata.description as string,
  path: '/benchmarks/',
  crumbs: [{ name: 'Benchmarks', path: '/benchmarks/' }],
});

export default function BenchmarksPage() {
  return (
    <>
      <JsonLd data={jsonLd} />
      <BenchmarksContent />
    </>
  );
}
