import type { Metadata } from 'next';
import { BenchmarksContent } from './BenchmarksContent';

export const metadata: Metadata = {
  title: { absolute: 'GoSQLX Performance Benchmarks — 1.38M+ ops/sec SQL Parsing for Go' },
  description:
    'Detailed performance benchmarks for GoSQLX: 1.38M+ ops/sec sustained throughput, 8M+ tokens/sec, zero race conditions across 20K+ concurrent operations. Compare against xwb1989/sqlparser, pg_query_go, and blastrain/sqlparser.',
  alternates: {
    canonical: '/benchmarks/',
  },
  openGraph: {
    title: 'GoSQLX Performance Benchmarks — 1.38M+ ops/sec SQL Parsing for Go',
    description: 'Detailed performance benchmarks for GoSQLX: 1.38M+ ops/sec sustained throughput, 8M+ tokens/sec, zero race conditions across 20K+ concurrent operations.',
    url: '/benchmarks/',
  },
};

export default function BenchmarksPage() {
  return <BenchmarksContent />;
}
