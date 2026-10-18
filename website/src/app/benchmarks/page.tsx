import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { BenchmarksContent } from './BenchmarksContent';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX Performance Benchmarks: Reproducible SQL Parser Numbers for Go',
  description:
    'GoSQLX performance benchmarks: parse-stage ns/op for common query shapes and a reproducible end-to-end comparison with pg_query_go, Vitess, TiDB and xwb1989, with hardware, Go version and commands.',
  path: '/benchmarks/',
  absolute: true,
});

export default function BenchmarksPage() {
  return <BenchmarksContent />;
}
