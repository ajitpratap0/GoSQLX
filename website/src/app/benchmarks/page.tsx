import type { Metadata } from 'next';
import { BenchmarksContent } from './BenchmarksContent';

export const metadata: Metadata = {
  title: { absolute: 'GoSQLX Performance Benchmarks — Reproducible SQL Parser Numbers for Go' },
  description:
    'Detailed performance benchmarks for GoSQLX: parse-stage ns/op and ops/sec for common query shapes, with hardware, Go version and the command to reproduce them. Zero race conditions across 20K+ concurrent operations.',
  alternates: {
    canonical: '/benchmarks/',
  },
  openGraph: {
    title: 'GoSQLX Performance Benchmarks — Reproducible SQL Parser Numbers for Go',
    description: 'Detailed performance benchmarks for GoSQLX: parse-stage ns/op and ops/sec for common query shapes, with hardware, Go version and the command to reproduce them.',
    url: '/benchmarks/',
  },
};

export default function BenchmarksPage() {
  return <BenchmarksContent />;
}
