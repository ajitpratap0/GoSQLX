import type { Metadata } from 'next';
import { BenchmarksContent } from './BenchmarksContent';

export const metadata: Metadata = {
  title: 'Benchmarks',
  description:
    'GoSQLX performance benchmarks. 1.38M+ ops/sec sustained, 8M+ tokens/sec throughput, validated across 20K+ concurrent operations.',
};

export default function BenchmarksPage() {
  return <BenchmarksContent />;
}
