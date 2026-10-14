import { Hero } from '@/components/home/Hero';
import { TrustSection } from '@/components/home/TrustSection';
import { PerformanceSection } from '@/components/home/PerformanceSection';
import { FeatureGrid } from '@/components/home/FeatureGrid';
import { DialectShowcase } from '@/components/home/DialectShowcase';
import { CodeExamples } from '@/components/home/CodeExamples';
import { McpSection } from '@/components/home/McpSection';
import { VscodeSection } from '@/components/home/VscodeSection';
import { CtaBanner } from '@/components/home/CtaBanner';
import { getStars } from '@/lib/github';

import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX: Go SQL Parser, Formatter & Linter',
  description:
    'High-performance, zero-copy SQL parser, formatter and linter for Go. Thread-safe with 8-dialect support: PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, and ClickHouse.',
  path: '/',
  absolute: true,
});

export default async function Home() {
  const stars = await getStars();
  return (
    <>
      <Hero stars={stars} />
      <TrustSection stars={stars} />
      <PerformanceSection />
      <FeatureGrid />
      <DialectShowcase />
      <CodeExamples />
      <McpSection />
      <VscodeSection />
      <CtaBanner />
    </>
  );
}
