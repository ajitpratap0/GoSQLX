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
import { baseOpenGraph } from '@/lib/open-graph';

export const metadata: Metadata = {
  alternates: { canonical: '/' },
  openGraph: { ...baseOpenGraph, url: '/' },
};

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
