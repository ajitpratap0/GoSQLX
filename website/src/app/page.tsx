import { Hero } from '@/components/home/Hero';
import { TrustSection } from '@/components/home/TrustSection';
import { PerformanceSection } from '@/components/home/PerformanceSection';
import { FeatureGrid } from '@/components/home/FeatureGrid';
import { DialectShowcase } from '@/components/home/DialectShowcase';
import { CodeExamples } from '@/components/home/CodeExamples';
import { McpSection } from '@/components/home/McpSection';
import { VscodeSection } from '@/components/home/VscodeSection';
import { CtaBanner } from '@/components/home/CtaBanner';

export default function Home() {
  return (
    <>
      <Hero />
      <TrustSection />
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
