import { Hero } from '@/components/home/Hero';
import { StatsBar } from '@/components/home/StatsBar';
import { FeatureGrid } from '@/components/home/FeatureGrid';
import { CodeExamples } from '@/components/home/CodeExamples';
import { McpSection } from '@/components/home/McpSection';
import { VscodeSection } from '@/components/home/VscodeSection';
import { SocialProof } from '@/components/home/SocialProof';
import { CtaBanner } from '@/components/home/CtaBanner';

export default function Home() {
  return (
    <main>
      <Hero />
      <StatsBar />
      <FeatureGrid />
      <CodeExamples />
      <McpSection />
      <VscodeSection />
      <SocialProof />
      <CtaBanner />
    </main>
  );
}
