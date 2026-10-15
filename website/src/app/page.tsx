import { Hero } from '@/components/home/Hero';
import { ProofStrip } from '@/components/home/ProofStrip';
import { PerformanceSection } from '@/components/home/PerformanceSection';
import { FeatureGrid } from '@/components/home/FeatureGrid';
import { DialectShowcase } from '@/components/home/DialectShowcase';
import { CodeExamples } from '@/components/home/CodeExamples';
import { UseEverywhere } from '@/components/home/UseEverywhere';
import { CtaBanner } from '@/components/home/CtaBanner';
import { getStars } from '@/lib/github';
import { JsonLd } from '@/components/JsonLd';
import { PROJECT } from '@/data/metrics';

import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX: Go SQL Parser, Formatter & Linter',
  description:
    'High-performance, zero-copy SQL parser, formatter and linter for Go. Thread-safe with 8-dialect support: PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, and ClickHouse.',
  path: '/',
  absolute: true,
});

const SITE = 'https://gosqlx.dev';
const REPO = 'https://github.com/ajitpratap0/GoSQLX';

const homeJsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'WebSite',
      '@id': `${SITE}/#website`,
      url: `${SITE}/`,
      name: 'GoSQLX',
      description: 'High-performance, zero-copy SQL parser, formatter and linter for Go.',
      inLanguage: 'en',
    },
    {
      '@type': 'SoftwareApplication',
      '@id': `${SITE}/#software`,
      name: 'GoSQLX',
      applicationCategory: 'DeveloperApplication',
      operatingSystem: 'Any',
      url: `${SITE}/`,
      downloadUrl: `${REPO}/releases`,
      codeRepository: REPO,
      programmingLanguage: 'Go',
      softwareVersion: PROJECT.version.replace(/^v/, ''),
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      description: 'High-performance, zero-copy SQL parsing SDK for Go',
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      publisher: {
        '@type': 'Organization',
        name: 'GoSQLX',
        url: SITE,
        sameAs: [REPO],
      },
    },
    {
      '@type': 'SoftwareSourceCode',
      '@id': `${SITE}/#source`,
      name: 'GoSQLX',
      codeRepository: REPO,
      programmingLanguage: 'Go',
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      targetProduct: { '@id': `${SITE}/#software` },
    },
  ],
};

export default async function Home() {
  const stars = await getStars();
  return (
    <>
      <JsonLd data={homeJsonLd} />
      <Hero stars={stars} />
      <ProofStrip stars={stars} />
      <PerformanceSection />
      <FeatureGrid />
      <DialectShowcase />
      <CodeExamples />
      <UseEverywhere />
      <CtaBanner />
    </>
  );
}
