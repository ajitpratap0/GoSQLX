import { renderOgCard } from '@/lib/og-image';
import { COMPETITOR_PAGES, getCompetitorPage } from '../competitors';

export const alt = 'GoSQLX alternative comparison';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export function generateStaticParams() {
  return COMPETITOR_PAGES.map((c) => ({ competitor: c.slug }));
}

export default async function Image({ params }: { params: Promise<{ competitor: string }> }) {
  const { competitor } = await params;
  const page = getCompetitorPage(competitor);
  return renderOgCard({
    eyebrow: 'Comparison',
    title: `${page?.short ?? 'Go SQL parsers'} alternative: GoSQLX`,
    subtitle: 'Honest trade-offs and reproducible numbers.',
  });
}
