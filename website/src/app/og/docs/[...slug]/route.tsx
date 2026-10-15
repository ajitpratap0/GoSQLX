import { getDocBySlug, getDocSlugs } from '@/lib/docs';
import { renderOgCard } from '@/lib/og-image';

// Next.js cannot place an opengraph-image file inside a catch-all segment, so
// per-doc images are served from this route and referenced by generateMetadata.
export const dynamicParams = false;

export function generateStaticParams() {
  return getDocSlugs().map((slug) => ({ slug: slug.split('/') }));
}

export async function GET(_request: Request, { params }: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await params;
  const doc = getDocBySlug(slug.join('/'));
  return renderOgCard({
    eyebrow: 'Documentation',
    title: doc?.label ?? 'GoSQLX Documentation',
    subtitle: 'GoSQLX docs',
  });
}
