import { getArticleBySlug, getArticleSlugs } from '@/lib/articles';
import { renderOgCard } from '@/lib/og-image';

// Served at a stable URL (no content hash) so Article JSON-LD can reference it.
export const dynamic = 'force-static';
export const dynamicParams = false;

export function generateStaticParams() {
  return getArticleSlugs().map((slug) => ({ slug }));
}

export async function GET(_request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const article = getArticleBySlug(slug);
  return renderOgCard({
    eyebrow: 'Blog',
    title: article?.title ?? 'GoSQLX Blog',
    subtitle: article ? `${article.readingMinutes} min read` : undefined,
  });
}
