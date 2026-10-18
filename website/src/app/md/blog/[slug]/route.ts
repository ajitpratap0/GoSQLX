import { notFound } from 'next/navigation';
import { MARKDOWN_HEADERS } from '@/lib/llms';
import { buildArticleMarkdown, getArticleBySlug, getArticleSlugs } from '@/lib/articles';

// Served publicly as /blog/<slug>.md through a rewrite in next.config.ts. The
// front matter carries canonical_url, so pasting it into dev.to or Medium's
// importer keeps gosqlx.dev as the canonical source.
export const dynamic = 'force-static';
export const dynamicParams = false;

interface RouteContext {
  params: Promise<{ slug: string }>;
}

export function generateStaticParams() {
  return getArticleSlugs().map((slug) => ({ slug }));
}

export async function GET(_req: Request, { params }: RouteContext): Promise<Response> {
  const { slug } = await params;
  const article = getArticleBySlug(slug);
  if (!article) notFound();
  return new Response(buildArticleMarkdown(article), { headers: MARKDOWN_HEADERS });
}
