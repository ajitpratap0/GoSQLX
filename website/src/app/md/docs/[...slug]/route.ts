import { notFound } from 'next/navigation';
import { buildDocMarkdown, MARKDOWN_HEADERS } from '@/lib/llms';
import { getDocBySlug, getDocSlugs } from '@/lib/docs';

// Served publicly as /docs/<slug>.md through a rewrite in next.config.ts.
export const dynamic = 'force-static';
export const dynamicParams = false;

interface RouteContext {
  params: Promise<{ slug: string[] }>;
}

export function generateStaticParams() {
  return getDocSlugs().map((slug) => ({ slug: slug.split('/') }));
}

export async function GET(_req: Request, { params }: RouteContext): Promise<Response> {
  const { slug } = await params;
  const doc = getDocBySlug(slug.join('/'));
  if (!doc) notFound();
  return new Response(buildDocMarkdown(doc), { headers: MARKDOWN_HEADERS });
}
