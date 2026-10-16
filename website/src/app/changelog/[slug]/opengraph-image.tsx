import { getPostBySlug, getPostSlugs } from '@/lib/blog';
import { renderOgCard } from '@/lib/og-image';

export const alt = 'GoSQLX release notes';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export function generateStaticParams() {
  return getPostSlugs().map((slug) => ({ slug }));
}

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  return renderOgCard({
    eyebrow: 'Release notes',
    title: post ? `GoSQLX ${post.title}` : 'GoSQLX release notes',
    subtitle: post?.date ? `Released ${post.date}` : undefined,
  });
}
