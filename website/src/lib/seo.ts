import type { Metadata } from 'next';
import { baseOpenGraph } from '@/lib/open-graph';

const BRAND = 'GoSQLX';
const OG_IMAGE = '/images/og-image.png';

interface PageMetaInput {
  /** Page title without the brand. The layout template appends " | GoSQLX". */
  title: string;
  description: string;
  /** Site-relative path, e.g. "/compare/". Resolved against metadataBase. */
  path: string;
  type?: 'website' | 'article';
  /** Use the title verbatim (no template), e.g. when it already carries the brand. */
  absolute?: boolean;
  /** Extra Open Graph fields, e.g. publishedTime for articles. */
  openGraph?: Record<string, unknown>;
}

/**
 * Build page metadata with canonical, complete Open Graph (siteName, type,
 * locale, url, images) and Twitter card tags. Next.js merges metadata
 * shallowly, so every page must supply the full openGraph/twitter objects.
 */
export function pageMeta({
  title,
  description,
  path,
  type = 'website',
  absolute = false,
  openGraph,
}: PageMetaInput): Metadata {
  const fullTitle = absolute || title.includes(BRAND) ? title : `${title} | ${BRAND}`;
  return {
    title: absolute ? { absolute: title } : title,
    description,
    alternates: { canonical: path },
    openGraph: {
      ...baseOpenGraph,
      ...openGraph,
      type,
      title: fullTitle,
      description,
      url: path,
    } as NonNullable<Metadata['openGraph']>,
    twitter: {
      card: 'summary_large_image',
      title: fullTitle,
      description,
      images: [OG_IMAGE],
    },
  };
}
