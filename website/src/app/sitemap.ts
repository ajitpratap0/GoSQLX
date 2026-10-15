import fs from 'fs';
import path from 'path';
import { MetadataRoute } from 'next';
import { DOCS_SIDEBAR } from '@/lib/constants';
import { blogPostHref, getAllPosts } from '@/lib/blog';
import { COMPETITOR_PAGES } from '@/app/compare/competitors';

// Mirrors DOCS_DIR in lib/docs.ts (repo-level docs/ folder).
const DOCS_DIR = path.join(process.cwd(), '..', 'docs');

function fileMtime(file: string): Date | undefined {
  try {
    return fs.statSync(path.join(DOCS_DIR, file)).mtime;
  } catch {
    return undefined;
  }
}

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = 'https://gosqlx.dev';

  // Every URL ends in "/" because next.config.ts sets trailingSlash: true;
  // slash-less URLs would 308. Static pages have no reliable modified date, so omit it.
  const staticPages: MetadataRoute.Sitemap = [
    '/',
    '/playground/',
    '/docs/',
    '/blog/',
    '/vscode/',
    '/benchmarks/',
    '/compare/',
    '/privacy/',
  ]
    .concat(COMPETITOR_PAGES.map((c) => `/compare/${c.slug}/`))
    .map((p) => ({ url: `${baseUrl}${p}` }));

  const docPages: MetadataRoute.Sitemap = DOCS_SIDEBAR.flatMap((category) =>
    category.items.map((item) => ({
      url: `${baseUrl}/docs/${item.slug}/`,
      lastModified: fileMtime(item.file),
    }))
  );

  const blogPages: MetadataRoute.Sitemap = getAllPosts().map((post) => ({
    url: `${baseUrl}${blogPostHref(post.slug)}/`,
    lastModified: post.date ? new Date(post.date + 'T00:00:00') : undefined,
  }));

  return [...staticPages, ...docPages, ...blogPages];
}
