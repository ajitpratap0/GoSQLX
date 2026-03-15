import { MetadataRoute } from 'next';
import { DOCS_SIDEBAR } from '@/lib/constants';
import { getAllPosts } from '@/lib/blog';

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = 'https://gosqlx.dev';

  const staticPages = [
    '',
    '/playground',
    '/docs',
    '/blog',
    '/vscode',
    '/benchmarks',
    '/privacy',
  ].map((path) => ({
    url: `${baseUrl}${path}`,
    lastModified: new Date(),
  }));

  const docPages = DOCS_SIDEBAR.flatMap((category) =>
    category.items.map((item) => ({
      url: `${baseUrl}/docs/${item.slug}`,
      lastModified: new Date(),
    }))
  );

  const blogPages = getAllPosts().map((post) => ({
    url: `${baseUrl}/blog/${post.slug}`,
    lastModified: post.date ? new Date(post.date + 'T00:00:00') : new Date(),
  }));

  return [...staticPages, ...docPages, ...blogPages];
}
