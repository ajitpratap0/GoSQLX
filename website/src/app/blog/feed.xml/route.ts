import { blogPostHref, getAllPosts } from '@/lib/blog';
import { SITE_URL } from '@/lib/llms';

export const dynamic = 'force-static';

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function rfc822(date: string): string | null {
  const d = new Date(`${date}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? null : d.toUTCString();
}

export function GET(): Response {
  const posts = getAllPosts();
  const latest = posts.map((p) => rfc822(p.date)).find((d) => d !== null);

  const items = posts
    .map((post) => {
      const url = `${SITE_URL}${blogPostHref(post.slug)}/`;
      const pub = rfc822(post.date);
      return [
        '    <item>',
        `      <title>${esc(post.title)}</title>`,
        `      <link>${esc(url)}</link>`,
        `      <guid isPermaLink="true">${esc(url)}</guid>`,
        pub ? `      <pubDate>${pub}</pubDate>` : null,
        `      <description>${esc(post.description)}</description>`,
        '    </item>',
      ]
        .filter((l): l is string => l !== null)
        .join('\n');
    })
    .join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>GoSQLX Changelog</title>
    <link>${SITE_URL}/blog/</link>
    <description>Release notes for GoSQLX, the high-performance SQL parsing SDK for Go.</description>
    <language>en</language>
${latest ? `    <lastBuildDate>${latest}</lastBuildDate>\n` : ''}    <atom:link href="${SITE_URL}/blog/feed.xml" rel="self" type="application/rss+xml" />
${items}
  </channel>
</rss>
`;
  return new Response(xml, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8' },
  });
}
