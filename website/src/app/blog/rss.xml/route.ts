import { articleUrl, getAllArticles } from '@/lib/articles';
import { SITE_URL } from '@/lib/site';

// /blog/feed.xml permanently redirects to the changelog feed (its subscribers
// signed up for release notes), so articles get their own feed URL.
export const dynamic = 'force-static';

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function rfc822(date: string): string {
  return new Date(`${date}T00:00:00Z`).toUTCString();
}

export function GET(): Response {
  const articles = getAllArticles();
  const items = articles
    .map((a) => {
      const url = articleUrl(a.slug);
      return [
        '    <item>',
        `      <title>${esc(a.title)}</title>`,
        `      <link>${esc(url)}</link>`,
        `      <guid isPermaLink="true">${esc(url)}</guid>`,
        `      <pubDate>${rfc822(a.date)}</pubDate>`,
        ...a.tags.map((t) => `      <category>${esc(t)}</category>`),
        `      <description>${esc(a.description)}</description>`,
        '    </item>',
      ].join('\n');
    })
    .join('\n');

  const latest = articles[0] ? `    <lastBuildDate>${rfc822(articles[0].date)}</lastBuildDate>\n` : '';
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>GoSQLX Blog</title>
    <link>${SITE_URL}/blog/</link>
    <description>Articles on parsing, linting and securing SQL in Go with GoSQLX.</description>
    <language>en</language>
${latest}    <atom:link href="${SITE_URL}/blog/rss.xml" rel="self" type="application/rss+xml" />
${items}
  </channel>
</rss>
`;
  return new Response(xml, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8' },
  });
}
