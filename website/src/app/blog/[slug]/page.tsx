import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { pageMeta } from '@/lib/seo';
import {
  articleHref,
  articleMarkdownPath,
  articleOgPath,
  articleUrl,
  getAllArticles,
  getArticleBySlug,
  getArticleSlugs,
} from '@/lib/articles';
import { SITE_URL } from '@/lib/site';
import { JsonLd } from '@/components/JsonLd';
import { renderMarkdown } from '@/lib/markdown';
import { formatArticleDate } from '../format-date';

interface Props {
  params: Promise<{ slug: string }>;
}

export const dynamicParams = false;

export function generateStaticParams() {
  return getArticleSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const article = getArticleBySlug(slug);
  if (!article) return {};

  const meta = pageMeta({
    title: article.metaTitle ?? article.title,
    description: article.description,
    path: articleHref(slug),
    type: 'article',
    openGraph: {
      publishedTime: `${article.date}T00:00:00Z`,
      modifiedTime: `${article.updated}T00:00:00Z`,
      tags: article.tags,
    },
    image: { url: articleOgPath(slug), alt: article.title },
  });
  return {
    ...meta,
    alternates: {
      ...meta.alternates,
      types: {
        ...meta.alternates?.types,
        'text/markdown': articleMarkdownPath(slug),
        'application/rss+xml': '/blog/rss.xml',
      },
    },
  };
}

export default async function ArticlePage({ params }: Props) {
  const { slug } = await params;
  const article = getArticleBySlug(slug);
  if (!article) notFound();

  const content = await renderMarkdown(article.content);

  const url = articleUrl(slug);
  const others = getAllArticles().filter((a) => a.slug !== slug).slice(0, 3);

  const articleJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: article.title,
    description: article.description,
    datePublished: `${article.date}T00:00:00Z`,
    dateModified: `${article.updated}T00:00:00Z`,
    url,
    inLanguage: 'en',
    keywords: article.tags.join(', '),
    author: { '@type': 'Organization', name: 'GoSQLX', url: SITE_URL },
    publisher: {
      '@type': 'Organization',
      name: 'GoSQLX',
      url: SITE_URL,
      logo: { '@type': 'ImageObject', url: `${SITE_URL}/images/logo.webp` },
    },
    image: { '@type': 'ImageObject', url: `${SITE_URL}${articleOgPath(slug)}`, width: 1200, height: 630 },
    mainEntityOfPage: { '@type': 'WebPage', '@id': url },
  };

  const breadcrumbJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Home', item: `${SITE_URL}/` },
      { '@type': 'ListItem', position: 2, name: 'Blog', item: `${SITE_URL}/blog/` },
      { '@type': 'ListItem', position: 3, name: article.title, item: url },
    ],
  };

  const shareText = encodeURIComponent(`${article.title} (GoSQLX)`);
  const shareUrl = encodeURIComponent(url);
  const shareLinks = [
    { label: 'X / Twitter', href: `https://x.com/intent/tweet?text=${shareText}&url=${shareUrl}` },
    { label: 'LinkedIn', href: `https://www.linkedin.com/sharing/share-offsite/?url=${shareUrl}` },
    { label: 'Hacker News', href: `https://news.ycombinator.com/submitlink?u=${shareUrl}&t=${shareText}` },
  ];

  return (
    <>
      <JsonLd data={[articleJsonLd, breadcrumbJsonLd]} />
      <div className="min-h-screen py-20 px-4">
        <article className="max-w-3xl mx-auto">
          <nav aria-label="Breadcrumb" className="mb-8 text-sm text-fg-muted">
            <Link href="/blog/" className="inline-flex min-h-11 items-center gap-1.5 hover:text-fg transition-colors">
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M10 4l-4 4 4 4" />
              </svg>
              All articles
            </Link>
          </nav>

          <header className="mb-10">
            <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">{article.title}</h1>
            <p className="mt-4 text-lg text-fg-muted">{article.description}</p>
            <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg-subtle">
              <time dateTime={article.date}>{formatArticleDate(article.date)}</time>
              {article.updated !== article.date && (
                <>
                  <span aria-hidden="true">&middot;</span>
                  <span>
                    Updated <time dateTime={article.updated}>{formatArticleDate(article.updated)}</time>
                  </span>
                </>
              )}
              <span aria-hidden="true">&middot;</span>
              <span>{article.readingMinutes} min read</span>
            </div>
          </header>

          <div className="prose prose-invert prose-dark max-w-none prose-headings:font-semibold prose-a:text-accent prose-a:underline prose-a:decoration-accent/50 prose-a:underline-offset-2 prose-a:hover:decoration-accent prose-hr:border-border">
            {content}
          </div>

          <div className="mt-12 pt-8 border-t border-border flex flex-wrap items-center gap-3">
            <span className="text-sm text-fg-subtle">Share:</span>
            {shareLinks.map((s) => (
              <a
                key={s.label}
                href={s.href}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex min-h-11 items-center text-xs text-fg-muted hover:text-fg border border-border-strong rounded px-2.5 py-1.5 transition-colors"
              >
                {s.label}
              </a>
            ))}
          </div>

          {others.length > 0 && (
            <nav aria-label="More articles" className="mt-12 pt-8 border-t border-border">
              <h2 className="text-sm font-medium text-fg-subtle mb-4">More from the blog</h2>
              <ul className="space-y-3">
                {others.map((a) => (
                  <li key={a.slug}>
                    <Link href={articleHref(a.slug)} className="text-fg-muted hover:text-fg transition-colors">
                      {a.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </nav>
          )}
        </article>
      </div>
    </>
  );
}
