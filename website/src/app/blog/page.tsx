import type { Metadata } from 'next';
import Link from 'next/link';
import { pageMeta } from '@/lib/seo';
import { articleHref, getAllArticles } from '@/lib/articles';
import { SITE_URL } from '@/lib/site';
import { JsonLd } from '@/components/JsonLd';
import { formatArticleDate } from './format-date';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX Blog: Go SQL Parsing, Linting & Benchmarks',
  description:
    'GoSQLX engineering blog: how the zero-copy SQL tokenizer and pooled parser work, benchmark methodology, and guides to linting and securing SQL in Go.',
  path: '/blog/',
  absolute: true,
});

export default function BlogIndexPage() {
  const articles = getAllArticles();

  const listJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Blog',
    name: 'GoSQLX Blog',
    url: `${SITE_URL}/blog/`,
    blogPost: articles.map((a) => ({
      '@type': 'BlogPosting',
      headline: a.title,
      url: `${SITE_URL}${articleHref(a.slug)}`,
      datePublished: `${a.date}T00:00:00Z`,
    })),
  };

  return (
    <>
      <JsonLd data={listJsonLd} />
      <div className="min-h-screen py-20 px-4">
        <div className="max-w-3xl mx-auto">
          <h1 className="text-4xl font-bold tracking-tight mb-3">Blog</h1>
          <p className="text-fg-muted text-lg mb-4">
            Deep dives into how GoSQLX parses SQL, how we measure it, and how to put it to work.
          </p>
          <p className="text-sm text-fg-subtle mb-12">
            Looking for release notes? See the{' '}
            <Link href="/changelog/" className="text-accent underline decoration-accent/50 underline-offset-2 hover:decoration-accent">
              changelog
            </Link>
            . Subscribe with{' '}
            <a href="/blog/rss.xml" className="text-accent underline decoration-accent/50 underline-offset-2 hover:decoration-accent">
              RSS
            </a>
            .
          </p>

          <ul className="space-y-4">
            {articles.map((a) => (
              <li key={a.slug}>
                <Link
                  href={articleHref(a.slug)}
                  className="group block rounded-xl border border-border bg-bg-raised/40 p-6 transition-colors hover:border-accent/40"
                >
                  <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg-subtle">
                    <time dateTime={a.date}>{formatArticleDate(a.date)}</time>
                    <span aria-hidden="true">&middot;</span>
                    <span>{a.readingMinutes} min read</span>
                  </div>
                  <h2 className="text-xl font-semibold text-fg group-hover:text-accent transition-colors">
                    {a.title}
                  </h2>
                  <p className="mt-2 text-fg-muted">{a.description}</p>
                  {a.tags.length > 0 && (
                    <ul className="mt-4 flex flex-wrap gap-2" aria-label="Tags">
                      {a.tags.map((tag) => (
                        <li
                          key={tag}
                          className="rounded-full border border-border px-2.5 py-0.5 text-xs text-fg-muted"
                        >
                          {tag}
                        </li>
                      ))}
                    </ul>
                  )}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </>
  );
}
