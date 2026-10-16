import { notFound } from 'next/navigation';
import Link from 'next/link';
import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { compileMDX } from 'next-mdx-remote/rsc';
import remarkGfm from 'remark-gfm';
import rehypeSlug from 'rehype-slug';
import { getDocBySlug, getDocSlugs, getAdjacentDocs, extractHeadings, stripCodeFences } from '@/lib/docs';
import { DOCS_SIDEBAR } from '@/lib/constants';
import { docMarkdownPath } from '@/lib/llms';
import { PROJECT } from '@/data/metrics';
import { Sidebar } from '@/components/docs/Sidebar';
import { Toc } from '@/components/docs/Toc';
import { DocNavigation } from '@/components/docs/DocNavigation';
import { JsonLd } from '@/components/JsonLd';
import { mdxComponents } from '@/components/docs/mdx-components';

function getReadingTime(text: string): number {
  const words = stripCodeFences(text).trim().split(/\s+/).length;
  return Math.max(1, Math.ceil(words / 200));
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

interface PageProps {
  params: Promise<{ slug: string[] }>;
}

export async function generateStaticParams() {
  return getDocSlugs().map((slug) => ({
    slug: slug.split('/'),
  }));
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { slug } = await params;
  const slugStr = slug.join('/');
  const doc = getDocBySlug(slugStr);
  if (!doc) return { title: { absolute: 'Page not found | GoSQLX' } };

  const meta = pageMeta({
    title: `${doc.label} (Docs)`,
    description: doc.description,
    path: `/docs/${slugStr}/`,
    image: { url: `/og/docs/${slugStr}/`, alt: `${doc.label} (GoSQLX docs)` },
  });
  return {
    ...meta,
    alternates: { ...meta.alternates, types: { 'text/markdown': docMarkdownPath(slugStr) } },
  };
}

export default async function DocPage({ params }: PageProps) {
  const { slug } = await params;
  const slugStr = slug.join('/');
  const doc = getDocBySlug(slugStr);

  if (!doc) notFound();

  const headings = extractHeadings(doc.content);
  const { prev, next } = getAdjacentDocs(slugStr);
  const readingTime = getReadingTime(doc.content);

  const { content } = await compileMDX({
    source: doc.content,
    options: {
      mdxOptions: {
        remarkPlugins: [remarkGfm],
        rehypePlugins: [rehypeSlug],
        format: 'md',
      },
    },
    components: mdxComponents,
  });

  // Build breadcrumb
  const categoryItem = DOCS_SIDEBAR.find((g) =>
    g.items.some((i) => i.slug === slugStr)
  );

  const breadcrumbItems: Array<{ '@type': string; position: number; name: string; item: string }> = [
    { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://gosqlx.dev/' },
    { '@type': 'ListItem', position: 2, name: 'Documentation', item: 'https://gosqlx.dev/docs/' },
    {
      '@type': 'ListItem',
      position: 3,
      name: doc.title,
      item: `https://gosqlx.dev/docs/${slugStr}/`,
    },
  ];

  const breadcrumbJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: breadcrumbItems,
  };

  const articleJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: doc.title,
    description: `GoSQLX documentation: ${doc.label}.`,
    url: `https://gosqlx.dev/docs/${slugStr}/`,
    dateModified: doc.modifiedAt,
    inLanguage: 'en',
    author: { '@type': 'Organization', name: 'GoSQLX', url: 'https://gosqlx.dev' },
    publisher: { '@type': 'Organization', name: 'GoSQLX', url: 'https://gosqlx.dev' },
    mainEntityOfPage: { '@type': 'WebPage', '@id': `https://gosqlx.dev/docs/${slugStr}/` },
  };

  return (
    <>
      <JsonLd data={[breadcrumbJsonLd, articleJsonLd]} />
      <div className="mx-auto flex max-w-[90rem]">
      <div className="flex w-full flex-col lg:flex-row">
      <Sidebar />

      {/* Main content */}
      <div className="min-w-0 flex-1 px-6 py-10 lg:px-12">
        {/* Breadcrumbs */}
        <nav aria-label="Breadcrumb" className="mb-6 text-sm text-fg-muted">
          <ol className="flex min-w-0 items-center gap-2 whitespace-nowrap">
            <li className="shrink-0">
              <Link href="/docs" className="hover:text-fg transition-colors">
                Docs
              </Link>
            </li>
            {categoryItem && (
              <>
                <li aria-hidden="true" className="shrink-0">/</li>
                <li className="shrink-0">{categoryItem.category}</li>
              </>
            )}
            <li aria-hidden="true" className="shrink-0">/</li>
            <li className="min-w-0 truncate text-fg-muted" title={doc.label} aria-current="page">{doc.label}</li>
          </ol>
        </nav>

        {/* Meta: reading time, last updated, version, edit link */}
        <div className="mb-6 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-text-muted">
          <span className="flex items-center gap-2">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {readingTime} min read
          </span>
          <span>
            Last updated{' '}
            <time dateTime={doc.modifiedAt}>{formatDate(doc.modifiedAt)}</time>
          </span>
          <span className="rounded-full border border-fg/10 px-2 py-0.5 text-xs text-fg-muted">
            {PROJECT.version}
          </span>
          <a
            href={`https://github.com/ajitpratap0/GoSQLX/edit/main/${doc.file}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-fg-muted underline-offset-2 transition-colors hover:text-fg hover:underline"
          >
            Edit this page
          </a>
        </div>

        <Toc headings={headings} variant="collapsible" />

        {/* Content */}
        <article className="prose prose-invert prose-dark max-w-none prose-code:before:content-none prose-code:after:content-none">
          {content}
        </article>

        {/* Prev / Next */}
        <DocNavigation prev={prev} next={next} />
      </div>

      {/* Table of Contents */}
      <div className="hidden xl:block w-64 shrink-0 py-10 pr-6">
        <Toc headings={headings} />
      </div>
      </div>
      </div>
    </>
  );
}
