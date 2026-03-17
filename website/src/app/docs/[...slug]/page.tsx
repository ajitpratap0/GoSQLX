import { notFound } from 'next/navigation';
import Link from 'next/link';
import type { Metadata } from 'next';
import { compileMDX } from 'next-mdx-remote/rsc';
import remarkGfm from 'remark-gfm';
import rehypeSlug from 'rehype-slug';
import { getDocBySlug, getDocSlugs, getAdjacentDocs, extractHeadings } from '@/lib/docs';
import { DOCS_SIDEBAR } from '@/lib/constants';
import { Sidebar } from '@/components/docs/Sidebar';
import { Toc } from '@/components/docs/Toc';
import { mdxComponents } from '@/components/docs/mdx-components';

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
  if (!doc) return { title: 'Not Found' };

  return {
    title: doc.title,
    description: `GoSQLX documentation - ${doc.title}`,
    alternates: {
      canonical: `https://gosqlx.dev/docs/${slugStr}/`,
    },
    openGraph: {
      url: `https://gosqlx.dev/docs/${slugStr}/`,
    },
  };
}

export default async function DocPage({ params }: PageProps) {
  const { slug } = await params;
  const slugStr = slug.join('/');
  const doc = getDocBySlug(slugStr);

  if (!doc) notFound();

  const headings = extractHeadings(doc.content);
  const { prev, next } = getAdjacentDocs(slugStr);

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
    ...(categoryItem
      ? [{ '@type': 'ListItem', position: 3, name: categoryItem.category, item: 'https://gosqlx.dev/docs/' }]
      : []),
    {
      '@type': 'ListItem',
      position: categoryItem ? 4 : 3,
      name: doc.title,
      item: `https://gosqlx.dev/docs/${slugStr}/`,
    },
  ];

  const breadcrumbJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: breadcrumbItems,
  };

  return (
    <>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbJsonLd) }}
      />
      <div className="mx-auto flex max-w-[90rem]">
      {/* Sidebar */}
      <div className="hidden lg:block w-64 shrink-0">
        <Sidebar />
      </div>
      {/* Mobile sidebar */}
      <div className="lg:hidden">
        <Sidebar />
      </div>

      {/* Main content */}
      <main className="min-w-0 flex-1 px-6 py-10 lg:px-12">
        {/* Breadcrumbs */}
        <nav className="mb-6 flex items-center gap-2 text-sm text-zinc-500">
          <Link href="/docs" className="hover:text-white transition-colors">
            Docs
          </Link>
          {categoryItem && (
            <>
              <span>/</span>
              <span>{categoryItem.category}</span>
            </>
          )}
          <span>/</span>
          <span className="text-zinc-300">{doc.title}</span>
        </nav>

        {/* Content */}
        <article className="prose prose-invert prose-dark max-w-none">
          {content}
        </article>

        {/* Prev / Next */}
        <div className="mt-16 flex items-center justify-between border-t border-white/5 pt-6">
          {prev ? (
            <Link
              href={`/docs/${prev.slug}`}
              className="group flex items-center gap-2 text-sm text-zinc-400 hover:text-white transition-colors"
            >
              <svg className="h-4 w-4 transition-transform group-hover:-translate-x-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
              </svg>
              {prev.title}
            </Link>
          ) : <span />}
          {next ? (
            <Link
              href={`/docs/${next.slug}`}
              className="group flex items-center gap-2 text-sm text-zinc-400 hover:text-white transition-colors"
            >
              {next.title}
              <svg className="h-4 w-4 transition-transform group-hover:translate-x-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </Link>
          ) : <span />}
        </div>
      </main>

      {/* Table of Contents */}
      <div className="hidden xl:block w-48 shrink-0 py-10 pr-6">
        <Toc headings={headings} />
      </div>
      </div>
    </>
  );
}
