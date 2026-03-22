import { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { compileMDX } from 'next-mdx-remote/rsc';
import remarkGfm from 'remark-gfm';
import { getAllPosts, getPostBySlug, getPostSlugs } from '@/lib/blog';

interface Props {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return getPostSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) return {};

  return {
    title: post.title,
    description: `GoSQLX ${post.title} release notes.`,
    alternates: {
      canonical: `https://gosqlx.dev/blog/${slug}/`,
    },
    openGraph: {
      title: `GoSQLX ${post.title}`,
      description: `GoSQLX ${post.title} release notes.`,
      type: 'article',
      publishedTime: post.date ? `${post.date}T00:00:00Z` : undefined,
      url: `https://gosqlx.dev/blog/${slug}/`,
    },
  };
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) notFound();

  const { content } = await compileMDX({
    source: post.content,
    options: {
      mdxOptions: {
        format: 'md',
        remarkPlugins: [remarkGfm],
      },
    },
  });

  // Find prev/next posts for navigation
  const allPosts = getAllPosts();
  const currentIndex = allPosts.findIndex((p) => p.slug === slug);
  const prevPost = currentIndex < allPosts.length - 1 ? allPosts[currentIndex + 1] : null;
  const nextPost = currentIndex > 0 ? allPosts[currentIndex - 1] : null;

  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: post.title,
    description: `GoSQLX ${post.title} release notes.`,
    datePublished: post.date ? `${post.date}T00:00:00Z` : undefined,
    dateModified: post.date ? `${post.date}T00:00:00Z` : undefined,
    url: `https://gosqlx.dev/blog/${slug}/`,
    author: {
      '@type': 'Organization',
      name: 'GoSQLX',
      url: 'https://gosqlx.dev',
    },
    publisher: {
      '@type': 'Organization',
      name: 'GoSQLX',
      url: 'https://gosqlx.dev',
      logo: {
        '@type': 'ImageObject',
        url: 'https://gosqlx.dev/images/logo.webp',
      },
    },
    image: {
      '@type': 'ImageObject',
      url: 'https://gosqlx.dev/images/og-image.png',
      width: 1200,
      height: 630,
    },
    mainEntityOfPage: {
      '@type': 'WebPage',
      '@id': `https://gosqlx.dev/blog/${slug}/`,
    },
  };

  return (
    <>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <main className="min-h-screen py-20 px-4">
        <article className="max-w-3xl mx-auto">
        {/* Back link */}
        <Link
          href="/blog"
          className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 transition-colors mb-8"
        >
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10 4l-4 4 4 4" />
          </svg>
          Back to Release Notes
        </Link>

        {/* Header */}
        <header className="mb-10">
          <div className="flex items-center gap-3 mb-3">
            <span className="inline-block bg-accent-indigo/10 border border-accent-indigo/20 rounded-full px-3.5 py-1 text-xs font-medium text-accent-indigo">
              v{post.version}
            </span>
            {post.date && (
              <time className="text-sm text-zinc-500" dateTime={post.date}>
                {formatDate(post.date)}
              </time>
            )}
          </div>
          <h1 className="text-3xl font-bold tracking-tight">{post.title}</h1>
        </header>

        {/* Content */}
        <div className="prose prose-invert prose-dark max-w-none prose-headings:font-semibold prose-a:text-accent-indigo prose-a:no-underline hover:prose-a:underline prose-code:bg-surface prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-sm prose-code:before:content-none prose-code:after:content-none prose-pre:bg-surface prose-pre:border prose-pre:border-zinc-800 prose-hr:border-zinc-800">
          {content}
        </div>

        {/* Social share */}
        {(() => {
          const postUrl = `https://gosqlx.dev/blog/${slug}/`;
          const shareText = encodeURIComponent(`${post.title} — GoSQLX`);
          const shareUrl = encodeURIComponent(postUrl);
          return (
            <div className="mt-12 pt-8 border-t border-zinc-800 flex items-center gap-3">
              <span className="text-sm text-zinc-500">Share:</span>
              <a
                href={`https://x.com/intent/tweet?text=${shareText}&url=${shareUrl}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white border border-zinc-800 hover:border-zinc-600 rounded px-2.5 py-1.5 transition-colors"
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-label="X (Twitter)"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.748l7.73-8.835L1.254 2.25H8.08l4.253 5.622zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
                X / Twitter
              </a>
              <a
                href={`https://www.linkedin.com/sharing/share-offsite/?url=${shareUrl}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white border border-zinc-800 hover:border-zinc-600 rounded px-2.5 py-1.5 transition-colors"
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-label="LinkedIn"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
                LinkedIn
              </a>
              <a
                href={`https://news.ycombinator.com/submitlink?u=${shareUrl}&t=${shareText}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white border border-zinc-800 hover:border-zinc-600 rounded px-2.5 py-1.5 transition-colors"
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-label="Hacker News"><path d="M0 24V0h24v24H0zM6.951 5.896l4.112 7.708v5.064h1.583v-4.972l4.148-7.799h-1.749l-2.457 4.875c-.372.745-.688 1.434-.688 1.434s-.297-.708-.651-1.434L8.831 5.896H6.95z"/></svg>
                HN
              </a>
            </div>
          );
        })()}

        {/* Navigation */}
        <nav className="mt-16 pt-8 border-t border-zinc-800 flex justify-between gap-4">
          {prevPost ? (
            <Link
              href={`/blog/${prevPost.slug}`}
              className="group flex flex-col text-sm"
            >
              <span className="text-zinc-500 mb-1">Older</span>
              <span className="text-zinc-300 group-hover:text-white transition-colors">
                {prevPost.title}
              </span>
            </Link>
          ) : (
            <div />
          )}
          {nextPost ? (
            <Link
              href={`/blog/${nextPost.slug}`}
              className="group flex flex-col text-sm text-right ml-auto"
            >
              <span className="text-zinc-500 mb-1">Newer</span>
              <span className="text-zinc-300 group-hover:text-white transition-colors">
                {nextPost.title}
              </span>
            </Link>
          ) : (
            <div />
          )}
        </nav>
        </article>
      </main>
    </>
  );
}

function formatDate(dateStr: string): string {
  try {
    const d = new Date(dateStr + 'T00:00:00');
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  } catch {
    return dateStr;
  }
}
