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
    openGraph: {
      title: `GoSQLX ${post.title}`,
      description: `GoSQLX ${post.title} release notes.`,
      type: 'article',
      publishedTime: post.date ? `${post.date}T00:00:00Z` : undefined,
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

  return (
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
