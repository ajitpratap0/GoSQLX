import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { getAllPosts } from '@/lib/blog';
import { BlogList } from './BlogList';

const baseMeta = pageMeta({
  title: 'Changelog',
  description:
    'GoSQLX changelog: release notes covering new features, improvements and bug fixes across every version of the Go SQL parsing SDK and its CLI.',
  path: '/blog/',
});

export const metadata: Metadata = {
  ...baseMeta,
  alternates: {
    ...baseMeta.alternates,
    types: { 'application/rss+xml': '/blog/feed.xml' },
  },
};

export default function BlogPage() {
  const posts = getAllPosts();

  return (
    <div className="min-h-screen py-20 px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold tracking-tight mb-3">Changelog</h1>
        <p className="text-zinc-500 text-lg mb-12">
          Track every feature, fix, and improvement across GoSQLX releases.
        </p>

        <BlogList posts={posts} />
      </div>
    </div>
  );
}
