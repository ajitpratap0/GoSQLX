import { Metadata } from 'next';
import { getAllPosts } from '@/lib/blog';
import { BlogList } from './BlogList';

export const metadata: Metadata = {
  title: 'Changelog',
  description: 'GoSQLX changelog — new features, improvements, and bug fixes across all versions of the SQL parsing SDK.',
  alternates: {
    canonical: '/blog/',
  },
  openGraph: {
    title: 'GoSQLX Changelog',
    description: 'New features, improvements, and bug fixes across all GoSQLX versions.',
    url: '/blog/',
  },
};

export default function BlogPage() {
  const posts = getAllPosts();

  return (
    <main className="min-h-screen py-20 px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold tracking-tight mb-3">Changelog</h1>
        <p className="text-zinc-500 text-lg mb-12">
          Track every feature, fix, and improvement across GoSQLX releases.
        </p>

        <BlogList posts={posts} />
      </div>
    </main>
  );
}
