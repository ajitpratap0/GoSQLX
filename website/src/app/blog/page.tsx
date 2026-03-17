import { Metadata } from 'next';
import { getAllPosts } from '@/lib/blog';
import { BlogList } from './BlogList';

export const metadata: Metadata = {
  title: 'Release Notes',
  description: 'GoSQLX release notes and changelog. Track new features, improvements, and bug fixes across all versions.',
};

export default function BlogPage() {
  const posts = getAllPosts();

  return (
    <main className="min-h-screen py-20 px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold tracking-tight mb-3">Release Notes</h1>
        <p className="text-zinc-500 text-lg mb-12">
          Track every feature, fix, and improvement across GoSQLX releases.
        </p>

        <BlogList posts={posts} />
      </div>
    </main>
  );
}
