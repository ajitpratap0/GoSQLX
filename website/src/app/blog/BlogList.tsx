'use client';

import Link from 'next/link';
import { motion } from 'framer-motion';
import type { BlogPost } from '@/lib/blog';

export function BlogList({ posts }: { posts: BlogPost[] }) {
  return (
    <div className="relative">
      {/* Timeline line */}
      <div className="absolute left-[7px] top-2 bottom-2 w-px bg-zinc-800" />

      <div className="space-y-0">
        {posts.map((post, i) => (
          <motion.div
            key={post.slug}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: i * 0.05, ease: 'easeOut' }}
          >
            <Link
              href={`/blog/${post.slug}`}
              className="group flex gap-6 py-5 pl-0 relative"
            >
              {/* Timeline dot */}
              <div className="relative z-10 mt-2 w-[15px] h-[15px] shrink-0 rounded-full border-2 border-zinc-700 bg-primary group-hover:border-accent-indigo transition-colors" />

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                  <span className="inline-block bg-accent-indigo/10 border border-accent-indigo/20 rounded-full px-3 py-0.5 text-xs font-medium text-accent-indigo">
                    v{post.version}
                  </span>
                  {post.date && (
                    <span className="text-sm text-zinc-500">{formatDate(post.date)}</span>
                  )}
                </div>
                <h2 className="text-lg font-semibold text-zinc-100 group-hover:text-white transition-colors truncate">
                  {post.title}
                </h2>
                {post.description && (
                  <p className="mt-1 text-sm text-zinc-400 line-clamp-2">
                    {post.description}
                  </p>
                )}
              </div>

              {/* Arrow */}
              <div className="mt-2 text-zinc-600 group-hover:text-zinc-400 transition-colors shrink-0">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M6 4l4 4-4 4" />
                </svg>
              </div>
            </Link>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function formatDate(dateStr: string): string {
  try {
    const d = new Date(dateStr + 'T00:00:00');
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return dateStr;
  }
}
