import type { Metadata } from 'next';
import Link from 'next/link';
import { DOCS_SIDEBAR } from '@/lib/constants';

export const metadata: Metadata = {
  title: 'Documentation',
  description:
    'GoSQLX documentation - everything you need to parse, analyze, and transform SQL with Go.',
};

const CATEGORY_ICONS: Record<string, string> = {
  'Getting Started': 'M13 10V3L4 14h7v7l9-11h-7z',
  'Core': 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253',
  'Reference': 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  'Advanced': 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z',
  'Tutorials': 'M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5',
  'Migration': 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4',
  'Editors': 'M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z',
};

export default function DocsPage() {
  return (
    <main className="mx-auto max-w-5xl px-6 py-20">
      <div className="mb-16 text-center">
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
          GoSQLX Documentation
        </h1>
        <p className="mt-4 text-lg text-zinc-400">
          Everything you need to parse, analyze, lint, and transform SQL with Go.
        </p>
        <Link
          href="/docs/getting-started"
          className="mt-8 inline-flex items-center gap-2 rounded-lg bg-accent-indigo px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-accent-indigo/80"
        >
          Get Started
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
          </svg>
        </Link>
      </div>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {DOCS_SIDEBAR.map((group) => (
          <Link
            key={group.category}
            href={`/docs/${group.items[0].slug}`}
            className="glass glass-hover block rounded-xl p-6 transition-colors"
          >
            <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-accent-indigo/10">
              <svg className="h-5 w-5 text-accent-indigo" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d={CATEGORY_ICONS[group.category] || CATEGORY_ICONS['Core']} />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-white">{group.category}</h2>
            <p className="mt-1 text-sm text-zinc-500">
              {group.items.length} {group.items.length === 1 ? 'article' : 'articles'}
            </p>
            <ul className="mt-3 space-y-1">
              {group.items.slice(0, 3).map((item) => (
                <li key={item.slug} className="text-sm text-zinc-400">{item.label}</li>
              ))}
              {group.items.length > 3 && (
                <li className="text-sm text-zinc-600">+{group.items.length - 3} more</li>
              )}
            </ul>
          </Link>
        ))}
      </div>
    </main>
  );
}
