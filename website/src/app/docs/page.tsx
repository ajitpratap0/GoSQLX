import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import Link from 'next/link';
import { DOCS_SIDEBAR, docsCategoryAnchor } from '@/lib/constants';
import { DocsSearchTrigger } from '@/components/docs/DocsSearchTrigger';
import { FadeIn } from '@/components/ui/FadeIn';

export const metadata: Metadata = pageMeta({
  title: 'Documentation',
  description:
    'GoSQLX documentation: task guides, integrations, per-package API reference, error codes, lint rules and dialect support to parse and analyze SQL in Go.',
  path: '/docs/',
});

const CATEGORY_ICONS: Record<string, string> = {
  'Start': 'M13 10V3L4 14h7v7l9-11h-7z',
  'Guides':'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253',
  'Reference': 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  'Concepts':'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z',
  'Migration': 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4',
  'Integrations':'M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z',
};

const START_HERE = ['getting-started', 'usage-guide', 'cli-guide'];
const ALL_ITEMS = DOCS_SIDEBAR.flatMap((g) => g.items);

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-20">
      <div className="mb-16 text-center">
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
          GoSQLX Documentation
        </h1>
        <p className="mt-4 text-lg text-fg-muted">
          Everything you need to parse, analyze, lint, and transform SQL with Go.
        </p>
        <Link
          href="/docs/getting-started/"
          className="mt-8 inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-3 text-sm font-semibold text-accent-fg transition-colors hover:bg-accent/90"
        >
          Get Started
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
          </svg>
        </Link>
      </div>

      <DocsSearchTrigger />

      <section aria-labelledby="start-here" className="mb-12">
        <h2 id="start-here" className="mb-4 text-sm font-semibold uppercase tracking-wider text-fg-subtle">
          Start here
        </h2>
        <div className="grid gap-4 sm:grid-cols-3">
          {START_HERE.map((slug) => {
            const item = ALL_ITEMS.find((i) => i.slug === slug);
            if (!item) return null;
            return (
              <Link
                key={slug}
                href={`/docs/${slug}`}
                className="glass glass-hover block rounded-xl p-5 transition-colors"
              >
                <span className="text-base font-semibold text-fg">{item.label}</span>
                <span className="mt-1 block text-sm text-fg-muted">{item.description}</span>
              </Link>
            );
          })}
        </div>
      </section>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {DOCS_SIDEBAR.map((group, i) => {
          // Package pages (depth 1) are reachable from the API Reference page; list top-level pages only.
          const pages = group.items.filter((item) => !item.depth);
          return (
            <FadeIn viewport key={group.category} delay={i * 0.06}>
              <section
                id={docsCategoryAnchor(group.category)}
                aria-labelledby={`docs-cat-${i}`}
                className="glass block h-full scroll-mt-24 rounded-xl p-6"
              >
                <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-accent/10">
                  <svg className="h-5 w-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" d={CATEGORY_ICONS[group.category] || CATEGORY_ICONS['Guides']} />
                  </svg>
                </div>
                <h2 id={`docs-cat-${i}`} className="text-lg font-semibold text-fg">{group.category}</h2>
                <p className="mt-1 text-sm text-fg-subtle">{group.summary}</p>
                <ul className="mt-3">
                  {pages.map((item) => (
                    <li key={item.slug}>
                      <Link
                        href={`/docs/${item.slug}/`}
                        className="inline-block py-1 text-sm text-fg-muted transition-colors hover:text-fg"
                      >
                        {item.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </section>
            </FadeIn>
          );
        })}
      </div>
    </div>
  );
}
