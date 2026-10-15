'use client';

import { useEffect, useState } from 'react';

interface TocProps {
  headings: { id: string; text: string; level: number }[];
  /** `rail` is the sticky xl sidebar; `collapsible` is the inline disclosure shown below xl. */
  variant?: 'rail' | 'collapsible';
}

export function Toc({ headings, variant = 'rail' }: TocProps) {
  const [activeId, setActiveId] = useState<string>('');

  useEffect(() => {
    if (headings.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        // Find the first intersecting heading
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id);
            break;
          }
        }
      },
      { rootMargin: '-80px 0px -80% 0px', threshold: 0 }
    );

    const elements = headings
      .map((h) => document.getElementById(h.id))
      .filter(Boolean) as HTMLElement[];

    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, [headings]);

  if (headings.length === 0) return null;

  const list = (
      <ul className="space-y-1.5 text-sm">
        {headings.map((heading) => (
          <li key={heading.id} className={heading.level === 3 ? 'pl-3' : ''}>
            <a
              href={`#${heading.id}`}
              title={heading.text}
              className={`line-clamp-2 py-0.5 transition-colors ${
                heading.level === 3 ? 'text-xs' : 'font-medium'
              } ${
                activeId === heading.id
                  ? 'text-white font-medium'
                  : heading.level === 3
                  ? 'text-fg-subtle hover:text-zinc-300'
                  : 'text-zinc-400 hover:text-zinc-300'
              }`}
            >
              {heading.text}
            </a>
          </li>
        ))}
      </ul>
  );

  if (variant === 'collapsible') {
    return (
      <details className="group mb-6 rounded-lg border border-white/[0.08] bg-white/[0.03] xl:hidden">
        <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3 text-sm font-medium text-zinc-300 [&::-webkit-details-marker]:hidden">
          On this page
          <svg
            className="h-4 w-4 transition-transform group-open:rotate-180"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </summary>
        <nav aria-label="On this page" className="px-4 pb-4">
          {list}
        </nav>
      </details>
    );
  }

  return (
    <nav aria-label="On this page" className="sticky top-20 hidden xl:block">
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-text-muted">
        On this page
      </h4>
      {list}
    </nav>
  );
}
