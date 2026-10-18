'use client';

import { useEffect, useRef, useState } from 'react';

interface TocProps {
  headings: { id: string; text: string; level: number }[];
  /** `rail` is the sticky xl sidebar; `collapsible` is the inline disclosure shown below xl. */
  variant?: 'rail' | 'collapsible';
}

export function Toc({ headings, variant = 'rail' }: TocProps) {
  const [activeId, setActiveId] = useState<string>('');
  const navRef = useRef<HTMLElement>(null);

  // Keep the active entry visible inside the scrollable rail (scroll only the nav, never the page).
  useEffect(() => {
    const nav = navRef.current;
    if (!nav || !activeId) return;
    const link = nav.querySelector<HTMLElement>(`a[href="#${CSS.escape(activeId)}"]`);
    if (!link) return;
    const navRect = nav.getBoundingClientRect();
    const linkRect = link.getBoundingClientRect();
    if (linkRect.top < navRect.top || linkRect.bottom > navRect.bottom) {
      nav.scrollTop += linkRect.top - navRect.top - nav.clientHeight / 2 + linkRect.height / 2;
    }
  }, [activeId]);

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
                  ? 'text-fg font-medium'
                  : heading.level === 3
                  ? 'text-fg-subtle hover:text-fg-muted'
                  : 'text-fg-muted hover:text-fg-muted'
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
      <details className="group mb-6 rounded-lg border border-fg/[0.08] bg-fg/[0.03] xl:hidden">
        <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3 text-sm font-medium text-fg-muted [&::-webkit-details-marker]:hidden">
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
    <nav
      ref={navRef}
      aria-label="On this page"
      className="sticky top-20 hidden max-h-[calc(100vh-6rem)] overflow-y-auto overscroll-contain xl:block"
    >
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-text-muted">
        On this page
      </h4>
      {list}
    </nav>
  );
}
