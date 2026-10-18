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

  // Scroll-spy: the active heading is the last one whose top is at or above the
  // offset (matches html scroll-padding-top: 5rem plus a little slack). Stays
  // active through long sections; first heading at top, last heading at bottom.
  useEffect(() => {
    if (headings.length === 0) return;
    let raf = 0;

    const update = () => {
      raf = 0;
      // Live scroll padding (5rem desktop, 7.5rem below lg) plus slack, so a clicked
      // anchor (which lands at exactly scroll-padding-top) counts as reached.
      const offset =
        (parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 80) + 16;
      let current = headings[0].id;
      for (const h of headings) {
        const el = document.getElementById(h.id);
        if (!el) continue;
        if (el.getBoundingClientRect().top <= offset) current = h.id;
        else break;
      }
      const atBottom =
        window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2;
      if (atBottom && window.scrollY > 0) current = headings[headings.length - 1].id;
      setActiveId(current);
    };
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(update);
    };

    update();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [headings]);

  if (headings.length === 0) return null;

  const list = (
      <ul className="space-y-1.5 text-sm">
        {headings.map((heading) => (
          <li key={heading.id} className={heading.level === 3 ? 'pl-3' : ''}>
            <a
              href={`#${heading.id}`}
              aria-current={activeId === heading.id ? 'location' : undefined}
              title={heading.text}
              className={`line-clamp-2 py-0.5 transition-colors ${
                heading.level === 3 ? 'text-xs' : 'font-medium'
              } ${
                activeId === heading.id
                  ? 'text-fg font-medium'
                  : heading.level === 3
                  ? 'text-fg-subtle hover:text-fg'
                  : 'text-fg-muted hover:text-fg'
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
      className="sticky top-20 -mx-1 hidden max-h-[calc(100vh-7rem)] overflow-y-auto overscroll-contain px-1 py-1 xl:block"
    >
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-fg-subtle">
        On this page
      </h4>
      {list}
    </nav>
  );
}
