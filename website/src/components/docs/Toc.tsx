'use client';

import { useEffect, useState } from 'react';

interface TocProps {
  headings: { id: string; text: string; level: number }[];
}

export function Toc({ headings }: TocProps) {
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

  return (
    <nav className="sticky top-20 hidden xl:block">
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">
        On this page
      </h4>
      <ul className="space-y-1.5 text-sm">
        {headings.map((heading) => (
          <li key={heading.id} style={{ paddingLeft: heading.level === 3 ? '0.75rem' : 0 }}>
            <a
              href={`#${heading.id}`}
              className={`block py-0.5 transition-colors ${
                activeId === heading.id
                  ? 'text-white font-medium'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {heading.text}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
