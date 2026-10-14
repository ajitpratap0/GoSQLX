'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { DOCS_SIDEBAR } from '@/lib/constants';

export function Sidebar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // Lock body scroll when mobile drawer is open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [mobileOpen]);

  const toggleCategory = (category: string) => {
    setCollapsed((prev) => ({ ...prev, [category]: !prev[category] }));
  };

  const isActive = (slug: string) => {
    const normalizedPathname = pathname.replace(/\/$/, '');
    const normalizedHref = `/docs/${slug}`.replace(/\/$/, '');
    return normalizedPathname === normalizedHref;
  };

  const sidebarContent = (
    <nav className="space-y-6 py-4">
      {DOCS_SIDEBAR.map((group) => (
        <div key={group.category}>
          <button
            onClick={() => toggleCategory(group.category)}
            className="flex w-full items-center justify-between px-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 hover:text-zinc-200 transition-colors"
          >
            {group.category}
            <svg
              className={`h-3.5 w-3.5 transition-transform ${collapsed[group.category] ? '-rotate-90' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {!collapsed[group.category] && (
            <ul className="mt-2 space-y-0.5">
              {group.items.map((item) => (
                <li key={item.slug}>
                  <Link
                    href={`/docs/${item.slug}`}
                    onClick={() => setMobileOpen(false)}
                    aria-current={isActive(item.slug) ? 'page' : undefined}
                    className={`block rounded-md px-3 py-1.5 text-sm transition-colors ${
                      isActive(item.slug)
                        ? 'border-l-2 border-accent-indigo bg-accent-indigo/10 pl-[10px] text-white font-medium'
                        : 'border-l-2 border-transparent pl-[10px] text-zinc-400 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </nav>
  );

  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mobileOpen]);

  return (
    <div className="lg:w-64 lg:shrink-0">
      {/* Mobile: inline menu bar under the navbar (no floating button) */}
      <div className="sticky top-16 z-30 border-b border-white/5 bg-surface/95 px-6 py-2 backdrop-blur lg:hidden">
        <button
          type="button"
          onClick={() => setMobileOpen(true)}
          aria-expanded={mobileOpen}
          aria-controls="docs-sidebar"
          className="flex items-center gap-2 py-1 text-sm font-medium text-zinc-300 hover:text-white"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
          Docs menu
        </button>
      </div>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setMobileOpen(false)} />
      )}

      {/* Sidebar (sticky column on lg, drawer below) */}
      <aside
        id="docs-sidebar"
        aria-label="Documentation"
        className={`fixed top-16 z-40 h-[calc(100vh-4rem)] w-64 overflow-y-auto border-r border-white/5 bg-surface px-2 transition-transform lg:sticky lg:translate-x-0 lg:bg-transparent ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex justify-end pt-2 lg:hidden">
          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            className="rounded p-1 text-zinc-400 hover:text-white"
            aria-label="Close docs menu"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        {sidebarContent}
      </aside>
    </div>
  );
}
