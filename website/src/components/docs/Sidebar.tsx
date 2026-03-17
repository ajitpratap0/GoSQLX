'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { DOCS_SIDEBAR } from '@/lib/constants';

export function Sidebar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const toggleCategory = (category: string) => {
    setCollapsed((prev) => ({ ...prev, [category]: !prev[category] }));
  };

  const isActive = (slug: string) => pathname === `/docs/${slug}`;

  const sidebarContent = (
    <nav className="space-y-6 py-4">
      {DOCS_SIDEBAR.map((group) => (
        <div key={group.category}>
          <button
            onClick={() => toggleCategory(group.category)}
            className="flex w-full items-center justify-between px-3 text-xs font-semibold uppercase tracking-wider text-zinc-500 hover:text-zinc-300 transition-colors"
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
                    className={`block rounded-md px-3 py-1.5 text-sm transition-colors ${
                      isActive(item.slug)
                        ? 'bg-accent-indigo/10 text-white font-medium'
                        : 'text-zinc-400 hover:text-white hover:bg-white/5'
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

  return (
    <>
      {/* Mobile toggle */}
      <button
        onClick={() => setMobileOpen(!mobileOpen)}
        className="fixed bottom-4 right-4 z-50 flex h-12 w-12 items-center justify-center rounded-full bg-accent-indigo text-white shadow-lg lg:hidden"
        aria-label="Toggle docs sidebar"
      >
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          {mobileOpen ? (
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          ) : (
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
          )}
        </svg>
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setMobileOpen(false)} />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed top-16 z-40 h-[calc(100vh-4rem)] w-64 overflow-y-auto border-r border-white/5 bg-surface px-2 transition-transform lg:sticky lg:translate-x-0 lg:bg-transparent ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {sidebarContent}
      </aside>
    </>
  );
}
