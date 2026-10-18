'use client';

import { useState, useEffect, useSyncExternalStore } from 'react';
import { usePathname } from 'next/navigation';
import { THEME_COLORS } from '@/lib/site';
import { m, AnimatePresence } from 'motion/react';

function SunIcon({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zM4.222 4.222a1 1 0 011.414 0l.707.707a1 1 0 01-1.414 1.414l-.707-.707a1 1 0 010-1.414zm11.314 0a1 1 0 010 1.414l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 0zM10 7a3 3 0 100 6 3 3 0 000-6zm-7 3a1 1 0 011-1h1a1 1 0 110 2H4a1 1 0 01-1-1zm13 0a1 1 0 011-1h1a1 1 0 110 2h-1a1 1 0 01-1-1zm-9.536 4.464a1 1 0 011.414 0l.707.707a1 1 0 01-1.414 1.414l-.707-.707a1 1 0 010-1.414zm7.072 0a1 1 0 010 1.414l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 0zM10 15a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function MoonIcon({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
    </svg>
  );
}

type Theme = 'dark' | 'light';

/** The html class is the single source of truth (set pre-hydration by the layout script). */
function readTheme(): Theme {
  return document.documentElement.classList.contains('light') ? 'light' : 'dark';
}

function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

/** Apply a theme to <html> and point the browser-chrome colour at it, even when it differs from the OS scheme. */
function applyTheme(next: Theme) {
  const html = document.documentElement;
  if (!html.classList.contains(next)) html.classList.add(next);
  html.classList.remove(next === 'light' ? 'dark' : 'light');
  document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]').forEach((meta) => {
    // Only write when different so our own observer cannot re-trigger itself.
    if (meta.getAttribute('content') !== THEME_COLORS[next]) {
      meta.setAttribute('content', THEME_COLORS[next]);
    }
  });
}

// Shared store: every ThemeToggle instance (desktop + mobile menu) subscribes
// here, so there is exactly one observer and one storage listener.
const listeners = new Set<() => void>();
let installed = false;

function notify() {
  listeners.forEach((l) => l());
}

function install() {
  if (installed) return;
  installed = true;
  // Next.js re-renders the viewport theme-color metas on client-side navigation,
  // resetting them to media defaults. The handler reads the live theme from
  // <html>, never from a closure, and applyTheme is idempotent, so it settles.
  new MutationObserver((records) => {
    // Ignore unrelated head churn (style/script injection by the playground etc.).
    const relevant = records.some((r) => {
      const nodes = [r.target, ...Array.from(r.addedNodes), ...Array.from(r.removedNodes)];
      return nodes.some((n) => n instanceof HTMLMetaElement && n.name === 'theme-color');
    });
    if (relevant) applyTheme(readTheme());
  }).observe(document.head, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['content'],
  });
  // Keep every open tab in step: the storage event fires in the other tabs.
  window.addEventListener('storage', (e) => {
    if (e.key !== 'theme' && e.key !== null) return;
    const value = e.key === null ? null : e.newValue;
    applyTheme(value === 'light' || value === 'dark' ? value : systemTheme());
    notify();
  });
  applyTheme(readTheme());
}

function subscribe(listener: () => void) {
  install();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function setTheme(next: Theme) {
  try {
    localStorage.setItem('theme', next);
  } catch {
    /* storage unavailable: still apply for this page */
  }
  applyTheme(next);
  notify();
}

export function ThemeToggle() {
  const theme = useSyncExternalStore<Theme>(subscribe, readTheme, () => 'dark');
  const [mounted, setMounted] = useState(false);
  const pathname = usePathname();

  useEffect(() => setMounted(true), []);

  // Re-apply after each route change in case the metas were reset.
  useEffect(() => {
    if (mounted) applyTheme(readTheme());
  }, [mounted, pathname]);

  const toggle = () => setTheme(theme === 'dark' ? 'light' : 'dark');

  if (!mounted) {
    return (
      <button
        type="button"
        data-theme-toggle=""
        className="inline-flex min-h-11 min-w-11 items-center justify-center text-fg-muted hover:text-fg transition-colors duration-200 p-2 rounded-lg hover:bg-fg/[0.04]"
        aria-label="Dark mode"
        aria-pressed="true"
      >
        <span className="block w-5 h-5" />
      </button>
    );
  }

  return (
    <m.button
      type="button"
      onClick={toggle}
      data-theme-toggle=""
      className="inline-flex min-h-11 min-w-11 items-center justify-center text-fg-muted hover:text-fg transition-colors duration-200 p-2 rounded-lg hover:bg-fg/[0.04] relative overflow-hidden"
      aria-label="Dark mode"
      aria-pressed={theme === 'dark'}
      whileTap={{ scale: 0.9 }}
      transition={{ type: 'spring', stiffness: 400, damping: 17 }}
    >
      <AnimatePresence mode="wait" initial={false}>
        {theme === 'dark' ? (
          <m.span
            key="sun"
            initial={{ rotate: -90, opacity: 0 }}
            animate={{ rotate: 0, opacity: 1 }}
            exit={{ rotate: 90, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="block"
          >
            <SunIcon className="w-5 h-5" />
          </m.span>
        ) : (
          <m.span
            key="moon"
            initial={{ rotate: 90, opacity: 0 }}
            animate={{ rotate: 0, opacity: 1 }}
            exit={{ rotate: -90, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="block"
          >
            <MoonIcon className="w-5 h-5" />
          </m.span>
        )}
      </AnimatePresence>
    </m.button>
  );
}
