'use client';

import { useState, useEffect } from 'react';
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

/** Apply a theme to <html> and point the browser-chrome colour at it, even when it differs from the OS scheme. */
function applyTheme(next: Theme) {
  const html = document.documentElement;
  html.classList.add(next);
  html.classList.remove(next === 'light' ? 'dark' : 'light');
  document
    .querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]')
    .forEach((meta) => meta.setAttribute('content', THEME_COLORS[next]));
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>('dark');
  const [mounted, setMounted] = useState(false);
  const pathname = usePathname();

  // Next.js re-renders the viewport theme-color metas on every client-side
  // navigation, resetting them to their media defaults. Re-apply the active
  // theme after each route change and whenever the metas are rewritten.
  useEffect(() => {
    if (!mounted) return;
    applyTheme(theme);
    const observer = new MutationObserver(() => {
      const stale = Array.from(
        document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]'),
      ).some((meta) => meta.getAttribute('content') !== THEME_COLORS[theme]);
      if (stale) applyTheme(theme);
    });
    observer.observe(document.head, { childList: true, subtree: true, attributes: true, attributeFilter: ['content'] });
    return () => observer.disconnect();
  }, [mounted, theme, pathname]);

  useEffect(() => {
    setMounted(true);
    const saved = localStorage.getItem('theme');
    let initial: Theme;
    if (saved === 'light' || saved === 'dark') {
      initial = saved;
    } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
      initial = 'light';
    } else {
      initial = 'dark';
    }
    setTheme(initial);
    applyTheme(initial);

    // Keep every open tab in step: the storage event fires in the other tabs.
    const onStorage = (e: StorageEvent) => {
      if (e.key !== 'theme' && e.key !== null) return;
      const value = e.key === null ? null : e.newValue;
      const next: Theme =
        value === 'light' || value === 'dark'
          ? value
          : window.matchMedia('(prefers-color-scheme: light)').matches
            ? 'light'
            : 'dark';
      setTheme(next);
      applyTheme(next);
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('theme', next);
    applyTheme(next);
  };

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
